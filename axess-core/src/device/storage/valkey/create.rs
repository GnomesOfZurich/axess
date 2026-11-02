//! The create step of `create_or_find`: insert a device only while no live
//! device of its tenant, fingerprint and owner exists.
//!
//! The row is an opaque (optionally encrypted) blob, so no script can look
//! inside the candidates to see whether one is live and has the same owner.
//! The check is made in Rust and the insert is made conditional on a create
//! guard instead: one key per `(tenant, fingerprint, owner)` that names the
//! device the last create of that key inserted, under a generation every
//! insert raises. A create reads the guard,
//! looks for a live device of the key (the one the guard names first), and
//! inserts only through [`CREATE_ROW`], which writes the row, its indexes
//! and the guard in one step and only while the guard still holds what was
//! read. Of two creates that both found nothing, the second script sees the
//! guard the first one set and conflicts; its next round finds the first
//! one's device through the guard and returns it.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use fred::prelude::*;

use super::index::plan_indexes;
use super::row::{create_guard_key, device_key, fingerprint_hex, fingerprint_zset_key};
use super::scripts::{CREATE_ROW, ScriptStatus, create_row_args, guarded_device};
use super::{MAX_ATTEMPTS, ValkeyDeviceStore, ValkeyDeviceStoreError};
use crate::device::store::{for_save, order_newest_first, shares_create_key};
use crate::device::types::Device;

/// How long a create guard lives. It only has to outlive the race it
/// settles: once it has expired, every create of the key finds the device
/// through the fingerprint indexes, which the inserting script updated.
pub(super) const CREATE_GUARD_TTL: Duration = Duration::from_secs(60);

/// A create round whose read is older than this starts again instead of
/// sending its insert, so the guard it read cannot have expired and been
/// set again by another create in between.
const CREATE_READ_MAX_AGE: Duration = Duration::from_secs(CREATE_GUARD_TTL.as_secs() / 2);

impl ValkeyDeviceStore {
    /// `create_or_find`: the live device of `device`'s key, or `device`
    /// inserted as a new row (through `for_save`) when there is none.
    pub(super) async fn create_or_find_row(
        &self,
        device: &Device,
        now: DateTime<Utc>,
    ) -> Result<Device, ValkeyDeviceStoreError> {
        let device = for_save(device, now);
        let tenant = device.tenant_id.to_string();
        let id = device.id.to_string();
        let hex = fingerprint_hex(&device.fingerprint_hash);
        let owner = device.user_id.map(|u| u.to_string());
        let guard = create_guard_key(&self.prefix, &tenant, &hex, owner.as_deref());
        let payload = self.encode_row(&device)?;
        let ttl = self.ttl_seconds_for(&device, now);
        // A new row is in no index yet, so the plan only adds.
        let plan = plan_indexes(&self.prefix, None, Some(&device));
        for _ in 0..MAX_ATTEMPTS {
            let read_at = Instant::now();
            let held: Option<String> = self.client.get(&guard).await?;
            if let Some(existing) = self.live_of_key(&device, held.as_deref()).await? {
                return Ok(existing);
            }
            if read_at.elapsed() > CREATE_READ_MAX_AGE {
                continue;
            }
            let keys = [
                guard.clone(),
                device_key(&self.prefix, &tenant, &id),
                fingerprint_zset_key(&self.prefix, &tenant, &hex),
            ]
            .into_iter()
            .chain(plan.keys());
            let args = create_row_args(
                held.as_deref(),
                CREATE_GUARD_TTL.as_secs(),
                &payload,
                ttl,
                &id,
                device.last_seen_at.timestamp(),
            );
            match self.run_script(CREATE_ROW, keys.collect(), args).await? {
                ScriptStatus::Ok => return Ok(device),
                ScriptStatus::Conflict | ScriptStatus::Missing => continue,
            }
        }
        Err(Self::contended(&tenant, &id))
    }

    /// The live device of `device`'s create key, newest sighting first: the
    /// one the create guard value `held` names when it is still live and of
    /// the key, otherwise the best one the fingerprint indexes list.
    async fn live_of_key(
        &self,
        device: &Device,
        held: Option<&str>,
    ) -> Result<Option<Device>, ValkeyDeviceStoreError> {
        let tenant = device.tenant_id.to_string();
        if let Some(held) = held.and_then(guarded_device)
            && let Some(named) = self.get_device(&tenant, held).await?
            && shares_create_key(&named, device)
        {
            return Ok(Some(named));
        }
        let live = |d: &Device| shares_create_key(d, device);
        let candidates = match device.user_id.as_ref() {
            Some(user) => {
                self.owned_with_fingerprint(&tenant, user, &device.fingerprint_hash, live)
                    .await?
            }
            None => self
                .devices_with_fingerprint(&tenant, &device.fingerprint_hash)
                .await?
                .into_iter()
                .filter(live)
                .collect(),
        };
        Ok(candidates.into_iter().min_by(order_newest_first))
    }
}
