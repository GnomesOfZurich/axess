//! Row writes: the compare-and-swap loop every conditional change runs
//! through, and the unconditional `save`.

use chrono::{DateTime, Utc};

use super::index::plan_indexes;
use super::read::StoredRowState;
use super::row::{device_key, fingerprint_hex, fingerprint_key, fingerprint_set_key};
use super::scripts::{
    REMOVE_DEVICE, ScriptStatus, WRITE_ROW, parse_status, remove_args, write_row_args,
};
use super::{MAX_ATTEMPTS, ValkeyDeviceStore, ValkeyDeviceStoreError};
use crate::device::store::{blocks_save, for_save};
use crate::device::types::Device;
use fred::prelude::*;

/// The decision [`ValkeyDeviceStore::apply`] takes for the row it read.
pub(super) enum Step {
    /// Leave the row alone (the caller learns the row it was decided on).
    Skip,
    /// Replace the row with this value.
    Write(Device),
    /// Delete the row.
    Remove,
}

/// What [`ValkeyDeviceStore::apply`] did.
pub(super) enum Applied {
    /// The row does not exist (or vanished before the write).
    Missing,
    /// The decision was to leave the row; carries the row as read.
    Skipped(Device),
    /// The new row was stored; carries the row as it was read.
    Written { before: Device },
    /// The row was deleted.
    Removed,
}

impl ValkeyDeviceStore {
    pub(super) async fn run_script(
        &self,
        script: &'static str,
        keys: Vec<String>,
        args: Vec<Value>,
    ) -> Result<ScriptStatus, ValkeyDeviceStoreError> {
        let reply: String = self.client.eval(script, keys, args).await?;
        parse_status(&reply).ok_or(ValkeyDeviceStoreError::UnexpectedScriptReply(reply))
    }

    /// The two fingerprint keys a script addresses for `device`, in script
    /// key order: its fingerprint set, then the single-id key of earlier
    /// releases (read and cleaned up, never created).
    fn fingerprint_keys(&self, tenant: &str, device: &Device) -> [String; 2] {
        let hex = fingerprint_hex(&device.fingerprint_hash);
        [
            fingerprint_set_key(&self.prefix, tenant, &hex),
            fingerprint_key(&self.prefix, tenant, &hex),
        ]
    }

    fn contended(tenant: &str, id: &str) -> ValkeyDeviceStoreError {
        ValkeyDeviceStoreError::Contended {
            tenant_id: tenant.to_string(),
            device_id: id.to_string(),
        }
    }

    /// Read a row, let `decide` choose what to do with it, and apply that
    /// decision atomically together with the index changes it implies; on a
    /// concurrent change re-read and decide again. `now` derives the TTL of a
    /// row that is written.
    pub(super) async fn apply<F>(
        &self,
        tenant: &str,
        id: &str,
        now: DateTime<Utc>,
        decide: F,
    ) -> Result<Applied, ValkeyDeviceStoreError>
    where
        F: Fn(&Device) -> Step,
    {
        self.apply_at(tenant, id, Some(now), decide).await
    }

    /// Delete a row with its fingerprint entry and index entries in one
    /// script, conditional on the row as it was read; a writer that changed
    /// it meanwhile conflicts the script and the delete runs again on the
    /// fresh row.
    pub(super) async fn remove_row(
        &self,
        tenant: &str,
        id: &str,
    ) -> Result<Applied, ValkeyDeviceStoreError> {
        self.apply_at(tenant, id, None, |_| Step::Remove).await
    }

    /// [`apply`](Self::apply) with the write time optional: `None` is for a
    /// decision that never writes a row, so there is no TTL to derive.
    async fn apply_at<F>(
        &self,
        tenant: &str,
        id: &str,
        now: Option<DateTime<Utc>>,
        decide: F,
    ) -> Result<Applied, ValkeyDeviceStoreError>
    where
        F: Fn(&Device) -> Step,
    {
        let row_key = device_key(&self.prefix, tenant, id);
        for _ in 0..MAX_ATTEMPTS {
            let Some((device, raw)) = self.get_row(tenant, id).await? else {
                return Ok(Applied::Missing);
            };
            let step = decide(&device);
            let status = match &step {
                Step::Skip => return Ok(Applied::Skipped(device)),
                Step::Write(new) => {
                    let plan = plan_indexes(&self.prefix, Some(&device), Some(new));
                    let args = write_row_args(
                        Some(&raw),
                        &self.encode_row(new)?,
                        now.and_then(|now| self.ttl_seconds_for(new, now)),
                        id,
                        &plan.ops(),
                    );
                    let keys = [row_key.clone()]
                        .into_iter()
                        .chain(self.fingerprint_keys(tenant, new))
                        .chain(plan.keys());
                    self.run_script(WRITE_ROW, keys.collect(), args).await?
                }
                Step::Remove => {
                    let plan = plan_indexes(&self.prefix, Some(&device), None);
                    let args = remove_args(Some(&raw), id, &plan.ops());
                    let keys = [row_key.clone()]
                        .into_iter()
                        .chain(self.fingerprint_keys(tenant, &device))
                        .chain(plan.keys());
                    self.run_script(REMOVE_DEVICE, keys.collect(), args).await?
                }
            };
            match (status, step) {
                (ScriptStatus::Ok, Step::Remove) => return Ok(Applied::Removed),
                (ScriptStatus::Ok, _) => return Ok(Applied::Written { before: device }),
                (ScriptStatus::Missing, _) => return Ok(Applied::Missing),
                (ScriptStatus::Conflict, _) => continue,
            }
        }
        Err(Self::contended(tenant, id))
    }

    /// Store `device` as the row for its id, whatever the row held: the
    /// write is a compare-and-swap against the row as read (or its absence),
    /// retried against the fresh row on a conflict, so the last writer wins
    /// without two saves interleaving their index changes. A stored
    /// `Revoked` row is left as it is by a save that is not itself revoked.
    pub(super) async fn save_row(
        &self,
        device: &Device,
        now: DateTime<Utc>,
    ) -> Result<(), ValkeyDeviceStoreError> {
        let device = for_save(device, now);
        let tenant = device.tenant_id.to_string();
        let id = device.id.to_string();
        let row_key = device_key(&self.prefix, &tenant, &id);
        let payload = self.encode_row(&device)?;
        let ttl = self.ttl_seconds_for(&device, now);
        for _ in 0..MAX_ATTEMPTS {
            let previous = match self.get_row_for_write(&tenant, &id).await? {
                StoredRowState::Absent => None,
                StoredRowState::Decoded(prev, raw) => Some((prev, raw)),
                StoredRowState::Undecodable(raw, error) => {
                    // A save replaces the row, so a stored row nobody can
                    // read is overwritten (against the exact bytes found)
                    // rather than failing every later save of the device.
                    // Its old index entries are not known; the readers prune
                    // them when they find the members stale.
                    tracing::warn!(
                        %tenant, device = %id, %error,
                        "replacing a device row that cannot be decoded"
                    );
                    let plan = plan_indexes(&self.prefix, None, Some(&device));
                    let args = write_row_args(Some(&raw), &payload, ttl, &id, &plan.ops());
                    let keys = [row_key.clone()]
                        .into_iter()
                        .chain(self.fingerprint_keys(&tenant, &device))
                        .chain(plan.keys());
                    match self.run_script(WRITE_ROW, keys.collect(), args).await? {
                        ScriptStatus::Ok => return Ok(()),
                        ScriptStatus::Missing | ScriptStatus::Conflict => continue,
                    }
                }
            };
            if let Some((prev, _)) = &previous
                && blocks_save(prev.trust_level)
            {
                return Ok(());
            }
            let plan = plan_indexes(
                &self.prefix,
                previous.as_ref().map(|(d, _)| d),
                Some(&device),
            );
            let args = write_row_args(
                previous.as_ref().map(|(_, raw)| raw.as_slice()),
                &payload,
                ttl,
                &id,
                &plan.ops(),
            );
            let keys = [row_key.clone()]
                .into_iter()
                .chain(self.fingerprint_keys(&tenant, &device))
                .chain(plan.keys());
            match self.run_script(WRITE_ROW, keys.collect(), args).await? {
                ScriptStatus::Ok => return Ok(()),
                ScriptStatus::Missing | ScriptStatus::Conflict => continue,
            }
        }
        Err(Self::contended(&tenant, &id))
    }
}
