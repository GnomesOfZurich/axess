//! [`MemoryDeviceStore`]: the in-memory [`DeviceStore`] backend.

use super::{
    BindingsUpdate, DeviceStore, OwnerClaim, SweepConfig, SweepCounts, TrustTransition,
    blocks_save, demotion_stamp, for_save, order_newest_first,
};
use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
use crate::health::{HealthCheck, HealthStatus};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ── MemoryDeviceStore ─────────────────────────────────────────────────────────

/// Composite primary key for the in-memory devices table: `(tenant, device)`.
///
/// `TenantId` and `DeviceId` are 16-byte `Copy` Uuid newtypes, so the key
/// is 32 bytes of stack data; no heap allocation per lookup.
type DeviceKey = (TenantId, DeviceId);

/// Composite key for the in-memory fingerprint index: `(tenant, hash)`.
type FingerprintKey = (TenantId, FingerprintHash);

/// In-memory device store backed by [`DashMap`].
///
/// **For testing and single-node development only.** Not suitable for
/// production: data is lost on restart, no encryption at rest, no
/// cross-node visibility. Lookups by fingerprint use an index; lookups
/// by user or by refresh family scan every device in every tenant, which
/// is immaterial at test sizes and not a basis for load testing.
///
/// # Time injection
///
/// `record_sighting` and `set_trust_level` accept `now` as a parameter so
/// the store itself does not own a [`Clock`](axess_clock::Clock);
/// callers thread the injected clock from the surrounding service. This
/// mirrors how `SessionStore::cycle` accepts caller-supplied state for
/// DST testability.
#[derive(Clone, Default)]
pub struct MemoryDeviceStore {
    /// Primary table: `(tenant_id, device_id) -> Device`.
    devices: Arc<DashMap<DeviceKey, Device>>,
    /// Secondary index: `(tenant_id, fingerprint_hash) -> device_id`. Kept
    /// in sync by `save` / `delete`; serves the `find_by_fingerprint` fast
    /// path without scanning the primary table.
    fingerprint_index: Arc<DashMap<FingerprintKey, DeviceId>>,
    /// Write counter: reserved for future auto-purge scheduling, mirrors
    /// the `MemorySessionStore` pattern even though no auto-purge runs in
    /// this sketch.
    write_count: Arc<AtomicU64>,
    /// Retention thresholds driving [`Self::sweep`]. Defaults to
    /// [`SweepConfig::default()`] (fintech-style 90/30/7 day windows).
    sweep_config: SweepConfig,
}

impl MemoryDeviceStore {
    /// Create an empty in-memory device store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the [`SweepConfig`] driving the retention ladder.
    pub fn with_sweep_config(mut self, config: SweepConfig) -> Self {
        self.sweep_config = config;
        self
    }

    /// Number of devices currently held. Useful in tests; not part of the
    /// trait surface.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// `true` when no devices are held.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    fn key(tenant_id: &TenantId, id: &DeviceId) -> DeviceKey {
        (*tenant_id, *id)
    }
}

/// Errors from [`MemoryDeviceStore`].
#[derive(Debug, thiserror::Error)]
pub enum MemoryDeviceStoreError {
    /// The targeted device id was not present in the store.
    #[error("device not found: tenant={tenant_id} id={device_id}")]
    NotFound {
        /// Tenant scope of the missed lookup.
        tenant_id: String,
        /// Opaque device id whose lookup missed.
        device_id: String,
    },
}

impl MemoryDeviceStore {
    /// Point the fingerprint index entry for `(tenant, hash)` at the device
    /// that sorts first among those carrying the fingerprint under
    /// [`order_newest_first`] (newest sighting, then the smaller id), the
    /// same device the SQL backends return for the lookup, or remove the
    /// entry when none carries it.
    ///
    /// Called after every change that can alter which device that is (a
    /// save, a sighting, a delete or purge), and never while a row guard is
    /// held: the scan takes read guards on other rows. The entry is replaced
    /// only while it still holds the value this call started from, so two
    /// settles cannot overwrite each other with a stale answer; the later
    /// one re-reads and decides again.
    fn settle_fingerprint(&self, tenant_id: &TenantId, hash: &FingerprintHash) {
        let key = (*tenant_id, *hash);
        for _ in 0..SETTLE_ATTEMPTS {
            let current = self.fingerprint_index.get(&key).map(|v| *v);
            let best = self
                .devices
                .iter()
                .filter(|e| e.tenant_id == *tenant_id && e.fingerprint_hash == *hash)
                .map(|e| e.value().clone())
                .min_by(order_newest_first)
                .map(|d| d.id);
            if current == best {
                return;
            }
            // Whether this call or a concurrent one moved the entry, the loop
            // reads again: an answer computed from a scan can be stale by the
            // time it is stored (the device may have re-keyed meanwhile), and
            // only a read that finds entry and table in agreement ends it.
            match (current, best) {
                (Some(old), Some(new)) => {
                    if let Some(mut slot) = self.fingerprint_index.get_mut(&key)
                        && *slot == old
                    {
                        *slot = new;
                    }
                }
                (Some(old), None) => {
                    self.fingerprint_index.remove_if(&key, |_, v| *v == old);
                }
                (None, Some(new)) => {
                    if let Entry::Vacant(slot) = self.fingerprint_index.entry(key) {
                        slot.insert(new);
                    }
                }
                (None, None) => {}
            }
        }
    }
}

/// How often [`MemoryDeviceStore::settle_fingerprint`] re-reads after losing
/// a swap to a concurrent settle.
const SETTLE_ATTEMPTS: usize = 16;

impl DeviceStore for MemoryDeviceStore {
    type Error = MemoryDeviceStoreError;

    async fn load(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> Result<Option<Device>, Self::Error> {
        Ok(self
            .devices
            .get(&Self::key(tenant_id, id))
            .map(|d| d.clone()))
    }

    async fn find_by_fingerprint(
        &self,
        tenant_id: &TenantId,
        hash: &FingerprintHash,
    ) -> Result<Option<Device>, Self::Error> {
        let key = (*tenant_id, *hash);
        let Some(device_id) = self.fingerprint_index.get(&key).map(|v| *v) else {
            return Ok(None);
        };
        let pk = (*tenant_id, device_id);
        // The index is a hint: the row it names must still carry the hash.
        Ok(self
            .devices
            .get(&pk)
            .filter(|d| d.fingerprint_hash == *hash)
            .map(|d| d.clone()))
    }

    async fn find_by_fingerprint_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        hash: &FingerprintHash,
    ) -> Result<Option<Device>, Self::Error> {
        Ok(self
            .devices
            .iter()
            .filter(|entry| {
                let d = entry.value();
                d.tenant_id == *tenant_id
                    && d.fingerprint_hash == *hash
                    && d.user_id.as_ref() == Some(user_id)
            })
            .map(|entry| entry.value().clone())
            .min_by(order_newest_first))
    }

    async fn find_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        limit: usize,
    ) -> Result<Vec<Device>, Self::Error> {
        let mut hits: Vec<Device> = self
            .devices
            .iter()
            .filter_map(|entry| {
                let device = entry.value();
                let same_tenant = device.tenant_id == *tenant_id;
                let owned_by_user = device.user_id.as_ref().is_some_and(|u| u == user_id);
                (same_tenant && owned_by_user).then(|| device.clone())
            })
            .collect();
        hits.sort_by(order_newest_first);
        hits.truncate(limit);
        Ok(hits)
    }

    async fn find_by_refresh_family(
        &self,
        tenant_id: &TenantId,
        family_id: &str,
    ) -> Result<Vec<Device>, Self::Error> {
        let mut hits: Vec<Device> = self
            .devices
            .iter()
            .filter_map(|entry| {
                let device = entry.value();
                if device.tenant_id != *tenant_id {
                    return None;
                }
                let matched = device.bindings.iter().any(|b| {
                    matches!(b, DeviceBinding::Refresh { family_id: fid, .. } if fid == family_id)
                });
                matched.then(|| device.clone())
            })
            .collect();
        hits.sort_by(order_newest_first);
        Ok(hits)
    }

    async fn save(&self, device: &Device, now: DateTime<Utc>) -> Result<(), Self::Error> {
        let device = for_save(device, now);
        let key = Self::key(&device.tenant_id, &device.id);
        // The row changes under its shard lock; the fingerprint index is
        // settled afterwards, from the table as it is then.
        let mut vacated = None;
        match self.devices.entry(key) {
            Entry::Occupied(mut slot) => {
                if blocks_save(slot.get().trust_level) {
                    return Ok(());
                }
                let old = slot.insert(device.clone());
                if old.fingerprint_hash != device.fingerprint_hash {
                    vacated = Some(old.fingerprint_hash);
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(device.clone());
            }
        }
        // A device re-saved under a new fingerprint stops answering to the
        // old one, and a save takes over the new fingerprint's entry only
        // when the device sorts first among those carrying it.
        if let Some(hash) = vacated {
            self.settle_fingerprint(&device.tenant_id, &hash);
        }
        self.settle_fingerprint(&device.tenant_id, &device.fingerprint_hash);
        self.write_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn record_sighting(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        now: DateTime<Utc>,
    ) -> Result<DeviceTrustLevel, Self::Error> {
        let key = Self::key(tenant_id, id);
        let outcome = self.devices.get_mut(&key).map(|mut entry| {
            // A sighting never rewinds the clock and never touches a
            // revoked row.
            let moved = entry.trust_level != DeviceTrustLevel::Revoked && now > entry.last_seen_at;
            if moved {
                entry.last_seen_at = now;
            }
            (entry.trust_level, entry.fingerprint_hash, moved)
        });
        let Some((level, hash, moved)) = outcome else {
            return Err(MemoryDeviceStoreError::NotFound {
                tenant_id: tenant_id.to_string(),
                device_id: id.to_string(),
            });
        };
        // The row guard is released: a newer sighting can make this device
        // the one the fingerprint lookup returns.
        if moved {
            self.settle_fingerprint(tenant_id, &hash);
        }
        Ok(level)
    }

    async fn set_trust_level(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        let key = Self::key(tenant_id, id);
        if let Some(mut entry) = self.devices.get_mut(&key) {
            apply_trust_level(&mut entry, level, now);
            return Ok(());
        }
        Err(MemoryDeviceStoreError::NotFound {
            tenant_id: tenant_id.to_string(),
            device_id: id.to_string(),
        })
    }

    async fn set_trust_level_if(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> Result<TrustTransition, Self::Error> {
        // The shard lock `get_mut` holds makes the check and the write one
        // step with respect to every other writer of this row.
        let Some(mut entry) = self.devices.get_mut(&Self::key(tenant_id, id)) else {
            return Ok(TrustTransition::Missing);
        };
        if entry.trust_level != expected {
            return Ok(TrustTransition::Refused {
                current: entry.trust_level,
            });
        }
        apply_trust_level(&mut entry, level, now);
        Ok(TrustTransition::Applied)
    }

    async fn replace_bindings(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        _now: DateTime<Utc>,
    ) -> Result<BindingsUpdate, Self::Error> {
        // The shard lock `get_mut` holds makes the comparison and the write
        // one step with respect to every other writer of this row.
        let Some(mut entry) = self.devices.get_mut(&Self::key(tenant_id, id)) else {
            return Ok(BindingsUpdate::Missing);
        };
        if entry.trust_level == DeviceTrustLevel::Revoked {
            return Ok(BindingsUpdate::Revoked);
        }
        if entry.bindings != expected {
            return Ok(BindingsUpdate::Conflict);
        }
        entry.bindings = bindings.to_vec();
        Ok(BindingsUpdate::Written)
    }

    async fn claim_owner(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        user: &UserId,
        _now: DateTime<Utc>,
    ) -> Result<OwnerClaim, Self::Error> {
        let Some(mut entry) = self.devices.get_mut(&Self::key(tenant_id, id)) else {
            return Ok(OwnerClaim::Missing);
        };
        match entry.user_id.as_ref() {
            Some(owner) if owner == user => Ok(OwnerClaim::Claimed),
            Some(_) => Ok(OwnerClaim::OwnedByOther),
            None => {
                entry.user_id = Some(*user);
                Ok(OwnerClaim::Claimed)
            }
        }
    }

    async fn delete(&self, tenant_id: &TenantId, id: &DeviceId) -> Result<(), Self::Error> {
        if let Some((_, device)) = self.devices.remove(&Self::key(tenant_id, id)) {
            self.settle_fingerprint(&device.tenant_id, &device.fingerprint_hash);
        }
        Ok(())
    }

    async fn sweep(
        &self,
        tenant_id: &TenantId,
        now: DateTime<Utc>,
    ) -> Result<SweepCounts, Self::Error> {
        let cfg = self.sweep_config;
        let mut counts = SweepCounts::default();

        // The tenant's keys are listed first and each row is then decided
        // and written under its own write guard, so the decision is taken on
        // the row as it is at that moment: a revocation, a sighting or a
        // promotion that lands during the sweep is never overwritten by a
        // decision taken from an earlier snapshot, and only a write that
        // happens is counted.
        let candidates: Vec<DeviceKey> = self
            .devices
            .iter()
            .filter(|e| e.tenant_id == *tenant_id)
            .map(|e| *e.key())
            .collect();

        for key in candidates {
            let mut purged = None;
            if let Some(mut entry) = self.devices.get_mut(&key) {
                // One step per row per sweep. last_seen_at is NOT bumped by
                // a demotion: demotion does not constitute a sighting.
                let level = entry.trust_level;
                match cfg.level_after(level, entry.last_seen_at, entry.demoted_at, now) {
                    DeviceTrustLevel::Seen if level == DeviceTrustLevel::Trusted => {
                        entry.trust_level = DeviceTrustLevel::Seen;
                        entry.demoted_at = Some(now);
                        counts.trusted_to_seen += 1;
                    }
                    DeviceTrustLevel::Revoked if level == DeviceTrustLevel::Seen => {
                        entry.trust_level = DeviceTrustLevel::Revoked;
                        entry.revoked_at = Some(now);
                        entry.demoted_at = None;
                        counts.seen_to_revoked += 1;
                    }
                    _ => {}
                }
                // A revoked row without a revocation time (a row saved
                // that way by an older version) starts its grace now, so it
                // ages out instead of staying forever.
                if entry.trust_level == DeviceTrustLevel::Revoked && entry.revoked_at.is_none() {
                    entry.revoked_at = Some(now);
                }
                // Revoked -> purge counts from the *existing* `revoked_at`;
                // a row revoked or stamped in this very sweep is not purged
                // until a later sweep.
                if entry.trust_level == DeviceTrustLevel::Revoked
                    && entry.revoked_at.is_some_and(|r| cfg.purge_due(r, now))
                {
                    purged = Some(entry.clone());
                }
            }
            if let Some(snapshot) = purged {
                // Removed only if the row is still the revoked, expired one
                // this decision was taken on.
                let removed = self.devices.remove_if(&key, |_, d| {
                    d.trust_level == DeviceTrustLevel::Revoked
                        && d.revoked_at == snapshot.revoked_at
                });
                if let Some((_, device)) = removed {
                    self.settle_fingerprint(&device.tenant_id, &device.fingerprint_hash);
                    counts.revoked_purged += 1;
                }
            }
        }

        Ok(counts)
    }
}

/// Move a stored row to `level` at `now`: the `demoted_at` rule of every
/// backend, and `revoked_at` stamped on a move into `Revoked` but kept on a
/// row that already is, so repeating a revocation does not restart the purge
/// grace clock; a move out of `Revoked` clears it.
fn apply_trust_level(row: &mut Device, level: DeviceTrustLevel, now: DateTime<Utc>) {
    let was_revoked = row.trust_level == DeviceTrustLevel::Revoked;
    row.demoted_at = demotion_stamp(row.trust_level, level, row.demoted_at, now);
    row.trust_level = level;
    row.revoked_at = match (level, was_revoked) {
        (DeviceTrustLevel::Revoked, true) => row.revoked_at.or(Some(now)),
        (DeviceTrustLevel::Revoked, false) => Some(now),
        _ => None,
    };
}

impl HealthCheck for MemoryDeviceStore {
    fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async { HealthStatus::Healthy })
    }
}

#[cfg(test)]
mod tests;
