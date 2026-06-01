//! [`DeviceStore`] trait + [`MemoryDeviceStore`] in-memory backend.
//!
//! Mirrors the shape of [`SessionStore`](crate::session::SessionStore): an
//! associated `Error` type, async methods using return-position `impl Future`,
//! and an in-memory implementation suitable for tests and single-node examples.
//!
//! The retention sweep ([`DeviceStore::sweep`]) implements the full
//! three-stage demotion ladder.

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::types::{Device, DeviceTrustLevel, FingerprintHash};
use crate::health::{HealthCheck, HealthStatus};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ── DeviceStore trait ─────────────────────────────────────────────────────────

/// Typed, async device-identity backend.
///
/// Implementors: [`MemoryDeviceStore`], `SqliteDeviceStore`,
/// `PostgresDeviceStore`, `ValkeyDeviceStore`.
///
/// All methods accept `&self`; implementations use interior mutability
/// (`Arc<DashMap<…>>` for memory, connection pool for SQL/Valkey).
pub trait DeviceStore: Send + Sync + Clone + 'static {
    /// The error type returned by storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load the device by id. Returns `None` if absent.
    fn load(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send;

    /// Look up a device by its keyed fingerprint within a tenant. Used as
    /// the fast-path during request handling when no `device_id` cookie is
    /// present yet. Collisions must be vanishingly rare given a
    /// per-tenant HMAC key, but implementations MUST scope the query by
    /// `tenant_id` to prevent cross-tenant correlation.
    fn find_by_fingerprint(
        &self,
        tenant_id: &TenantId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send;

    /// List active devices for a user, newest-sighted first. `limit` caps
    /// the result so a high-cardinality user doesn't blow up
    /// device-management UIs.
    ///
    /// Returns every device regardless of trust level. Callers driving a
    /// device-management UI should filter to `trust_level != Revoked`, or
    /// use [`find_active_for_user`](Self::find_active_for_user) which
    /// applies that filter at the store layer.
    fn find_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send;

    /// Same as [`find_for_user`](Self::find_for_user) but excludes
    /// `Revoked` rows. Default implementation filters in-memory after a
    /// full `find_for_user` call; SQL backends SHOULD override with a
    /// `WHERE trust_level != 'Revoked'` clause that the optimiser can
    /// use against the trust-level index.
    fn find_active_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        async move {
            let mut all = self.find_for_user(tenant_id, user_id, limit).await?;
            all.retain(|d| d.trust_level != DeviceTrustLevel::Revoked);
            Ok(all)
        }
    }

    /// Find every device in `tenant` carrying a
    /// [`DeviceBinding::Refresh { family_id }`](crate::device::types::DeviceBinding::Refresh)
    /// matching the supplied `family_id`. Used by the refresh-cascade
    /// path to convert "this refresh-token family was compromised"
    /// into the list of [`Device`]s to revoke.
    ///
    /// Implementations MUST scope by `tenant_id` to prevent cross-
    /// tenant leakage and SHOULD scan or index on the `Refresh`
    /// binding variant only.
    fn find_by_refresh_family(
        &self,
        tenant_id: &TenantId,
        family_id: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send;

    /// Persist a new device row, or overwrite an existing one. Idempotent.
    fn save(&self, device: &Device) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Touch the `last_seen_at` timestamp for the given device.
    /// Implementations SHOULD perform this as a single UPDATE rather than
    /// a load-modify-save round trip.
    fn record_sighting(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Set the trust level. Drives transitions across the
    /// [`DeviceTrustLevel`] ladder. Setting to
    /// [`DeviceTrustLevel::Revoked`] also stamps `revoked_at = now`.
    fn set_trust_level(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Hard-delete the row. Idempotent. Used by the retention sweep once a
    /// `Revoked` device has aged out of the configured grace window, and
    /// by Art 17 erasure cascades.
    fn delete(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Drive the three-stage retention ladder: Trusted → Seen (after the
    /// configured Trusted-idle window), Seen → Revoked (after the
    /// configured Seen-idle window), Revoked → purged (after the
    /// configured grace window). Returns the count of rows changed at
    /// each stage.
    ///
    /// Required, not defaulted: a default of `Ok(SweepCounts::default())`
    /// would be a silent no-op: a backend that forgot to override would
    /// fail to demote anything, and the caller would have no way to tell
    /// "no rows aged out this tick" from "sweep is unimplemented." Every
    /// backend must answer the question, even if the answer is
    /// `Err(_)` with a "not yet implemented" sentinel.
    fn sweep(
        &self,
        tenant_id: &TenantId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send;
}

/// Per-stage counts returned by [`DeviceStore::sweep`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepCounts {
    /// `Trusted` rows demoted to `Seen` because last-seen exceeded the
    /// trusted-idle window.
    pub trusted_to_seen: u64,
    /// `Seen` rows demoted to `Revoked` because last-seen exceeded the
    /// seen-idle window.
    pub seen_to_revoked: u64,
    /// `Revoked` rows hard-deleted because they aged past the grace window.
    pub revoked_purged: u64,
}

// ── SweepConfig ───────────────────────────────────────────────────────────────

/// Retention thresholds driving [`DeviceStore::sweep`].
///
/// The sweep cascades demotions: a device whose last-seen is older
/// than `trusted_idle + seen_idle` will pass through both demotion
/// stages in a single sweep call (Trusted → Seen → Revoked); a
/// further sweep after `revoked_grace` has elapsed since the
/// just-stamped `revoked_at` finalises the row purge. `Unknown`
/// devices are NOT demoted by sweep; they can only graduate via an
/// explicit promotion step; retention of stale `Unknown` rows is the
/// application's call.
///
/// Defaults reflect a fintech-style retention posture suitable for
/// PSD2 / DORA / MiFID II contexts: 90-day trusted idle, 30-day
/// seen idle, 7-day revoked grace. Tighten or loosen via
/// [`SweepConfig::builder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepConfig {
    /// How long a `Trusted` device may go un-sighted before sweep
    /// demotes it to `Seen`. NIST SP 800-63B-4 §5.2.6 informs the
    /// 90-day default: a device that hasn't authenticated for a
    /// quarter shouldn't keep its possession-factor status without a
    /// fresh ceremony.
    pub trusted_idle: chrono::Duration,
    /// How long a `Seen` device may go un-sighted before sweep
    /// demotes it to `Revoked`.
    pub seen_idle: chrono::Duration,
    /// How long a `Revoked` device row sticks around before hard
    /// deletion. Provides an audit-trail window for forensics on
    /// recently-compromised devices.
    pub revoked_grace: chrono::Duration,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            trusted_idle: chrono::Duration::days(90),
            seen_idle: chrono::Duration::days(30),
            revoked_grace: chrono::Duration::days(7),
        }
    }
}

impl SweepConfig {
    /// Construct via the builder.
    pub fn builder() -> SweepConfigBuilder {
        SweepConfigBuilder::default()
    }
}

/// Builder for [`SweepConfig`]. Each setter overrides the default
/// for one window; unset fields keep their default value.
#[derive(Debug, Default, Clone, Copy)]
pub struct SweepConfigBuilder {
    trusted_idle: Option<chrono::Duration>,
    seen_idle: Option<chrono::Duration>,
    revoked_grace: Option<chrono::Duration>,
}

impl SweepConfigBuilder {
    /// Set the Trusted-idle window.
    pub fn trusted_idle(mut self, d: chrono::Duration) -> Self {
        self.trusted_idle = Some(d);
        self
    }
    /// Set the Seen-idle window.
    pub fn seen_idle(mut self, d: chrono::Duration) -> Self {
        self.seen_idle = Some(d);
        self
    }
    /// Set the Revoked-grace window.
    pub fn revoked_grace(mut self, d: chrono::Duration) -> Self {
        self.revoked_grace = Some(d);
        self
    }
    /// Finalise the [`SweepConfig`].
    pub fn build(self) -> SweepConfig {
        let d = SweepConfig::default();
        SweepConfig {
            trusted_idle: self.trusted_idle.unwrap_or(d.trusted_idle),
            seen_idle: self.seen_idle.unwrap_or(d.seen_idle),
            revoked_grace: self.revoked_grace.unwrap_or(d.revoked_grace),
        }
    }
}

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
/// cross-node visibility.
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
        Ok(self.devices.get(&pk).map(|d| d.clone()))
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
        hits.sort_by_key(|d| std::cmp::Reverse(d.last_seen_at));
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
                    matches!(b, crate::device::types::DeviceBinding::Refresh { family_id: fid, .. } if fid == family_id)
                });
                matched.then(|| device.clone())
            })
            .collect();
        // Newest-sighted first to match `find_for_user` ordering.
        hits.sort_by_key(|d| std::cmp::Reverse(d.last_seen_at));
        Ok(hits)
    }

    async fn save(&self, device: &Device) -> Result<(), Self::Error> {
        let key = Self::key(&device.tenant_id, &device.id);
        let fp_key = (device.tenant_id, device.fingerprint_hash);
        self.devices.insert(key, device.clone());
        self.fingerprint_index.insert(fp_key, device.id);
        self.write_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn record_sighting(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        let key = Self::key(tenant_id, id);
        if let Some(mut entry) = self.devices.get_mut(&key) {
            entry.last_seen_at = now;
            return Ok(());
        }
        Err(MemoryDeviceStoreError::NotFound {
            tenant_id: tenant_id.to_string(),
            device_id: id.to_string(),
        })
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
            entry.trust_level = level;
            entry.revoked_at = matches!(level, DeviceTrustLevel::Revoked).then_some(now);
            return Ok(());
        }
        Err(MemoryDeviceStoreError::NotFound {
            tenant_id: tenant_id.to_string(),
            device_id: id.to_string(),
        })
    }

    async fn delete(&self, tenant_id: &TenantId, id: &DeviceId) -> Result<(), Self::Error> {
        let key = Self::key(tenant_id, id);
        if let Some((_, device)) = self.devices.remove(&key) {
            let fp_key = (device.tenant_id, device.fingerprint_hash);
            self.fingerprint_index.remove(&fp_key);
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

        // Two passes: (1) collect transitions while only holding read
        // refs; (2) apply mutations. Avoids re-entering `DashMap` while
        // a `get_mut` is held, which deadlocks on contended shards.
        enum Action {
            DemoteToSeen,
            DemoteToRevoked,
            Purge,
        }
        let mut actions: Vec<(DeviceKey, Action)> = Vec::new();

        for entry in self.devices.iter() {
            let device = entry.value();
            if device.tenant_id != *tenant_id {
                continue;
            }
            // Trusted → Seen. last_seen_at is NOT bumped; demotion
            // does not constitute a sighting.
            let mut current_level = device.trust_level;
            if current_level == DeviceTrustLevel::Trusted
                && now.signed_duration_since(device.last_seen_at) > cfg.trusted_idle
            {
                actions.push((*entry.key(), Action::DemoteToSeen));
                counts.trusted_to_seen += 1;
                current_level = DeviceTrustLevel::Seen;
            }
            // Seen → Revoked (cascades from the Trusted → Seen demotion
            // when last-seen clears both windows).
            if current_level == DeviceTrustLevel::Seen
                && now.signed_duration_since(device.last_seen_at) > cfg.seen_idle
            {
                actions.push((*entry.key(), Action::DemoteToRevoked));
                counts.seen_to_revoked += 1;
                current_level = DeviceTrustLevel::Revoked;
            }
            // Revoked → Purge. Uses the *existing* `revoked_at`, not
            // `now`; a device demoted in this same sweep won't be
            // purged until a future sweep where the grace has elapsed.
            if current_level == DeviceTrustLevel::Revoked
                && let Some(revoked_at) = device.revoked_at
                && now.signed_duration_since(revoked_at) > cfg.revoked_grace
            {
                actions.push((*entry.key(), Action::Purge));
                counts.revoked_purged += 1;
            }
        }

        for (key, action) in actions {
            match action {
                Action::DemoteToSeen => {
                    if let Some(mut entry) = self.devices.get_mut(&key) {
                        entry.trust_level = DeviceTrustLevel::Seen;
                    }
                }
                Action::DemoteToRevoked => {
                    if let Some(mut entry) = self.devices.get_mut(&key) {
                        entry.trust_level = DeviceTrustLevel::Revoked;
                        entry.revoked_at = Some(now);
                    }
                }
                Action::Purge => {
                    if let Some((_, device)) = self.devices.remove(&key) {
                        let fp_key = (device.tenant_id, device.fingerprint_hash);
                        self.fingerprint_index.remove(&fp_key);
                    }
                }
            }
        }

        Ok(counts)
    }
}

impl HealthCheck for MemoryDeviceStore {
    fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async { HealthStatus::Healthy })
    }
}

#[cfg(test)]
mod tests;
