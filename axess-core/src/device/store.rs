//! [`DeviceStore`] trait + [`MemoryDeviceStore`] in-memory backend.
//!
//! Mirrors the shape of [`SessionStore`](crate::session::SessionStore): an
//! associated `Error` type, async methods using return-position `impl Future`,
//! and an in-memory implementation suitable for tests and single-node examples.
//!
//! The retention sweep ([`DeviceStore::sweep`]) implements the full
//! three-stage demotion ladder.

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
use crate::health::{HealthCheck, HealthStatus};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// How many of a user's devices the default
/// [`DeviceStore::find_by_fingerprint_for_user`] scans.
pub const OWN_DEVICE_SCAN_LIMIT: usize = 100;

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

    /// Look up the device `user_id` owns that carries `hash`, newest-sighted
    /// first when several do. Unlike [`find_by_fingerprint`](Self::find_by_fingerprint),
    /// which returns one row for the whole tenant (possibly another user's),
    /// this finds the caller's own device however many devices the user has.
    ///
    /// The default implementation scans the user's
    /// [`OWN_DEVICE_SCAN_LIMIT`] most recently seen devices, so a user with
    /// more devices than that can miss an older match. Backends SHOULD
    /// override it with an indexed query on `(tenant, user, fingerprint)`.
    fn find_by_fingerprint_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        async move {
            Ok(self
                .find_for_user(tenant_id, user_id, OWN_DEVICE_SCAN_LIMIT)
                .await?
                .into_iter()
                .find(|d| d.fingerprint_hash == *hash))
        }
    }

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
    /// `Revoked` rows, and returns up to `limit` of the remaining ones.
    /// The default implementation asks `find_for_user` for more rows
    /// until `limit` active ones are found or the user has no more
    /// devices, so revoked devices never use up the limit. SQL backends
    /// SHOULD override with a `WHERE trust_level != 'Revoked'` clause
    /// that the optimiser can use against the trust-level index.
    fn find_active_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        async move {
            if limit == 0 {
                return Ok(Vec::new());
            }
            let mut fetch = limit;
            loop {
                let mut rows = self.find_for_user(tenant_id, user_id, fetch).await?;
                let exhausted = rows.len() < fetch;
                rows.retain(|d| d.trust_level != DeviceTrustLevel::Revoked);
                if rows.len() >= limit || exhausted {
                    rows.truncate(limit);
                    return Ok(rows);
                }
                fetch = fetch.saturating_mul(2);
            }
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
    ///
    /// `now` is the time of the write. A backend that expires rows by
    /// age derives the row's lifetime from it, so the store never reads the
    /// wall clock itself.
    fn save(
        &self,
        device: &Device,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

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

    /// Set the trust level to `level` only if the row is currently at
    /// `expected`; a compare-and-set, so a transition decided from an
    /// earlier read cannot overwrite a change made in between (most
    /// importantly a revocation).
    ///
    /// Returns [`TrustTransition::Applied`] when the row was at `expected`
    /// and is now at `level` (with `revoked_at` stamped or cleared exactly
    /// as [`set_trust_level`](Self::set_trust_level) does),
    /// [`TrustTransition::Refused`] carrying the level actually found when
    /// it was not, and [`TrustTransition::Missing`] when no such device
    /// exists.
    ///
    /// Backends MUST implement this as one conditional write in their own
    /// storage engine. The provided body is a load followed by an
    /// unconditional write and is NOT safe against a concurrent change; it
    /// exists so that an out-of-tree backend keeps compiling, and a
    /// backend that is used with concurrent writers must override it.
    fn set_trust_level_if(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<TrustTransition, Self::Error>> + Send {
        async move {
            let Some(device) = self.load(tenant_id, id).await? else {
                return Ok(TrustTransition::Missing);
            };
            if device.trust_level != expected {
                return Ok(TrustTransition::Refused {
                    current: device.trust_level,
                });
            }
            self.set_trust_level(tenant_id, id, level, now).await?;
            Ok(TrustTransition::Applied)
        }
    }

    /// Replace the device's bindings with `bindings`, only if they are
    /// still exactly `expected`, and nothing else; never on a
    /// [`DeviceTrustLevel::Revoked`] device. A compare-and-swap on the
    /// bindings: two editors that each read the row, changed it and wrote it
    /// back cannot both succeed, so neither loses the other's change, and
    /// unlike [`save`](Self::save) it never writes the trust level,
    /// `revoked_at` or any other column, so a revocation that lands while
    /// the caller is working cannot be undone by it and a revoked device
    /// never gains a binding.
    ///
    /// Returns [`BindingsUpdate::Written`], [`BindingsUpdate::Conflict`]
    /// (the stored bindings differ from `expected`; nothing written, reload
    /// and decide again), [`BindingsUpdate::Revoked`] (nothing written) or
    /// [`BindingsUpdate::Missing`].
    ///
    /// The same rule as [`set_trust_level_if`](Self::set_trust_level_if)
    /// applies to the provided body: it is a load and a [`save`](Self::save),
    /// not safe against a concurrent writer, and a backend with concurrent
    /// writers must override it with a conditional write.
    fn replace_bindings(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<BindingsUpdate, Self::Error>> + Send {
        async move {
            let Some(mut device) = self.load(tenant_id, id).await? else {
                return Ok(BindingsUpdate::Missing);
            };
            if device.trust_level == DeviceTrustLevel::Revoked {
                return Ok(BindingsUpdate::Revoked);
            }
            if device.bindings != expected {
                return Ok(BindingsUpdate::Conflict);
            }
            device.bindings = bindings.to_vec();
            self.save(&device, now).await?;
            Ok(BindingsUpdate::Written)
        }
    }

    /// Make `user` the owner of the device if it has none (`user_id IS
    /// NULL`), as one conditional write.
    ///
    /// A device created during a guest request has no owner, and without a
    /// claim any later user could resolve it. Returns
    /// [`OwnerClaim::Claimed`] when the device is now owned by `user`
    /// (including when it already was), [`OwnerClaim::OwnedByOther`] when
    /// another user owns it (nothing written), and [`OwnerClaim::Missing`]
    /// when no such device exists. Two users racing for one unowned device:
    /// exactly one is `Claimed`.
    ///
    /// The provided body is a load and a [`save`](Self::save) and is NOT
    /// safe against a concurrent claim; a backend with concurrent writers
    /// must override it with a conditional write.
    fn claim_owner(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<OwnerClaim, Self::Error>> + Send {
        async move {
            let Some(mut device) = self.load(tenant_id, id).await? else {
                return Ok(OwnerClaim::Missing);
            };
            match device.user_id.as_ref() {
                Some(owner) if owner == user => Ok(OwnerClaim::Claimed),
                Some(_) => Ok(OwnerClaim::OwnedByOther),
                None => {
                    device.user_id = Some(*user);
                    self.save(&device, now).await?;
                    Ok(OwnerClaim::Claimed)
                }
            }
        }
    }

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

/// Result of [`DeviceStore::set_trust_level_if`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a refused transition means the device was not changed"]
pub enum TrustTransition {
    /// The row was at the expected level and now carries the new one.
    Applied,
    /// The row was not at the expected level and was left untouched.
    /// `current` is the level found; [`DeviceTrustLevel::Revoked`] means a
    /// revocation won the race.
    Refused {
        /// The trust level the row actually had.
        current: DeviceTrustLevel,
    },
    /// No device with that id exists in the tenant.
    Missing,
}

/// Result of [`DeviceStore::replace_bindings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a revoked or missing device was not changed"]
pub enum BindingsUpdate {
    /// The bindings were replaced.
    Written,
    /// The stored bindings are not the ones the caller read (another
    /// writer changed them first); nothing was written.
    Conflict,
    /// The device is revoked; nothing was written.
    Revoked,
    /// No device with that id exists in the tenant.
    Missing,
}

/// Result of [`DeviceStore::claim_owner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a claim owned by another user means the device must not be used"]
pub enum OwnerClaim {
    /// The device is now owned by the claiming user (newly, or already).
    Claimed,
    /// Another user owns the device; nothing was written.
    OwnedByOther,
    /// No device with that id exists in the tenant.
    Missing,
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
/// The sweep moves each row at most one step per call. A `Trusted` device
/// un-sighted for more than `trusted_idle` is demoted to `Seen` (never
/// revoked in the same sweep) and the demotion is stamped on the row
/// ([`Device::demoted_at`]). A `Seen` device is revoked once `seen_idle` has
/// passed since the later of its last sighting and its demotion: a `Seen`
/// device that was never `Trusted` is therefore revoked `seen_idle` after
/// its last sighting, and one that was demoted gets its full `seen_idle`
/// window from the demotion (120 days from the last sighting in total with
/// the defaults, when it was not sighted again). A further sweep after
/// `revoked_grace` has elapsed since the just-stamped `revoked_at`
/// finalises the row purge. `Unknown`
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
    /// How long a `Seen` device may go un-sighted before sweep revokes
    /// it, counted from the later of its last sighting and its demotion
    /// from `Trusted` ([`Device::demoted_at`]).
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
    /// The level a device settles at after ONE step of the sweep's two
    /// demotion stages (the `Revoked` purge is separate: it counts from
    /// `revoked_at`). A row never moves two levels in one call, so a
    /// `Trusted` device is demoted to `Seen` and gets its `seen_idle` window
    /// from `now`. `Unknown` and `Revoked` are never moved by these stages.
    ///
    /// The `Seen` window runs from the later of `last_seen_at` and
    /// `demoted_at`, so a device that was never trusted (`demoted_at` is
    /// `None`) is revoked `seen_idle` after its last sighting, and a demoted
    /// one `seen_idle` after the demotion unless it is sighted again, which
    /// restarts the window.
    pub fn level_after(
        &self,
        level: DeviceTrustLevel,
        last_seen_at: DateTime<Utc>,
        demoted_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> DeviceTrustLevel {
        match level {
            DeviceTrustLevel::Trusted if now - last_seen_at > self.trusted_idle => {
                DeviceTrustLevel::Seen
            }
            DeviceTrustLevel::Seen
                if now - demoted_at.map_or(last_seen_at, |d| d.max(last_seen_at))
                    > self.seen_idle =>
            {
                DeviceTrustLevel::Revoked
            }
            other => other,
        }
    }

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

/// The `demoted_at` a row carries after its trust level moves from `from`
/// to `to` at `now`, given the value it carried before.
///
/// Moving `Trusted` to `Seen` stamps `now`; staying `Seen` (or moving to
/// `Seen` from a level that was never trusted) keeps what the row had; every
/// other target clears it, so a promotion to `Trusted` starts a fresh ladder.
/// Every backend applies exactly this rule.
pub(crate) fn demotion_stamp(
    from: DeviceTrustLevel,
    to: DeviceTrustLevel,
    current: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    match (from, to) {
        (DeviceTrustLevel::Trusted, DeviceTrustLevel::Seen) => Some(now),
        (_, DeviceTrustLevel::Seen) => current,
        _ => None,
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
            .max_by_key(|d| d.last_seen_at))
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

    async fn save(&self, device: &Device, _now: DateTime<Utc>) -> Result<(), Self::Error> {
        let key = Self::key(&device.tenant_id, &device.id);
        let fp_key = (device.tenant_id, device.fingerprint_hash);
        let previous = self.devices.insert(key, device.clone());
        // A device re-saved under a new fingerprint must stop answering
        // to the old one, unless the old entry already belongs to
        // another device.
        if let Some(old) = previous
            && old.fingerprint_hash != device.fingerprint_hash
        {
            self.fingerprint_index
                .remove_if(&(old.tenant_id, old.fingerprint_hash), |_, v| *v == old.id);
        }
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
            entry.demoted_at = demotion_stamp(entry.trust_level, level, entry.demoted_at, now);
            entry.trust_level = level;
            entry.revoked_at = matches!(level, DeviceTrustLevel::Revoked).then_some(now);
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
        entry.demoted_at = demotion_stamp(entry.trust_level, level, entry.demoted_at, now);
        entry.trust_level = level;
        entry.revoked_at = matches!(level, DeviceTrustLevel::Revoked).then_some(now);
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
        let key = Self::key(tenant_id, id);
        if let Some((_, device)) = self.devices.remove(&key) {
            let fp_key = (device.tenant_id, device.fingerprint_hash);
            self.fingerprint_index
                .remove_if(&fp_key, |_, v| *v == device.id);
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
            // One step per row per sweep. last_seen_at is NOT bumped by a
            // demotion: demotion does not constitute a sighting.
            let mut current_level = device.trust_level;
            match cfg.level_after(current_level, device.last_seen_at, device.demoted_at, now) {
                DeviceTrustLevel::Seen if current_level == DeviceTrustLevel::Trusted => {
                    actions.push((*entry.key(), Action::DemoteToSeen));
                    counts.trusted_to_seen += 1;
                }
                DeviceTrustLevel::Revoked if current_level == DeviceTrustLevel::Seen => {
                    actions.push((*entry.key(), Action::DemoteToRevoked));
                    counts.seen_to_revoked += 1;
                    current_level = DeviceTrustLevel::Revoked;
                }
                _ => {}
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
                        entry.demoted_at = Some(now);
                    }
                }
                Action::DemoteToRevoked => {
                    if let Some(mut entry) = self.devices.get_mut(&key) {
                        entry.trust_level = DeviceTrustLevel::Revoked;
                        entry.revoked_at = Some(now);
                        entry.demoted_at = None;
                    }
                }
                Action::Purge => {
                    if let Some((_, device)) = self.devices.remove(&key) {
                        let fp_key = (device.tenant_id, device.fingerprint_hash);
                        self.fingerprint_index
                            .remove_if(&fp_key, |_, v| *v == device.id);
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

#[cfg(test)]
pub(crate) mod ladder;

#[cfg(test)]
mod claims;
