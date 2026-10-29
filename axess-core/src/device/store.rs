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
use chrono::{DateTime, Utc};
use std::future::Future;

mod memory;

pub use memory::{MemoryDeviceStore, MemoryDeviceStoreError};

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
    /// wall clock itself, and it is also the `revoked_at` a
    /// [`DeviceTrustLevel::Revoked`] row gets when the caller left it
    /// `None`, so a revoked row always has a grace clock and the sweep can
    /// purge it.
    ///
    /// A save never changes a stored [`DeviceTrustLevel::Revoked`] row: a
    /// `Device` loaded before a revocation and saved after it leaves the
    /// revoked row as it is, and a save of a revoked copy does not rewrite
    /// the row's `revoked_at` or bindings either. Reinstating a revoked
    /// device is an explicit [`set_trust_level`](Self::set_trust_level).
    fn save(
        &self,
        device: &Device,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Touch the `last_seen_at` timestamp for the given device.
    /// Implementations SHOULD perform this as a single UPDATE rather than
    /// a load-modify-save round trip.
    ///
    /// The write is monotonic: `last_seen_at` becomes the later of its
    /// stored value and `now`, so a late or out-of-order request never moves
    /// it backwards. A [`DeviceTrustLevel::Revoked`] row is not touched (a
    /// sighting cannot extend a revoked device) and the call still succeeds.
    /// A missing device is an error.
    ///
    /// Returns the trust level the row had when the sighting was applied (or
    /// skipped): [`DeviceTrustLevel::Revoked`] means the row is revoked and
    /// was not touched, including when it was revoked after the caller last
    /// loaded it. A caller that reports a device's level after a sighting
    /// reports this value, not the level it read earlier.
    fn record_sighting(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<DeviceTrustLevel, Self::Error>> + Send;

    /// Set the trust level. Drives transitions across the
    /// [`DeviceTrustLevel`] ladder. Setting to
    /// [`DeviceTrustLevel::Revoked`] also stamps `revoked_at = now`, except
    /// on a row that is already revoked, which keeps its original
    /// `revoked_at` so repeating a revocation does not restart the purge
    /// grace clock.
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
    ///
    /// Every comparison is made on whole seconds (the instants are floored
    /// to the second, the windows are whole seconds), which is how the SQL
    /// backends store and compare timestamps. All backends therefore take
    /// the same decision for the same row, whatever the sub-second part of
    /// the instants.
    pub fn level_after(
        &self,
        level: DeviceTrustLevel,
        last_seen_at: DateTime<Utc>,
        demoted_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> DeviceTrustLevel {
        let idle_secs = |since: DateTime<Utc>| now.timestamp() - since.timestamp();
        match level {
            DeviceTrustLevel::Trusted
                if idle_secs(last_seen_at) > self.trusted_idle.num_seconds() =>
            {
                DeviceTrustLevel::Seen
            }
            DeviceTrustLevel::Seen
                if idle_secs(demoted_at.map_or(last_seen_at, |d| d.max(last_seen_at)))
                    > self.seen_idle.num_seconds() =>
            {
                DeviceTrustLevel::Revoked
            }
            other => other,
        }
    }

    /// `true` when a `Revoked` row revoked at `revoked_at` has outlived the
    /// grace window at `now` and may be purged. Whole seconds, like
    /// [`level_after`](Self::level_after).
    pub fn purge_due(&self, revoked_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        now.timestamp() - revoked_at.timestamp() > self.revoked_grace.num_seconds()
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
    ///
    /// # Errors
    ///
    /// [`SweepConfigError::SubSecondWindow`] when a window is not a whole
    /// number of seconds: every backend compares whole seconds, so a
    /// fraction would be silently dropped.
    pub fn build(self) -> Result<SweepConfig, SweepConfigError> {
        let d = SweepConfig::default();
        let cfg = SweepConfig {
            trusted_idle: self.trusted_idle.unwrap_or(d.trusted_idle),
            seen_idle: self.seen_idle.unwrap_or(d.seen_idle),
            revoked_grace: self.revoked_grace.unwrap_or(d.revoked_grace),
        };
        for (window, value) in [
            ("trusted_idle", cfg.trusted_idle),
            ("seen_idle", cfg.seen_idle),
            ("revoked_grace", cfg.revoked_grace),
        ] {
            if value.subsec_nanos() != 0 {
                return Err(SweepConfigError::SubSecondWindow { window });
            }
        }
        Ok(cfg)
    }
}

/// Why [`SweepConfigBuilder::build`] refused a configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SweepConfigError {
    /// A retention window has a fractional-second part.
    #[error("sweep window `{window}` must be a whole number of seconds")]
    SubSecondWindow {
        /// The field that carried the fraction.
        window: &'static str,
    },
}

/// Newest-sighted first, ties broken by the smaller device id, so every
/// backend returns the same device for equal `last_seen_at` whatever its
/// iteration order.
pub(crate) fn order_newest_first(a: &Device, b: &Device) -> std::cmp::Ordering {
    b.last_seen_at
        .cmp(&a.last_seen_at)
        .then_with(|| a.id.cmp(&b.id))
}

/// The row a [`DeviceStore::save`] stores for `device`: a revoked row with no
/// `revoked_at` gets `now`, so it has a grace clock and can be purged.
pub(crate) fn for_save(device: &Device, now: DateTime<Utc>) -> Device {
    let mut row = device.clone();
    if row.trust_level == DeviceTrustLevel::Revoked && row.revoked_at.is_none() {
        row.revoked_at = Some(now);
    }
    row
}

/// `true` when a save must leave a stored row at `stored` alone: a save never un-revokes, and it never rewrites a revoked row
/// either, so a stale copy of a revoked device (an older `revoked_at`, older
/// bindings) cannot restart its purge grace clock or bring old state back.
pub(crate) fn blocks_save(stored: DeviceTrustLevel) -> bool {
    stored == DeviceTrustLevel::Revoked
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

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod ladder;

#[cfg(test)]
mod claims;

#[cfg(test)]
pub(crate) mod consistency;

#[cfg(all(test, any(feature = "postgres", feature = "mysql")))]
pub(crate) mod sql_contract;
