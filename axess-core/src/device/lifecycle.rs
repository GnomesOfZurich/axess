//! [`DeviceLifecycleService`]: opinionated higher-level helper that
//! composes [`DeviceStore`] primitives into the operations an axess
//! consumer needs at request/authn boundaries:
//!
//! 0. **Resolve by proof**
//!    ([`resolve_or_keep`](DeviceLifecycleService::resolve_or_keep),
//!    [`resolve_proven`](DeviceLifecycleService::resolve_proven)): find the
//!    device by the secret token on its cookie, keep the one the session
//!    is bound to, or create one for an authenticated user. This is what
//!    [`LifecycleDeviceResolver`](crate::device::LifecycleDeviceResolver)
//!    runs on every request; the fingerprint selects nothing there.
//! 1. **Ensure-or-create**
//!    ([`ensure_device`](DeviceLifecycleService::ensure_device)), for an
//!    application that proves the device some other way: given a fingerprint, look up the existing
//!    `Device` row or create a fresh one with
//!    [`DeviceTrustLevel::Unknown`]. Idempotent on the existing-device
//!    path; bumps `last_seen_at` either way (at most once per sighting
//!    granularity for a known device, see
//!    [`DeviceLifecycleService::with_sighting_granularity`]).
//! 2. **Promote-on-authn**: atomically transition `Unknown → Seen`
//!    when authentication succeeds. No-op when the device is already
//!    `Seen`, `Trusted`, or `Revoked`; never re-elevates a revoked
//!    device, never demotes a trusted one.
//!
//! # Why a separate helper (not a trait extension)
//!
//! The store trait stays focused on storage primitives so SQL / Valkey
//! backends don't have to re-implement the lifecycle state machine.
//! Composition over inheritance: every backend that implements
//! [`DeviceStore`] gets the lifecycle logic for free, and the unit
//! tests on the lifecycle live in one place.
//!
//! # What this helper does **not** do
//!
//! - **Compute the fingerprint.** The application supplies a
//!   pre-computed [`FingerprintHash`]. Choosing the input set
//!   (User-Agent family, IP /24, Accept-Language, …), the
//!   tenant-scoped HMAC pepper, and the parsing strategy is an
//!   application concern that varies by deployment;
//!   [`DefaultFingerprintExtractor`](crate::device::DefaultFingerprintExtractor)
//!   is the stock choice, and the lifecycle layer is
//!   fingerprint-agnostic.
//! - **Wire itself into middleware.** The decision of *where* in the
//!   request pipeline a resolution runs is made by the
//!   [`DeviceResolver`](crate::device::DeviceResolver) the session layer
//!   is given
//!   ([`LifecycleDeviceResolver`](crate::device::LifecycleDeviceResolver)
//!   calls `resolve_or_keep`), or by application code calling
//!   `ensure_device` directly. This keeps the helper
//!   testable in isolation and lets apps make the cost trade-offs.
//! - **Revoke devices, and their tokens, when a refresh family is
//!   compromised.** That is
//!   [`cascade_revoke_by_refresh_family_and_tokens`](crate::device::cascade_revoke_by_refresh_family_and_tokens),
//!   which finds the devices through
//!   [`DeviceStore::find_by_refresh_family`] and revokes every refresh
//!   token bound to them, whatever its family.

use axess_clock::Timestamp;
use std::future::Future;
use std::sync::Arc;

use crate::authn::event::{AuthEventBuilder, AuthEventType};
use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::authn::service::FactorOutcome;
use crate::device::events::{DeviceEventSink, NoopDeviceEventSink};
// Named by the doc links below, and by the tests through `super::*`.
#[cfg(any(doc, test))]
use crate::device::proof::ProvenDevice;
use crate::device::proof::UserDevice;
#[cfg(feature = "fido2")]
use crate::device::store::BindingsUpdate;
use crate::device::store::{DeviceStore, OwnerClaim, TrustTransition};
use crate::device::types::{Device, DeviceTrustLevel, FingerprintHash};

/// How long after a device's recorded `last_seen_at` `ensure_device`
/// treats another sighting as redundant, unless
/// [`DeviceLifecycleService::with_sighting_granularity`] says otherwise.
const DEFAULT_SIGHTING_GRANULARITY: std::time::Duration = std::time::Duration::from_mins(5);

/// How many `Unknown` devices one user may hold at once, unless
/// [`DeviceLifecycleService::with_max_unknown_devices_per_user`] says
/// otherwise. A client that arrives without its device cookie gets a new
/// `Unknown` device per login; past this many, the least recently seen
/// `Unknown` devices of that user are deleted to make room. `Seen` and
/// `Trusted` devices are never evicted.
pub const DEFAULT_MAX_UNKNOWN_DEVICES_PER_USER: usize = 32;

/// How often a bindings edit re-reads the row and tries again after losing a
/// compare-and-swap to a concurrent edit.
#[cfg(feature = "fido2")]
const BINDINGS_RETRIES: usize = 16;

/// `true` when `device` may serve a request made by `user`: the device is
/// unowned, the request is not yet attributed to a user (a guest), or the
/// owner is that user. A revoked device serves nobody: a request that
/// matches one is treated as a new device, as the device chapter describes.
fn is_usable_by(device: &Device, user: Option<&UserId>) -> bool {
    if device.trust_level == DeviceTrustLevel::Revoked {
        return false;
    }
    match (device.user_id.as_ref(), user) {
        (Some(owner), Some(user)) => owner == user,
        _ => true,
    }
}

/// Composes [`DeviceStore`] primitives into the lifecycle operations
/// every axess consumer needs at request/authn boundaries.
///
/// Cheap to clone (the inner store is `Clone` and the optional event
/// sink is `Arc`-backed); construct once at startup and share across
/// handlers.
#[derive(Clone)]
pub struct DeviceLifecycleService<S>
where
    S: DeviceStore,
{
    store: S,
    /// Optional sink for device-lifecycle audit events.
    /// Defaults to [`NoopDeviceEventSink`] so deployments that don't
    /// (yet) record audit events run unchanged.
    event_sink: Arc<dyn DeviceEventSink>,
    /// A known device whose `last_seen_at` is newer than this is not
    /// written again by `ensure_device`.
    sighting_granularity: std::time::Duration,
    /// See [`DEFAULT_MAX_UNKNOWN_DEVICES_PER_USER`].
    max_unknown_per_user: usize,
}

impl<S> DeviceLifecycleService<S>
where
    S: DeviceStore,
{
    /// Wrap a [`DeviceStore`]. Audit events are dropped on the floor
    /// until [`Self::with_event_sink`] is called; the underlying
    /// device-state mutations always happen regardless.
    pub fn new(store: S) -> Self {
        Self {
            store,
            event_sink: Arc::new(NoopDeviceEventSink),
            sighting_granularity: DEFAULT_SIGHTING_GRANULARITY,
            max_unknown_per_user: DEFAULT_MAX_UNKNOWN_DEVICES_PER_USER,
        }
    }

    /// How many `Unknown` devices one user may hold (default
    /// [`DEFAULT_MAX_UNKNOWN_DEVICES_PER_USER`]; at least one).
    ///
    /// A request that carries a user and no valid device cookie creates a
    /// device. Without a bound a client that drops its cookie, or a script,
    /// adds a row per login for ever. When a user already holds this many
    /// `Unknown` devices, the least recently seen are deleted before the new
    /// one is written. Only `Unknown` rows are evicted: a device the user has
    /// been recognised on (`Seen`, `Trusted`) stays.
    pub fn with_max_unknown_devices_per_user(mut self, max: usize) -> Self {
        self.max_unknown_per_user = max.max(1);
        self
    }

    /// Set how stale a device's `last_seen_at` must be before
    /// [`ensure_device`](Self::ensure_device) writes a new sighting
    /// (default 5 minutes). A request for a device seen more recently
    /// than `granularity` before `now` performs no write, so a busy
    /// client costs one store write per window rather than one per
    /// request. [`Duration::ZERO`](std::time::Duration::ZERO) records every
    /// sighting.
    pub fn with_sighting_granularity(mut self, granularity: std::time::Duration) -> Self {
        self.sighting_granularity = granularity;
        self
    }

    /// Wire a [`DeviceEventSink`] so device-lifecycle transitions emit
    /// audit events. Typically wraps an
    /// [`IdentityStore`](crate::authn::store::IdentityStore) via
    /// [`IdentityStoreEventSink`](super::events::IdentityStoreEventSink).
    pub fn with_event_sink<E: DeviceEventSink>(mut self, sink: E) -> Self {
        self.event_sink = Arc::new(sink);
        self
    }

    /// Borrow the underlying store. Use sparingly: bypasses the
    /// lifecycle invariants this service exists to enforce.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Look up a device by `fingerprint` within `tenant`. If present,
    /// bump `last_seen_at = now` (skipped when the device was seen within
    /// the [sighting granularity](Self::with_sighting_granularity)) and
    /// return its `device_id`. If absent,
    /// create a new row at [`DeviceTrustLevel::Unknown`] using
    /// `new_id_fn()` for the device_id and return it.
    ///
    /// When `user` is `Some`, only a device that user owns (or one with
    /// no owner) is reused. A device owned by someone else is skipped:
    /// the caller's own device with that fingerprint is returned if it
    /// has one, otherwise a new `Unknown` device is created. Two people
    /// behind one office or VPN address with the same browser therefore
    /// never share a device or its trust. When `user` is `None` the
    /// owner cannot be compared, so the fingerprint's device is returned
    /// as is; compare the owner with the authenticating user before
    /// trusting it (see [`decide_step_up_for_user`](crate::authn::service::decide_step_up_for_user)).
    ///
    /// **A fingerprint is not proof of a device.** It is shared by everyone
    /// behind one address with the same headers, and an attacker can match a
    /// victim's. A device found this way must never be taken as one the user
    /// has used: not for a lockout exemption
    /// ([`with_device_store`](crate::authn::service::AuthnServiceBuilder::with_device_store)),
    /// not for skipping a step-up. Bind the session's device with
    /// [`resolve_or_keep`](Self::resolve_or_keep), which finds a device only
    /// by the secret token on its cookie, keeps the device a session already
    /// had as recognised and no more, and is what
    /// [`LifecycleDeviceResolver`](crate::device::LifecycleDeviceResolver)
    /// uses.
    ///
    /// A `Revoked` device is never reused or touched: a request whose
    /// fingerprint matches one gets a new `Unknown` device, so a sighting
    /// cannot extend a revoked row and no user can claim it. That holds for
    /// a device revoked between the lookup and the sighting too: the store
    /// reports the level it found when it applied the sighting, and a
    /// `Revoked` answer sends the request to the create path.
    ///
    /// Two requests that both find no device and both create one end on one
    /// device: the create goes through [`DeviceStore::create_or_find`],
    /// which inserts the new row only while no live device of the same
    /// tenant, fingerprint and owner exists and otherwise returns the one
    /// that does, so both requests return the same id and one row is left.
    ///
    /// `user` is `None` for guest sessions (pre-authn requests). The
    /// `user_id` field on the created Device row is set to whatever
    /// is passed in. A device that exists without an owner (it was made
    /// during a guest request) is claimed by the first authenticated user
    /// that resolves it, through [`DeviceStore::claim_owner`], so it cannot
    /// be reused by a later user; a user who loses that race gets a device
    /// of their own.
    ///
    /// `new_id_fn` is the application's choice of identifier scheme: a
    /// UUID v4 built from an injected [`SecureRng`](axess_rng::SecureRng)
    /// (a seeded one under test) is the canonical shape. Only called on
    /// the create path.
    pub fn ensure_device(
        &self,
        tenant: &TenantId,
        user: Option<&UserId>,
        fingerprint: FingerprintHash,
        now: Timestamp,
        new_id_fn: impl FnOnce() -> DeviceId + Send,
    ) -> impl Future<Output = Result<DeviceId, S::Error>> + Send {
        let tenant = *tenant;
        let user = user.cloned();
        async move {
            // An identified user first looks for a device they own with this
            // fingerprint. That lookup is the cheap one (a store indexes it
            // per user), and it is the request path of everyone who has
            // signed in before, so it runs before the lookup that must weigh
            // every device sharing the fingerprint. It also finds the user's
            // device when the newest device with the fingerprint is
            // someone else's, or is a store's not-yet-indexed twin (a Valkey
            // row last written by 0.11.0, whose index named a deleted twin).
            if let Some(user) = user.as_ref() {
                let own = self
                    .store
                    .find_by_fingerprint_for_user(&tenant, user, &fingerprint)
                    .await?;
                if let Some(own) = own
                    && is_usable_by(&own, Some(user))
                    && self.note_sighting(&tenant, &own, now).await? != DeviceTrustLevel::Revoked
                {
                    return Ok(own.id);
                }
            }

            // Device already known by this fingerprint. One owned by a
            // different user is not reused: a shared office, NAT or VPN gives
            // two people the same fingerprint, and the second must not
            // inherit the first one's trust.
            let existing = self
                .store
                .find_by_fingerprint(&tenant, &fingerprint)
                .await?;
            if let Some(existing) = existing
                && is_usable_by(&existing, user.as_ref())
            {
                // An unowned device (made during a guest request) is
                // claimed by the first authenticated user to reach it,
                // as one conditional write; otherwise any later user
                // could resolve it. A user who loses the race to
                // another falls through and gets a device of their own.
                let usable = match (existing.user_id.as_ref(), user.as_ref()) {
                    (None, Some(user)) => matches!(
                        self.store
                            .claim_owner(&tenant, &existing.id, user, now)
                            .await?,
                        OwnerClaim::Claimed
                    ),
                    _ => true,
                };
                if usable
                    && self.note_sighting(&tenant, &existing, now).await?
                        != DeviceTrustLevel::Revoked
                {
                    return Ok(existing.id);
                }
            }

            // Create path: brand-new device at Unknown.
            let id = new_id_fn();
            let device = Device {
                id,
                tenant_id: tenant,
                user_id: user,
                trust_level: DeviceTrustLevel::Unknown,
                fingerprint_hash: fingerprint,
                first_seen_at: now,
                last_seen_at: now,
                revoked_at: None,
                demoted_at: None,
                bindings: Vec::new(),
            };
            // The lookups above and the create are separate store calls, so
            // a concurrent first sighting of the same fingerprint may have
            // created a device meanwhile. The store inserts this one only
            // while no live device of the same tenant, fingerprint and
            // owner exists, and otherwise hands back the one that does; it
            // was created moments ago, so no sighting of it is due.
            let created = self.store.create_or_find(&device, now).await?;
            if created.id != id {
                return Ok(created.id);
            }

            // Emit `DeviceFirstSeen` after the row commit so a
            // sink failure can never fail the device creation. The
            // sink's own failure handling logs and swallows, so the
            // outer caller never observes audit-pipeline blips.
            let event = AuthEventBuilder::success(AuthEventType::DeviceFirstSeen)
                .maybe_attributed_to(user.as_ref(), Some(&tenant))
                .with_device(id)
                .build_at(now);
            self.event_sink.emit(event).await;

            Ok(id)
        }
    }

    /// Record a sighting of `device` unless it was seen within the
    /// sighting granularity of `now`.
    ///
    /// Returns the trust level the device is known to be at after the call:
    /// the level the store found when it applied the sighting, or the loaded
    /// level when no sighting was due. A `Revoked` answer means the device
    /// was revoked after the caller loaded it, and the caller must not serve
    /// it.
    async fn note_sighting(
        &self,
        tenant: &TenantId,
        device: &Device,
        now: Timestamp,
    ) -> Result<DeviceTrustLevel, S::Error> {
        // A request that is older than the last recorded sighting (an
        // out-of-order arrival, or a node whose clock lags) records nothing.
        // Past the first test the request is later than the sighting, so
        // the size of the span between them is the span.
        if now <= device.last_seen_at
            || now.since(device.last_seen_at).unsigned_abs() < self.sighting_granularity
        {
            return Ok(device.trust_level);
        }
        self.store.record_sighting(tenant, &device.id, now).await
    }

    /// Promote a device's trust level after a successful
    /// authentication ceremony.
    ///
    /// State machine:
    ///
    /// | Current | After `promote_on_authn` |
    /// |---------|--------------------------|
    /// | `Unknown` | `Seen` (recorded with `record_sighting(now)`) |
    /// | `Seen` | `Seen` (no-op; `last_seen_at` bumped) |
    /// | `Trusted` | `Trusted` (no-op; `last_seen_at` bumped) |
    /// | `Revoked` | `Revoked` (no-op; `last_seen_at` **not** bumped) |
    ///
    /// A `Seen` or `Trusted` device that is revoked between the load and the
    /// sighting is reported as `Revoked`, with `last_seen_at` unchanged.
    ///
    /// **Never re-elevates a `Revoked` device.** Revocation is a
    /// terminal state until an admin / user explicitly resurrects the
    /// device via [`DeviceStore::set_trust_level`]; passing through
    /// `promote_on_authn` after a successful login on a revoked
    /// device must not silently undo the revocation. (The application
    /// should reject the login earlier in such cases; this is
    /// defence-in-depth.)
    ///
    /// **Never demotes a `Trusted` device.** A Trusted device that
    /// authenticates again stays Trusted. This is the standard "user
    /// elevated device once via explicit consent; subsequent logins
    /// don't downgrade trust" semantic.
    ///
    /// Returns the trust level the device is in after the call.
    /// `Ok(Some(DeviceTrustLevel::Revoked))` is the "not promoted because
    /// revoked" outcome, whether the device was already revoked when it was
    /// loaded or was revoked between the load and the promotion; the
    /// promotion is a conditional write ([`DeviceStore::set_trust_level_if`])
    /// so the revocation is never overwritten. `Ok(None)` if the device no
    /// longer exists, or is another user's.
    ///
    /// **Takes a [`UserDevice`], not an id.** Trust is written only onto a
    /// device the request proved it holds, for the user the session is
    /// authenticated as (see
    /// [`AuthSession::user_device`](crate::session::extractor::AuthSession::user_device)),
    /// so a row found by fingerprint ([`Self::ensure_device`]) or a device a
    /// session only kept cannot be promoted: neither yields a
    /// [`ProvenDevice`]. A login on a device the request did not prove
    /// promotes nothing.
    ///
    /// **Writes nothing to another user's device.** The request that
    /// completes a login proved its device before anyone was signed in, so
    /// on a browser profile two accounts share it may be the other
    /// account's. A row owned by another user is left as it was and the
    /// answer is `Ok(None)`; a row with no owner is first claimed for the
    /// user by one conditional write ([`DeviceStore::claim_owner`]).
    pub fn promote_on_authn(
        &self,
        device: &UserDevice,
        now: Timestamp,
    ) -> impl Future<Output = Result<Option<DeviceTrustLevel>, S::Error>> + Send {
        let (tenant, user, device_id) = (device.tenant(), device.user(), device.device().id());
        async move {
            let device = match self.store.load(&tenant, &device_id).await? {
                Some(d) => d,
                None => return Ok(None),
            };
            if !self.is_users(&tenant, &device, &user, now).await? {
                return Ok(None);
            }

            match device.trust_level {
                DeviceTrustLevel::Unknown => {
                    // One conditional write: the device becomes Seen only
                    // if it is still Unknown, so a revocation that landed
                    // after the load above is not overwritten.
                    match self
                        .store
                        .set_trust_level_if(
                            &tenant,
                            &device_id,
                            DeviceTrustLevel::Unknown,
                            DeviceTrustLevel::Seen,
                            now,
                        )
                        .await?
                    {
                        TrustTransition::Applied => {
                            // The level the sighting found, so a revocation
                            // that landed after the promotion is reported.
                            let level =
                                self.store.record_sighting(&tenant, &device_id, now).await?;
                            Ok(Some(level))
                        }
                        // Revoked in between: not promoted, and reported as
                        // Revoked, never as Seen.
                        TrustTransition::Refused {
                            current: DeviceTrustLevel::Revoked,
                        } => Ok(Some(DeviceTrustLevel::Revoked)),
                        // Another request promoted it first.
                        TrustTransition::Refused { .. } => {
                            let level =
                                self.store.record_sighting(&tenant, &device_id, now).await?;
                            Ok(Some(level))
                        }
                        TrustTransition::Missing => Ok(None),
                    }
                }
                DeviceTrustLevel::Seen | DeviceTrustLevel::Trusted => {
                    // The sighting reports the level the row has when it is
                    // applied; a device revoked since the load above is
                    // reported as `Revoked` and its `last_seen_at` is left
                    // alone.
                    let level = self.store.record_sighting(&tenant, &device_id, now).await?;
                    Ok(Some(level))
                }
                DeviceTrustLevel::Revoked => {
                    // Terminal; no last_seen bump, no trust change.
                    Ok(Some(DeviceTrustLevel::Revoked))
                }
            }
        }
    }

    /// Convenience composition for the AuthnService glue pattern:
    /// fire [`Self::promote_on_authn`] iff the [`FactorOutcome`]
    /// indicates the user just completed authentication. No-op on
    /// `FactorRequired` / `InvalidCredential` / `Locked`.
    ///
    /// Usage:
    ///
    /// ```text
    /// let outcome = authn.verify_factor(...).await?;
    /// if let Some(device) = session.user_device().await {
    ///     device_lifecycle
    ///         .promote_if_authenticated(&outcome, &device, now)
    ///         .await?;
    /// }
    /// ```
    ///
    /// Returns the same `Option<DeviceTrustLevel>` as
    /// [`Self::promote_on_authn`] when the outcome was
    /// `Authenticated`; `Ok(None)` otherwise (including the absent-
    /// device case, mirroring `promote_on_authn` semantics).
    pub fn promote_if_authenticated(
        &self,
        outcome: &FactorOutcome,
        device: &UserDevice,
        now: Timestamp,
    ) -> impl Future<Output = Result<Option<DeviceTrustLevel>, S::Error>> + Send {
        let is_authenticated = matches!(outcome, FactorOutcome::Authenticated);
        let device = *device;
        async move {
            if is_authenticated {
                self.promote_on_authn(&device, now).await
            } else {
                Ok(None)
            }
        }
    }

    /// Whether a trust write for `user` may touch `row`: the row is owned by
    /// `user`, or has no owner and is claimed for `user` by the store's
    /// conditional write. A row another user owns is not, and nothing is
    /// written to it. A revoked row with no owner is passed on unclaimed:
    /// nothing is written to a revoked row, and the caller reports it.
    async fn is_users(
        &self,
        tenant: &TenantId,
        row: &Device,
        user: &UserId,
        now: Timestamp,
    ) -> Result<bool, S::Error> {
        match row.user_id.as_ref() {
            Some(owner) if owner == user => Ok(true),
            Some(_) => {
                tracing::warn!(
                    device_id = %row.id,
                    "a trust write named a device another user owns; nothing was written"
                );
                Ok(false)
            }
            None if row.trust_level == DeviceTrustLevel::Revoked => Ok(true),
            None => Ok(matches!(
                self.store.claim_owner(tenant, &row.id, user, now).await?,
                OwnerClaim::Claimed
            )),
        }
    }

    /// Mark a device [`Trusted`](DeviceTrustLevel::Trusted): the write
    /// behind "trust this device".
    ///
    /// Like [`promote_on_authn`](Self::promote_on_authn) it takes a
    /// [`UserDevice`], so the device that becomes trusted is the one the
    /// request proved it holds and never a row that merely shares its
    /// fingerprint, and it writes nothing to a device another user owns
    /// (`Ok(None)`). Call it after whatever the application asks of the user
    /// first (a step-up, a confirmation).
    ///
    /// An `Unknown` or `Seen` device becomes `Trusted` by one conditional
    /// write ([`DeviceStore::set_trust_level_if`]) and a
    /// [`DeviceTrustGranted`](AuthEventType::DeviceTrustGranted) row is
    /// written. A `Trusted` device stays as it is. A `Revoked` device is
    /// never trusted, including one revoked between the load and the write.
    /// Returns the level the device is at after the call, `None` when it no
    /// longer exists.
    pub fn grant_trust(
        &self,
        device: &UserDevice,
        now: Timestamp,
    ) -> impl Future<Output = Result<Option<DeviceTrustLevel>, S::Error>> + Send {
        let (tenant, user, device_id) = (device.tenant(), device.user(), device.device().id());
        async move {
            let Some(row) = self.store.load_fresh(&tenant, &device_id).await? else {
                return Ok(None);
            };
            if !self.is_users(&tenant, &row, &user, now).await? {
                return Ok(None);
            }
            let from = match row.trust_level {
                DeviceTrustLevel::Trusted => return Ok(Some(DeviceTrustLevel::Trusted)),
                DeviceTrustLevel::Revoked => return Ok(Some(DeviceTrustLevel::Revoked)),
                level @ (DeviceTrustLevel::Unknown | DeviceTrustLevel::Seen) => level,
            };
            match self
                .store
                .set_trust_level_if(&tenant, &device_id, from, DeviceTrustLevel::Trusted, now)
                .await?
            {
                TrustTransition::Applied => {
                    // The grant is `user`'s: `is_users` let the write through
                    // because the row is theirs or has just been claimed for
                    // them, and `row` is the snapshot from before that claim,
                    // whose owner of an unowned device is still none.
                    let event = AuthEventBuilder::success(AuthEventType::DeviceTrustGranted)
                        .attributed_to(&user, &tenant)
                        .with_device(device_id)
                        .build_at(now);
                    self.event_sink.emit(event).await;
                    Ok(Some(DeviceTrustLevel::Trusted))
                }
                // The row moved under the write: report where it is now and
                // change nothing. A revocation that won stays a revocation.
                TrustTransition::Refused { current } => Ok(Some(current)),
                TrustTransition::Missing => Ok(None),
            }
        }
    }

    // ── WebAuthn binding ────────────────────────────────────────────

    /// Record a `DeviceBinding::WebAuthn` on a device after a successful
    /// FIDO2 registration ceremony.
    ///
    /// If the device already carries a `WebAuthn` binding for the same
    /// `credential_id`, this is a no-op (idempotent). Otherwise the new
    /// binding is appended and a [`AuthEventType::DeviceBindingAdded`]
    /// audit event is emitted.
    ///
    /// Returns `Ok(true)` when a new binding was added and `Ok(false)` when
    /// nothing was added: the credential was already bound, the device does
    /// not exist, or the device is `Revoked` (a revoked device never gains a
    /// binding, including when it was revoked while this call ran).
    #[cfg(feature = "fido2")]
    pub fn bind_webauthn_credential(
        &self,
        tenant: &TenantId,
        device_id: &DeviceId,
        credential_id: String,
        attestation_class: crate::device::types::AttestationClass,
        now: Timestamp,
    ) -> impl Future<Output = Result<bool, S::Error>> + Send {
        let tenant = *tenant;
        let device_id = *device_id;
        let event_sink = self.event_sink.clone();
        async move {
            let mut attempts = 0;
            let device = loop {
                let mut device = match self.store.load(&tenant, &device_id).await? {
                    Some(d) => d,
                    None => return Ok(false),
                };

                // A revoked device gains no bindings.
                if device.trust_level == DeviceTrustLevel::Revoked {
                    return Ok(false);
                }

                // Dedup: don't add a second binding for the same credential.
                let already_bound = device.bindings.iter().any(|b| {
                    matches!(
                        b,
                        crate::device::types::DeviceBinding::WebAuthn {
                            credential_id: cid, ..
                        } if cid == &credential_id
                    )
                });
                if already_bound {
                    return Ok(false);
                }

                let before = device.bindings.clone();
                device
                    .bindings
                    .push(crate::device::types::DeviceBinding::WebAuthn {
                        credential_id: credential_id.clone(),
                        attestation_class,
                        bound_at: now,
                        last_used_at: now,
                    });
                // Bindings-only compare-and-swap that refuses a revoked row:
                // a revocation made since the load is neither undone nor
                // given a new binding, and a concurrent bindings edit makes
                // this conflict, so the row is re-read and the change
                // decided again instead of one edit overwriting the other.
                match self
                    .store
                    .replace_bindings(&tenant, &device_id, &before, &device.bindings, now)
                    .await?
                {
                    BindingsUpdate::Written => break device,
                    BindingsUpdate::Conflict if attempts < BINDINGS_RETRIES => attempts += 1,
                    BindingsUpdate::Conflict => {
                        tracing::warn!(
                            "device bindings kept changing under concurrent writers; \
                             WebAuthn binding not recorded"
                        );
                        return Ok(false);
                    }
                    BindingsUpdate::Revoked | BindingsUpdate::Missing => return Ok(false),
                }
            };

            // Emit `DeviceBindingAdded` after the write so the
            // binding is persisted even if the sink fails.
            let event = AuthEventBuilder::success(AuthEventType::DeviceBindingAdded)
                .maybe_attributed_to(device.user_id.as_ref(), Some(&tenant))
                .with_device(device_id)
                .build_at(now);
            event_sink.emit(event).await;

            Ok(true)
        }
    }

    /// Update the `last_used_at` timestamp on an existing
    /// `DeviceBinding::WebAuthn` after a successful FIDO2 assertion.
    ///
    /// No-op if the device doesn't exist, is `Revoked`, or has no `WebAuthn`
    /// binding matching `credential_id`. A concurrent bindings edit makes the
    /// write conflict; the row is then re-read and the update applied to what
    /// is stored now.
    #[cfg(feature = "fido2")]
    pub fn record_webauthn_usage(
        &self,
        tenant: &TenantId,
        device_id: &DeviceId,
        credential_id: &str,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), S::Error>> + Send {
        let tenant = *tenant;
        let device_id = *device_id;
        let credential_id = credential_id.to_owned();
        async move {
            for _ in 0..=BINDINGS_RETRIES {
                let device = match self.store.load(&tenant, &device_id).await? {
                    Some(d) => d,
                    None => return Ok(()),
                };

                let mut bindings = device.bindings.clone();
                let mut touched = false;
                for binding in &mut bindings {
                    if let crate::device::types::DeviceBinding::WebAuthn {
                        credential_id: cid,
                        last_used_at,
                        ..
                    } = binding
                        && cid == &credential_id
                    {
                        *last_used_at = now;
                        touched = true;
                        break;
                    }
                }
                if !touched {
                    return Ok(());
                }
                // Bindings-only; a revoked device is left as it is.
                match self
                    .store
                    .replace_bindings(&tenant, &device_id, &device.bindings, &bindings, now)
                    .await?
                {
                    BindingsUpdate::Conflict => continue,
                    _ => return Ok(()),
                }
            }
            tracing::warn!(
                "device bindings kept changing under concurrent writers; \
                 WebAuthn last-used time not recorded"
            );
            Ok(())
        }
    }
}

mod proof;
pub use proof::{DeviceRequest, ResolvedDevice, ResolvedOrKept};

#[cfg(test)]
mod tests;
