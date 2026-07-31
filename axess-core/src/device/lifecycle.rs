//! [`DeviceLifecycleService`]: opinionated higher-level helper that
//! composes [`DeviceStore`] primitives into the two operations every
//! axess consumer needs at request/authn boundaries:
//!
//! 1. **Ensure-or-create**: given a fingerprint, look up the existing
//!    `Device` row or create a fresh one with
//!    [`DeviceTrustLevel::Unknown`]. Idempotent on the existing-device
//!    path; bumps `last_seen_at` either way.
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
//!   application concern that varies by deployment. axess will
//!   eventually ship a default extractor (separate iteration); the
//!   lifecycle layer is fingerprint-agnostic.
//! - **Wire itself into middleware.** The decision of *where* in the
//!   request pipeline `ensure_device` runs (session middleware,
//!   authn service, application-specific layer) is left to the
//!   consumer. This keeps the helper testable in isolation and lets
//!   apps make the cost trade-offs.
//! - **Refresh-cascade revocation.** When a refresh-token family is
//!   revoked, every `Device` bound to that family must transition to
//!   `Revoked`. That requires `DeviceBinding` to track refresh-family
//!   identifiers, which it does not yet. Tracked separately.

use chrono::{DateTime, Utc};
use std::future::Future;
use std::sync::Arc;

use crate::authn::event::{AuthEventBuilder, AuthEventType};
use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::authn::service::FactorOutcome;
use crate::device::events::{DeviceEventSink, NoopDeviceEventSink};
use crate::device::store::DeviceStore;
use crate::device::types::{Device, DeviceTrustLevel, FingerprintHash};

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
        }
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
    /// bump `last_seen_at = now` and return its `device_id`. If absent,
    /// create a new row at [`DeviceTrustLevel::Unknown`] using
    /// `new_id_fn()` for the device_id and return it.
    ///
    /// `user` is `None` for guest sessions (pre-authn requests). The
    /// `user_id` field on the created Device row is set to whatever
    /// is passed in; updates that arrive later (e.g. when authn
    /// completes for a previously-guest device) need to call
    /// [`DeviceStore::save`] directly via [`Self::store`]; this
    /// helper deliberately doesn't touch user_id on the existing-
    /// device path to keep the create-vs-find branches symmetric.
    ///
    /// `new_id_fn` is the application's choice of identifier scheme.
    /// Pass `|| DeviceId::try_new(Uuid::new_v4().to_string()).unwrap()`
    /// for the canonical UUID-v4 shape, or a deterministic generator
    /// driven by [`MockRng`](axess_rng::testing::MockRng) for tests.
    /// Only called on the create path.
    pub fn ensure_device(
        &self,
        tenant: &TenantId,
        user: Option<&UserId>,
        fingerprint: FingerprintHash,
        now: DateTime<Utc>,
        new_id_fn: impl FnOnce() -> DeviceId + Send,
    ) -> impl Future<Output = Result<DeviceId, S::Error>> + Send {
        let tenant = *tenant;
        let user = user.cloned();
        async move {
            // Fast path: device already known by this fingerprint.
            if let Some(existing) = self
                .store
                .find_by_fingerprint(&tenant, &fingerprint)
                .await?
            {
                self.store
                    .record_sighting(&tenant, &existing.id, now)
                    .await?;
                return Ok(existing.id);
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
                bindings: Vec::new(),
            };
            self.store.save(&device).await?;

            // Emit `DeviceFirstSeen` after the row commit so a
            // sink failure can never fail the device creation. The
            // sink's own failure handling logs and swallows, so the
            // outer caller never observes audit-pipeline blips.
            let event = AuthEventBuilder::success(AuthEventType::DeviceFirstSeen)
                .maybe_attributed_to(user.as_ref(), Some(&tenant))
                .with_device(id)
                .build();
            self.event_sink.emit(event).await;

            Ok(id)
        }
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
    /// `Ok(None)` if the `device_id` doesn't resolve: defensive,
    /// callers shouldn't see this if they pass an id from
    /// [`Self::ensure_device`].
    pub fn promote_on_authn(
        &self,
        tenant: &TenantId,
        device_id: &DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<DeviceTrustLevel>, S::Error>> + Send {
        let tenant = *tenant;
        let device_id = *device_id;
        async move {
            let device = match self.store.load(&tenant, &device_id).await? {
                Some(d) => d,
                None => return Ok(None),
            };

            match device.trust_level {
                DeviceTrustLevel::Unknown => {
                    self.store
                        .set_trust_level(&tenant, &device_id, DeviceTrustLevel::Seen, now)
                        .await?;
                    self.store.record_sighting(&tenant, &device_id, now).await?;
                    Ok(Some(DeviceTrustLevel::Seen))
                }
                DeviceTrustLevel::Seen | DeviceTrustLevel::Trusted => {
                    self.store.record_sighting(&tenant, &device_id, now).await?;
                    Ok(Some(device.trust_level))
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
    /// let outcome = authn.complete_factor_step(...).await?;
    /// let _ = device_lifecycle
    ///     .promote_if_authenticated(&outcome, &tenant, &device_id, now)
    ///     .await?;
    /// ```
    ///
    /// Returns the same `Option<DeviceTrustLevel>` as
    /// [`Self::promote_on_authn`] when the outcome was
    /// `Authenticated`; `Ok(None)` otherwise (including the absent-
    /// device-id case, mirroring `promote_on_authn` semantics).
    pub fn promote_if_authenticated(
        &self,
        outcome: &FactorOutcome,
        tenant: &TenantId,
        device_id: &DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<DeviceTrustLevel>, S::Error>> + Send {
        let is_authenticated = matches!(outcome, FactorOutcome::Authenticated);
        let tenant = *tenant;
        let device_id = *device_id;
        async move {
            if is_authenticated {
                self.promote_on_authn(&tenant, &device_id, now).await
            } else {
                Ok(None)
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
    /// Returns `Ok(true)` when a new binding was added, `Ok(false)` when
    /// deduplicated, `Ok(None)`-shaped `Err` when the device doesn't exist.
    #[cfg(feature = "fido2")]
    pub fn bind_webauthn_credential(
        &self,
        tenant: &TenantId,
        device_id: &DeviceId,
        credential_id: String,
        attestation_class: crate::device::types::AttestationClass,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<bool, S::Error>> + Send {
        let tenant = *tenant;
        let device_id = *device_id;
        let event_sink = self.event_sink.clone();
        async move {
            let mut device = match self.store.load(&tenant, &device_id).await? {
                Some(d) => d,
                None => return Ok(false),
            };

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

            device
                .bindings
                .push(crate::device::types::DeviceBinding::WebAuthn {
                    credential_id: credential_id.clone(),
                    attestation_class,
                    bound_at: now,
                    last_used_at: now,
                });
            self.store.save(&device).await?;

            // Emit `DeviceBindingAdded` after the save so the
            // binding is persisted even if the sink fails.
            let event = AuthEventBuilder::success(AuthEventType::DeviceBindingAdded)
                .maybe_attributed_to(device.user_id.as_ref(), Some(&tenant))
                .with_device(device_id)
                .build();
            event_sink.emit(event).await;

            Ok(true)
        }
    }

    /// Update the `last_used_at` timestamp on an existing
    /// `DeviceBinding::WebAuthn` after a successful FIDO2 assertion.
    ///
    /// No-op if the device doesn't exist or has no `WebAuthn` binding
    /// matching `credential_id`.
    #[cfg(feature = "fido2")]
    pub fn record_webauthn_usage(
        &self,
        tenant: &TenantId,
        device_id: &DeviceId,
        credential_id: &str,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), S::Error>> + Send {
        let tenant = *tenant;
        let device_id = *device_id;
        let credential_id = credential_id.to_owned();
        async move {
            let mut device = match self.store.load(&tenant, &device_id).await? {
                Some(d) => d,
                None => return Ok(()),
            };

            let mut touched = false;
            for binding in &mut device.bindings {
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

            if touched {
                self.store.save(&device).await?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
