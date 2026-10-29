//! Resolving a request to a device by proof, not by fingerprint.
//!
//! See [`proof`](crate::device::proof) for the token. The fingerprint plays no
//! part in finding the device here: it is stored on a new row and nothing
//! else.

use super::*;
use crate::device::proof::{DeviceToken, PresentedDevice};
use axess_rng::SecureRng;

/// What a request is, and what it offers to be recognised by.
#[derive(Debug, Clone, Copy)]
pub struct DeviceRequest<'a> {
    /// The tenant the request is for.
    pub tenant: &'a TenantId,
    /// The user the session has authenticated, `None` for a guest or a login
    /// still in flight.
    pub user: Option<&'a UserId>,
    /// The keyed fingerprint of the request. Stored on a new device; it never
    /// selects an existing one.
    pub fingerprint: FingerprintHash,
    /// The device and token the request's cookie presents, unverified.
    pub presented: Option<&'a PresentedDevice>,
    /// The device an authenticated session was last bound to. Kept when the
    /// request presents no token (a cross-site navigation does not send the
    /// strict device cookie), so such a visit does not mint another device.
    pub session_device: Option<&'a DeviceId>,
}

/// The device a request resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDevice {
    /// The device.
    pub id: DeviceId,
    /// A token minted for it by this request. `Some` exactly when the device
    /// was just created: the cookie that carries it must reach the browser.
    pub issued: Option<DeviceToken>,
}

impl<S> DeviceLifecycleService<S>
where
    S: DeviceStore,
{
    /// Resolve a request to its device by the token it presents.
    ///
    /// - A request whose cookie names a device of `tenant` and presents the
    ///   token on its row is that device: it is returned, and an
    ///   authenticated `user` is recorded as a sighting (and claims the device
    ///   if it has no owner). A request with no `user` reads and writes
    ///   nothing, so the device can be judged for step-up before sign-in.
    /// - Otherwise a request with no `user` has no device.
    /// - Otherwise the device the session was last bound to is kept when it
    ///   exists, is not revoked and belongs to `user`.
    /// - Otherwise a new `Unknown` device owned by `user` is created, with a
    ///   fresh token whose digest is on the row and whose value is returned in
    ///   [`ResolvedDevice::issued`] for the cookie.
    ///
    /// A device that matches the fingerprint but cannot prove itself is never
    /// returned, whoever it belongs to. A `Revoked` device is never
    /// returned either.
    pub fn resolve_proven(
        &self,
        request: DeviceRequest<'_>,
        now: DateTime<Utc>,
        rng: &dyn SecureRng,
        new_id_fn: impl FnOnce() -> DeviceId + Send,
    ) -> impl Future<Output = Result<Option<ResolvedDevice>, S::Error>> + Send {
        let tenant = *request.tenant;
        let user = request.user.cloned();
        let fingerprint = request.fingerprint;
        let presented = request.presented.cloned();
        let session_device = request.session_device.copied();
        async move {
            if let Some(presented) = presented.as_ref()
                && let Some(device) = self.store.load(&tenant, &presented.id).await?
                && device.trust_level != DeviceTrustLevel::Revoked
                && presented.token.is_listed_in(&device.bindings)
                && is_usable_by(&device, user.as_ref())
            {
                let Some(user) = user.as_ref() else {
                    return Ok(Some(ResolvedDevice {
                        id: device.id,
                        issued: None,
                    }));
                };
                if device.user_id.is_none()
                    && !matches!(
                        self.store
                            .claim_owner(&tenant, &device.id, user, now)
                            .await?,
                        OwnerClaim::Claimed
                    )
                {
                    // Another user claimed it first: it is theirs now.
                } else {
                    self.note_sighting(&tenant, &device, now).await?;
                    return Ok(Some(ResolvedDevice {
                        id: device.id,
                        issued: None,
                    }));
                }
            }
            let Some(user) = user else {
                return Ok(None);
            };

            if let Some(id) = session_device
                && let Some(device) = self.store.load(&tenant, &id).await?
                && device.trust_level != DeviceTrustLevel::Revoked
                && device.user_id.as_ref() == Some(&user)
            {
                self.note_sighting(&tenant, &device, now).await?;
                return Ok(Some(ResolvedDevice {
                    id: device.id,
                    issued: None,
                }));
            }

            let token = DeviceToken::mint(rng);
            let id = new_id_fn();
            let device = Device {
                id,
                tenant_id: tenant,
                user_id: Some(user),
                trust_level: DeviceTrustLevel::Unknown,
                fingerprint_hash: fingerprint,
                first_seen_at: now,
                last_seen_at: now,
                revoked_at: None,
                demoted_at: None,
                bindings: vec![token.binding(now)],
            };
            self.store.save(&device, now).await?;
            let event = AuthEventBuilder::success(AuthEventType::DeviceFirstSeen)
                .maybe_attributed_to(device.user_id.as_ref(), Some(&tenant))
                .with_device(id)
                .build_at(now);
            self.event_sink.emit(event).await;
            Ok(Some(ResolvedDevice {
                id,
                issued: Some(token),
            }))
        }
    }
}
