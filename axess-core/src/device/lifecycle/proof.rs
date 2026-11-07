//! Resolving a request to a device by proof, not by fingerprint.
//!
//! See [`proof`](crate::device::proof) for the token. The fingerprint plays no
//! part in finding the device here: it is stored on a new row and nothing
//! else.

use super::*;
use crate::device::proof::{DeviceToken, PresentedDevice, ProvenDevice};
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
    /// The proof, kept out of reach of a struct literal.
    pub(crate) proof: ProvenDevice,
}

impl ResolvedDevice {
    /// The device as one the client proved. Hand it to the session layer from
    /// a [`DeviceResolver`](crate::device::DeviceResolver) as
    /// [`BoundDevice::Proven`](crate::device::BoundDevice::Proven); an API
    /// that exempts a device from a lockout accepts nothing else.
    pub fn proven(&self) -> ProvenDevice {
        self.proof
    }
}

impl<S> DeviceLifecycleService<S>
where
    S: DeviceStore,
{
    /// Delete the least recently seen `Unknown` devices of `user` so that,
    /// with one more written, they hold at most `max`. Looks at the user's
    /// most recently seen devices only (a window of four times `max` and a
    /// hundred more), which holds every `Unknown` device of a user who is
    /// not hoarding `Seen` ones; the sweep reaps what lies beyond it.
    async fn make_room_for_unknown(
        &self,
        tenant: &TenantId,
        user: &UserId,
        max: usize,
    ) -> Result<(), S::Error> {
        let window = max.saturating_mul(4).saturating_add(100);
        let rows = self.store.find_for_user(tenant, user, window).await?;
        let unknown: Vec<&Device> = rows
            .iter()
            .filter(|d| d.trust_level == DeviceTrustLevel::Unknown)
            .collect();
        let surplus = (unknown.len() + 1).saturating_sub(max);
        if surplus == 0 {
            return Ok(());
        }
        // Newest-sighted first: the oldest are at the end.
        for device in unknown.iter().rev().take(surplus) {
            self.store.delete(tenant, &device.id).await?;
        }
        Ok(())
    }

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
    /// - Otherwise a new `Unknown` device owned by `user` is created, after the
    ///   user's least recently seen `Unknown` devices beyond
    ///   [`DEFAULT_MAX_UNKNOWN_DEVICES_PER_USER`]
    ///   (or the service's own bound) are deleted, with a
    ///   fresh token whose digest is on the row and whose value is returned in
    ///   [`ResolvedDevice::issued`] for the cookie.
    ///
    /// A device that matches the fingerprint but cannot prove itself is never
    /// returned, whoever it belongs to. A `Revoked` device is never
    /// returned either, including one revoked between the load and the
    /// sighting: the store reports the level it found when it applied the
    /// sighting, and a `Revoked` answer sends the request on to a new device.
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
        let max_unknown = self.max_unknown_per_user;
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
                        proof: ProvenDevice::new(device.id),
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
                } else if self.note_sighting(&tenant, &device, now).await?
                    != DeviceTrustLevel::Revoked
                {
                    return Ok(Some(ResolvedDevice {
                        id: device.id,
                        issued: None,
                        proof: ProvenDevice::new(device.id),
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
                && self.note_sighting(&tenant, &device, now).await? != DeviceTrustLevel::Revoked
            {
                return Ok(Some(ResolvedDevice {
                    id: device.id,
                    issued: None,
                    proof: ProvenDevice::new(device.id),
                }));
            }

            self.make_room_for_unknown(&tenant, &user, max_unknown)
                .await?;
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
                proof: ProvenDevice::new(id),
            }))
        }
    }
}
