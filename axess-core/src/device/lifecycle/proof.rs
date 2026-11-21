//! Resolving a request to a device by proof, not by fingerprint.
//!
//! See [`proof`](crate::device::proof) for the token. The fingerprint plays no
//! part in finding the device here: it is stored on a new row and nothing
//! else, and a request without one is given no new row.

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
    /// The keyed fingerprint of the request, `None` when it could not be
    /// computed (the default extractor needs a `User-Agent`). Stored on a new
    /// device, so a request without one is given no new device; it never
    /// selects an existing one.
    pub fingerprint: Option<FingerprintHash>,
    /// The devices and tokens the request's cookie presents, newest first,
    /// unverified: one entry per device of the browser profile, so a
    /// profile that several accounts sign in on presents one per account.
    pub presented: &'a [PresentedDevice],
    /// The device an authenticated session was last bound to. Kept when the
    /// request presents no token (a cross-site navigation does not send the
    /// strict device cookie), so such a visit does not mint another device.
    /// A device kept this way is recognised, not proven: see
    /// [`ResolvedOrKept::Kept`].
    pub session_device: Option<&'a DeviceId>,
    /// Whether device keys are enforced for the request and what it proved,
    /// read from the request itself
    /// ([`KeyEnforcement::of`](crate::device_key::KeyEnforcement::of)).
    /// Under enforcement a device that has a key is proven only by it.
    pub keys: crate::device_key::KeyEnforcement<'a>,
}

/// The device a request proved: it presented the device's token, or the
/// device was created for it by this request.
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

/// What [`resolve_or_keep`](DeviceLifecycleService::resolve_or_keep) found
/// for a request: a device the request proved, or the device its session was
/// already bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedOrKept {
    /// The request proved this device: it presented the device's token, or
    /// the device was created for it now and its token is in
    /// [`ResolvedDevice::issued`].
    Proven(ResolvedDevice),
    /// The request presented no token, and its authenticated session was
    /// already bound to this device, which exists, is not revoked and
    /// belongs to the session's user. The session keeps it, so a visit that
    /// arrives without the device cookie does not create another device, but
    /// nothing on this request proves it: what stands behind it is the
    /// session cookie. It is recognised, as
    /// [`BoundDevice::Unproven`](crate::device::BoundDevice::Unproven), and
    /// no lockout exemption reads it.
    Kept(DeviceId),
}

impl ResolvedOrKept {
    /// The device's id, proven or kept.
    pub fn id(&self) -> DeviceId {
        match self {
            Self::Proven(resolved) => resolved.id,
            Self::Kept(id) => *id,
        }
    }

    /// The device as a [`DeviceResolver`](crate::device::DeviceResolver)
    /// hands it to the session layer:
    /// [`Proven`](crate::device::BoundDevice::Proven) for a device the
    /// request proved, [`Unproven`](crate::device::BoundDevice::Unproven)
    /// for one the session kept.
    pub fn bound(&self) -> crate::device::BoundDevice {
        match self {
            Self::Proven(resolved) => crate::device::BoundDevice::Proven(resolved.proven()),
            Self::Kept(id) => crate::device::BoundDevice::Unproven(*id),
        }
    }

    /// The token this request was issued, when it created the device.
    pub fn issued(&self) -> Option<&DeviceToken> {
        match self {
            Self::Proven(resolved) => resolved.issued.as_ref(),
            Self::Kept(_) => None,
        }
    }
}

/// How a request that presented `device`'s token proved the device, `None`
/// when it did not: the device has a key, keys are enforced, and the request
/// did not prove that key.
fn proof_of(
    device: &Device,
    keys: Option<&crate::device_key::KeyCheck>,
) -> Option<crate::device_key::DeviceProof> {
    use crate::device_key::DeviceProof;
    let key = device.bindings.iter().find_map(|binding| match binding {
        crate::device::types::DeviceBinding::Key { thumbprint, .. } => Some(*thumbprint),
        _ => None,
    });
    match (key, keys) {
        (None, _) | (Some(_), None) => Some(DeviceProof::Token),
        (Some(key), Some(keys)) => keys
            .for_device(&device.tenant_id, &device.id)
            .filter(|proven| proven.thumbprint.matches(&key))
            .map(|_| DeviceProof::Key(key)),
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
    /// not hoarding `Seen` ones. An `Unknown` device beyond the window is
    /// not counted and not deleted here, and the retention sweep leaves
    /// `Unknown` rows alone, so it stays until it enters the window.
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

    /// Resolve a request to the device it proves.
    ///
    /// As [`resolve_or_keep`](Self::resolve_or_keep), without the device a
    /// session keeps: every answer is a device the request proved, by the
    /// token it presents or by being created for it now. A request of an
    /// authenticated session that presents no token, and whose session
    /// device still stands, proves nothing and is answered `None`; no device
    /// is created for it. A resolver that wants the session to keep that
    /// device calls [`resolve_or_keep`](Self::resolve_or_keep) and hands the
    /// kept device on as recognised.
    pub fn resolve_proven(
        &self,
        request: DeviceRequest<'_>,
        now: Timestamp,
        rng: &dyn SecureRng,
        new_id_fn: impl FnOnce() -> DeviceId + Send,
    ) -> impl Future<Output = Result<Option<ResolvedDevice>, S::Error>> + Send {
        let resolving = self.resolve_or_keep(request, now, rng, new_id_fn);
        async move {
            Ok(match resolving.await? {
                Some(ResolvedOrKept::Proven(resolved)) => Some(resolved),
                Some(ResolvedOrKept::Kept(_)) | None => None,
            })
        }
    }

    /// Resolve a request to its device by the token it presents, or keep the
    /// device its session is bound to.
    ///
    /// - The cookie's entries are tried newest first. The first that names a
    ///   device of `tenant` the request's `user` may use (one it owns, or
    ///   one with no owner) and presents the token on its row is that
    ///   device: it is returned as [`Proven`](ResolvedOrKept::Proven), and
    ///   the authenticated `user` is recorded as a sighting (and claims the
    ///   device if it has no owner). An account switch on a shared browser
    ///   profile therefore finds the account's own device again.
    /// - A request with no `user` reads and writes nothing, and has the
    ///   device the cookie proves when it proves exactly one, so the device
    ///   can be judged for step-up before sign-in; with several proven (a
    ///   profile several accounts share) or none, it has no device.
    /// - Otherwise the device the session was last bound to is kept when it
    ///   exists, is not revoked and belongs to `user`: it is returned as
    ///   [`Kept`](ResolvedOrKept::Kept), recognised and not proven, because
    ///   the request presented no token for it.
    /// - Otherwise, for a request with a fingerprint, a new `Unknown` device
    ///   owned by `user` is created, after the user's least recently seen
    ///   `Unknown` devices beyond [`DEFAULT_MAX_UNKNOWN_DEVICES_PER_USER`]
    ///   (or the service's own bound) are deleted, with a
    ///   fresh token whose digest is on the row and whose value is returned in
    ///   [`ResolvedDevice::issued`] for the cookie. It is
    ///   [`Proven`](ResolvedOrKept::Proven): the request holds the token it
    ///   was just issued. A request with no fingerprint
    ///   ([`DeviceRequest::fingerprint`]) has no device, and nothing is
    ///   deleted or written for it.
    ///
    /// Under enforcement of device keys ([`DeviceRequest::keys`]) a device
    /// that has a key is proven only when the request proved that key, and
    /// its answer says so
    /// ([`DeviceProof::Key`](crate::device_key::DeviceProof::Key)); the
    /// token of such a device proves nothing alone. A request that presents
    /// the token without the key is treated as one that presented no token:
    /// a guest has no device, a session that names the device keeps it as
    /// recognised, and any other authenticated request with a fingerprint is
    /// given a new `Unknown` device. A device without a key is proven by its
    /// token.
    ///
    /// A device that matches the fingerprint but cannot prove itself is never
    /// returned, whoever it belongs to. A `Revoked` device is never
    /// returned either, including one revoked between the load and the
    /// sighting: the store reports the level it found when it applied the
    /// sighting, and a `Revoked` answer sends the request on to a new device.
    pub fn resolve_or_keep(
        &self,
        request: DeviceRequest<'_>,
        now: Timestamp,
        rng: &dyn SecureRng,
        new_id_fn: impl FnOnce() -> DeviceId + Send,
    ) -> impl Future<Output = Result<Option<ResolvedOrKept>, S::Error>> + Send {
        let keys = request.keys.check().cloned();
        let tenant = *request.tenant;
        let user = request.user.cloned();
        let fingerprint = request.fingerprint;
        let presented = request.presented.to_vec();
        let session_device = request.session_device.copied();
        let max_unknown = self.max_unknown_per_user;
        async move {
            // A guest is recognised only when the cookie proves exactly one
            // device: with several (a profile several accounts share)
            // nothing says which account is signing in.
            let mut for_guest: Vec<(DeviceId, crate::device_key::DeviceProof)> = Vec::new();
            for entry in &presented {
                let Some(device) = self.store.load(&tenant, &entry.id).await? else {
                    continue;
                };
                if device.trust_level == DeviceTrustLevel::Revoked
                    || !entry.token.is_listed_in(&device.bindings)
                    || !is_usable_by(&device, user.as_ref())
                {
                    continue;
                }
                let Some(proof) = proof_of(&device, keys.as_ref()) else {
                    continue;
                };
                let Some(user) = user.as_ref() else {
                    for_guest.push((device.id, proof));
                    continue;
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
                    continue;
                }
                if self.note_sighting(&tenant, &device, now).await? != DeviceTrustLevel::Revoked {
                    return Ok(Some(ResolvedOrKept::Proven(ResolvedDevice {
                        id: device.id,
                        issued: None,
                        proof: ProvenDevice::by(device.id, proof),
                    })));
                }
            }
            let Some(user) = user else {
                return Ok(match for_guest.as_slice() {
                    [(id, proof)] => Some(ResolvedOrKept::Proven(ResolvedDevice {
                        id: *id,
                        issued: None,
                        proof: ProvenDevice::by(*id, *proof),
                    })),
                    _ => None,
                });
            };

            if let Some(id) = session_device
                && let Some(device) = self.store.load(&tenant, &id).await?
                && device.trust_level != DeviceTrustLevel::Revoked
                && device.user_id.as_ref() == Some(&user)
                && self.note_sighting(&tenant, &device, now).await? != DeviceTrustLevel::Revoked
            {
                // No token was presented for it: the session keeps the
                // device, and the answer does not say it was proven.
                return Ok(Some(ResolvedOrKept::Kept(device.id)));
            }

            // The new row stores the fingerprint: without one there is none.
            let Some(fingerprint) = fingerprint else {
                return Ok(None);
            };
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
            Ok(Some(ResolvedOrKept::Proven(ResolvedDevice {
                id,
                issued: Some(token),
                proof: ProvenDevice::new(id),
            })))
        }
    }
}
