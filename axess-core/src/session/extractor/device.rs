//! What a session answers about its device: the device a request proved,
//! and that device as the signed-in user's own.

use super::AuthSession;
use crate::session::data::{AuthState, SessionData};

impl AuthSession {
    /// The session's device when this request proved it, `None` otherwise
    /// (no device, one a resolver found by other means such as a
    /// fingerprint, or one the session only kept from an earlier request
    /// and this request proved by neither its token nor its key).
    ///
    /// The only reading of the session's device that a lockout exemption
    /// accepts: the per-account lockout lets an account's own device through
    /// only as a [`ProvenDevice`](crate::device::ProvenDevice), which the
    /// session layer notes, for the request it is serving and no longer,
    /// when the device resolver reports one. The library's
    /// [`LifecycleDeviceResolver`](crate::device::LifecycleDeviceResolver)
    /// reports one for a request that presents the secret token of the
    /// device cookie (a guest's, such as the request that completes a
    /// login, only when it can be fingerprinted, which the default
    /// extractor does from its `User-Agent`), and for the device it creates
    /// for an authenticated user, whose token it issues in the same answer. A request of an
    /// authenticated session that presents no token keeps the device the
    /// session was bound to
    /// ([`device_id`](Self::device_id) still answers it), and this answers
    /// `None` for it: the session cookie is not proof of the device. A
    /// session bound to a device key is the exception: a request that proved
    /// the bound key has the bound device proven by that key, token or not.
    /// Like [`device_id`](Self::device_id), it answers only a device that
    /// holds for the person at the browser: `None` for the rest of a request
    /// in which another person signed in on a signed-in session.
    pub async fn proven_device(&self) -> Option<crate::device::ProvenDevice> {
        let inner = self.0.0.read().await;
        proven_device_of(&inner.data, inner.device_in_force())
    }

    /// The device this request proved, paired with the user and the tenant
    /// this session is authenticated as: what a trust write takes
    /// ([`DeviceLifecycleService::promote_on_authn`](crate::device::DeviceLifecycleService::promote_on_authn),
    /// [`grant_trust`](crate::device::DeviceLifecycleService::grant_trust)).
    /// `None` for a session that is not fully authenticated, for a request
    /// that proved no device (see [`proven_device`](Self::proven_device)),
    /// and for a session an administrator is impersonating the user in
    /// ([`impersonator`](Self::impersonator)): the browser is the
    /// administrator's, and nothing done under impersonation promotes or
    /// trusts a device, the user's or the administrator's. Ask after the
    /// handler has authenticated the session, on the request that completes
    /// a login: a device the request resolved for nobody (a guest's request,
    /// or one inside a login) holds for whoever signs in, and one resolved
    /// for another person holds for nobody else.
    pub async fn user_device(&self) -> Option<crate::device::UserDevice> {
        let inner = self.0.0.read().await;
        let AuthState::Authenticated {
            user_id,
            tenant_id,
            impersonator: None,
            ..
        } = &inner.data.auth_state
        else {
            return None;
        };
        proven_device_of(&inner.data, inner.device_in_force())
            .map(|device| crate::device::UserDevice::new(*tenant_id, *user_id, device))
    }
}

/// The device the request `data` belongs to proved, and how: `device`, the
/// session's device while it holds for the person at the browser
/// (`SessionInner::device_in_force`), and none when it does not.
fn proven_device_of(
    data: &SessionData,
    device: Option<crate::authn::ids::DeviceId>,
) -> Option<crate::device::ProvenDevice> {
    if !data.device_proven {
        return None;
    }
    let proof = match data.device_key {
        Some(proven) => crate::device_key::DeviceProof::Key(proven.thumbprint),
        None => crate::device_key::DeviceProof::Token,
    };
    device.map(|id| crate::device::ProvenDevice::by(id, proof))
}
