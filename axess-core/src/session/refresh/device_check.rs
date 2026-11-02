//! Refreshing a session only while the device the token was issued to is
//! still trusted.

use super::rotation::{DeviceGate, DeviceRefusal, Refresh};
use super::store::RefreshTokenStore;
use super::types::{RefreshError, RefreshToken, RefreshTokenConfig};
use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::{DeviceStore, DeviceTrustLevel};
use crate::session::data::SessionData;
use axess_rng::SecureRng;
use chrono::{DateTime, Utc};
use std::future::Future;
use std::pin::Pin;

/// The device check against a [`DeviceStore`]: the token's device must be
/// loadable, not `Revoked`, and unowned or owned by the token's user; a
/// store that cannot answer refuses.
struct CheckedAgainst<'a, D>(&'a D);

impl<D: DeviceStore> DeviceGate for CheckedAgainst<'_, D> {
    fn check<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        user: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = Result<(), DeviceRefusal>> + Send + 'a>> {
        Box::pin(async move {
            match self.0.load(tenant, device).await {
                Ok(Some(device)) if device.trust_level != DeviceTrustLevel::Revoked => {
                    match device.user_id.as_ref() {
                        Some(owner) if owner != user => Err(DeviceRefusal::OtherOwner),
                        _ => Ok(()),
                    }
                }
                Ok(_) => Err(DeviceRefusal::Revoked),
                Err(error) => Err(DeviceRefusal::Store(error.to_string())),
            }
        })
    }
}

impl<'a, F> Refresh<'a, F> {
    /// Check the device the token was issued to before anything is rotated.
    ///
    /// A token carries the id of its device (`RefreshToken::device_id`).
    /// When it has one, the device is loaded from `devices`, and the refresh
    /// is refused with [`RefreshError::DeviceRevoked`] when the device is
    /// `Revoked` or no longer exists (the retention sweep purges revoked
    /// rows, so a purged device is a revoked one), and with
    /// [`RefreshError::DeviceMismatch`] when another user owns it (a device
    /// made during a guest request and claimed by someone else). An unowned
    /// device passes, and a token with no device id has nothing to check.
    /// When the device store cannot answer, the refresh fails with
    /// [`RefreshError::DeviceStore`]: the check does not fail open.
    ///
    /// This closes the gap that setting a device's trust level leaves open:
    /// [`set_trust_level`](crate::device::DeviceStore::set_trust_level)
    /// changes the device row and touches no token, so a lost device's
    /// tokens keep refreshing until something revokes them.
    /// [`revoke_device`](crate::device::revoke_device) revokes the device
    /// and its tokens together; this check is the second line for tokens
    /// that escaped it, and the only one for a store that cannot revoke by
    /// device. It costs one device-store read per refresh, so put a
    /// [`CachedDeviceStore`](crate::device::CachedDeviceStore) in front of a
    /// slow store.
    ///
    /// The check and the rotation are two store operations, so a device
    /// revoked between them is still rotated once: the child carries the
    /// same device id, so `revoke_device` revokes it when its insert landed
    /// before the revocation's statement, and the next device-checked
    /// refresh refuses it otherwise.
    pub fn device_store<D: DeviceStore>(self, devices: &'a D) -> Self {
        self.device_gate(Box::new(CheckedAgainst(devices)))
    }
}

/// [`refresh_session`](super::refresh_session) that first checks the device
/// the token was issued to.
///
/// Deprecated: it skips the account-status check. Use [`Refresh::new`] with
/// a status predicate and [`Refresh::device_store`], which also composes
/// with the tenant check this form cannot add.
#[deprecated(
    since = "0.14.0",
    note = "skips the account-status check; \
            use Refresh::new(plaintext, status_check).device_store(devices).run(..)"
)]
pub async fn refresh_session_with_device_check<S: RefreshTokenStore, D: DeviceStore>(
    plaintext: &str,
    store: &S,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    device_info: Option<&str>,
    device_store: &D,
) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>> {
    Refresh::without_status_check(plaintext)
        .device_info(device_info)
        .device_store(device_store)
        .run(store, config, rng, now)
        .await
}
