//! The device check a per-account lockout makes: is the session's device one
//! the locked account has already used?

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::store::DeviceStore;
use crate::device::types::DeviceTrustLevel;
use std::future::Future;
use std::pin::Pin;

/// Whether a device is one `user` has used: a row of the tenant owned by the
/// user and at [`Seen`](DeviceTrustLevel::Seen) or
/// [`Trusted`](DeviceTrustLevel::Trusted). Object-safe, so the service holds
/// it behind an `Arc` whatever the store.
pub(crate) trait KnownDevices: Send + Sync {
    fn is_known<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        user: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// [`KnownDevices`] over a [`DeviceStore`].
pub(crate) struct StoreKnownDevices<D>(pub(crate) D);

impl<D: DeviceStore> KnownDevices for StoreKnownDevices<D> {
    fn is_known<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        user: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self.0.load(tenant, device).await {
                Ok(Some(row)) => {
                    row.user_id.as_ref() == Some(user)
                        && matches!(
                            row.trust_level,
                            DeviceTrustLevel::Seen | DeviceTrustLevel::Trusted
                        )
                }
                Ok(None) => false,
                Err(error) => {
                    // The lock holds when the store cannot say.
                    tracing::warn!(error = %error, "lockout: device lookup failed; the lock applies");
                    false
                }
            }
        })
    }
}
