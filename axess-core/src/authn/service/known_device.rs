//! The device check a per-account lockout makes: is the session's device one
//! the locked account has already used?

use crate::authn::ids::{TenantId, UserId};
use crate::device::ProvenDevice;
use crate::device::store::DeviceStore;
use crate::device::types::DeviceTrustLevel;
use std::future::Future;
use std::pin::Pin;

/// Whether a device, one the client proved it holds, is one `user` has used: a row of the tenant owned by the
/// user and at [`Seen`](DeviceTrustLevel::Seen) or
/// [`Trusted`](DeviceTrustLevel::Trusted). Object-safe, so the service holds
/// it behind an `Arc` whatever the store.
pub(crate) trait KnownDevices: Send + Sync {
    fn is_known<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a ProvenDevice,
        user: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// [`KnownDevices`] over a [`DeviceStore`].
pub(crate) struct StoreKnownDevices<D>(pub(crate) D);

impl<D: DeviceStore> KnownDevices for StoreKnownDevices<D> {
    fn is_known<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a ProvenDevice,
        user: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(store_knows(&self.0, tenant, device, user))
    }
}

/// Whether `store` holds `device` as a row of `tenant` owned by `user` at
/// `Seen` or `Trusted`. `false` when the store cannot say: the lock holds.
async fn store_knows<D: DeviceStore>(
    store: &D,
    tenant: &TenantId,
    device: &ProvenDevice,
    user: &UserId,
) -> bool {
    match store.load(tenant, &device.id()).await {
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
}

/// [`StoreKnownDevices`] for a deployment that requires device keys: a device
/// counts only when the request proved it by a signature of its key. A
/// device proven by its token, which a copy of the cookie store also holds,
/// is never exempt.
#[cfg(feature = "device-keys")]
pub(crate) struct KeyProvenKnownDevices<D>(pub(crate) D);

#[cfg(feature = "device-keys")]
impl<D: DeviceStore> KnownDevices for KeyProvenKnownDevices<D> {
    fn is_known<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a ProvenDevice,
        user: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            matches!(device.proof(), crate::device_key::DeviceProof::Key(_))
                && store_knows(&self.0, tenant, device, user).await
        })
    }
}

#[cfg(all(test, feature = "device-keys"))]
mod tests {
    use super::*;
    use crate::device::store::MemoryDeviceStore;
    use crate::device::store::consistency::{at, dev_id, device, tenant, user};
    use crate::device_key::KeyThumbprint;

    /// With device keys required, the owner's device is exempt only for a
    /// request that proved it by key; proven by its token it is not, and the
    /// plain check, for a deployment that does not require keys, takes both.
    #[tokio::test]
    async fn a_token_proven_device_is_known_only_where_keys_are_not_required() {
        let store = MemoryDeviceStore::new();
        store
            .save(&device("laptop", 1, DeviceTrustLevel::Seen, at(0)), at(0))
            .await
            .unwrap();
        let by_token = ProvenDevice::for_tests(dev_id("laptop"));
        let by_key =
            ProvenDevice::for_tests_by_key(dev_id("laptop"), KeyThumbprint::from_bytes([1; 32]));
        let (t, u) = (tenant(), user());

        let plain = StoreKnownDevices(store.clone());
        assert!(plain.is_known(&t, &by_token, &u).await);
        assert!(plain.is_known(&t, &by_key, &u).await);

        let keyed = KeyProvenKnownDevices(store);
        assert!(!keyed.is_known(&t, &by_token, &u).await);
        assert!(keyed.is_known(&t, &by_key, &u).await);
        // Still only a device the account has used.
        let stranger = crate::authn::ids::testing::user("stranger");
        assert!(!keyed.is_known(&t, &by_key, &stranger).await);
        let unknown =
            ProvenDevice::for_tests_by_key(dev_id("elsewhere"), KeyThumbprint::from_bytes([1; 32]));
        assert!(!keyed.is_known(&t, &unknown, &u).await);
    }
}
