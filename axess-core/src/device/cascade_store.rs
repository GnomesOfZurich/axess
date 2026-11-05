//! [`CascadingRefreshStore`]: a refresh-token store that revokes the linked
//! devices when a token family is compromised.

use std::sync::Arc;

use axess_clock::Clock;

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::cascade::cascade_revoke_devices_and_tokens;
use crate::device::store::DeviceStore;
use crate::session::refresh::{
    DeviceTokenRevocation, RefreshToken, RefreshTokenId, RefreshTokenStore, RotationOutcome,
    TokenFamilyId,
};

/// Wraps a [`RefreshTokenStore`] so that a compromised token family also
/// revokes the devices it was issued to.
///
/// The default
/// [`on_token_compromise`](RefreshTokenStore::on_token_compromise) only logs,
/// because a refresh store has no device store to act on. This decorator
/// holds one: when reuse of a rotated-out token is detected it runs
/// [`cascade_revoke_devices_and_tokens`] on each device the refresh functions collected (the
/// device and every refresh token it holds), then calls the wrapped store's own hook (so an alerting
/// override there still fires). Everything else is forwarded unchanged.
///
/// A failure to revoke one device is logged and does not stop the others,
/// as in [`cascade_revoke_devices`](crate::device::cascade_revoke_devices); the compromise hook cannot fail the
/// refresh that detected the reuse, which has already refused it.
#[derive(Clone)]
pub struct CascadingRefreshStore<R, D> {
    refresh: R,
    devices: D,
    clock: Arc<dyn Clock>,
}

impl<R, D> CascadingRefreshStore<R, D>
where
    R: RefreshTokenStore,
    D: DeviceStore,
{
    /// Wrap `refresh`; devices are revoked in `devices` at the time `clock`
    /// reports.
    pub fn new(refresh: R, devices: D, clock: Arc<dyn Clock>) -> Self {
        Self {
            refresh,
            devices,
            clock,
        }
    }
}

impl<R, D> RefreshTokenStore for CascadingRefreshStore<R, D>
where
    R: RefreshTokenStore,
    D: DeviceStore,
{
    type Error = R::Error;

    fn store_token(
        &self,
        token: &RefreshToken,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.refresh.store_token(token)
    }

    fn find_token(
        &self,
        token_hash: &str,
    ) -> impl Future<Output = Result<Option<RefreshToken>, Self::Error>> + Send {
        self.refresh.find_token(token_hash)
    }

    fn revoke_token(
        &self,
        token_id: &RefreshTokenId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.refresh.revoke_token(token_id)
    }

    fn revoke_user_tokens(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.refresh.revoke_user_tokens(user_id)
    }

    fn revoke_device_tokens(
        &self,
        tenant_id: &TenantId,
        device_id: &DeviceId,
    ) -> impl Future<Output = Result<DeviceTokenRevocation, Self::Error>> + Send {
        self.refresh.revoke_device_tokens(tenant_id, device_id)
    }

    fn active_tokens(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<Vec<RefreshToken>, Self::Error>> + Send {
        self.refresh.active_tokens(user_id)
    }

    fn revoke_family(
        &self,
        user_id: &UserId,
        family_id: &TokenFamilyId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.refresh.revoke_family(user_id, family_id)
    }

    fn issue_capped(
        &self,
        new_token: &RefreshToken,
        max_per_user: usize,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.refresh.issue_capped(new_token, max_per_user)
    }

    fn rotate_token(
        &self,
        parent_id: &RefreshTokenId,
        new_token: &RefreshToken,
    ) -> impl Future<Output = Result<RotationOutcome, Self::Error>> + Send {
        self.refresh.rotate_token(parent_id, new_token)
    }

    fn on_token_compromise(
        &self,
        user_id: &UserId,
        family_id: &TokenFamilyId,
        compromised_devices: &[(TenantId, DeviceId)],
    ) -> impl Future<Output = ()> + Send {
        let now = self.clock.now();
        async move {
            let revoked = cascade_revoke_devices_and_tokens(
                &self.devices,
                &self.refresh,
                compromised_devices,
                now,
            )
            .await;
            tracing::warn!(
                %user_id,
                %family_id,
                devices = compromised_devices.len(),
                revoked,
                "refresh token compromise: linked devices revoked"
            );
            self.refresh
                .on_token_compromise(user_id, family_id, compromised_devices)
                .await;
        }
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use crate::device::store::MemoryDeviceStore;
    use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
    use crate::testing::MemoryRefreshTokenStore;
    use axess_rng::testing::MockRng;
    use chrono::Utc;

    fn token(
        rng: &MockRng,
        hash: &str,
        family: Option<TokenFamilyId>,
        dev: DeviceId,
    ) -> RefreshToken {
        let now = Utc::now();
        RefreshToken {
            id: RefreshTokenId::new(rng),
            user_id: axess_identity::testing::user("u1"),
            tenant_id: axess_identity::testing::tenant("t1"),
            token_hash: hash.to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(1),
            revoked: false,
            device_info: None,
            family_id: family,
            device_id: Some(dev),
            authn_time: None,
            revoked_reason: None,
            revoked_at: None,
        }
    }

    /// A compromised family revokes its devices and every other refresh
    /// token those devices hold, whatever family they belong to.
    #[tokio::test]
    async fn a_compromise_revokes_the_devices_other_tokens_too() {
        let rng = MockRng::new(11);
        let tenant = axess_identity::testing::tenant("t1");
        let device_id = axess_identity::testing::device("dev-a");
        let now = crate::device::store::whole_second(Utc::now());
        let devices = MemoryDeviceStore::new();
        devices
            .save(
                &Device {
                    id: device_id,
                    tenant_id: tenant,
                    user_id: Some(axess_identity::testing::user("u1")),
                    trust_level: DeviceTrustLevel::Trusted,
                    fingerprint_hash: FingerprintHash::from_bytes([1; 32]),
                    first_seen_at: now,
                    last_seen_at: now,
                    revoked_at: None,
                    demoted_at: None,
                    bindings: Vec::<DeviceBinding>::new(),
                },
                now,
            )
            .await
            .unwrap();
        let refresh = MemoryRefreshTokenStore::new();
        // A token of another family, on the same device.
        let other = token(&rng, "other", None, device_id);
        refresh.store_token(&other).await.unwrap();

        let clock: Arc<dyn Clock> = Arc::new(axess_clock::testing::MockClock::at(now));
        let store = CascadingRefreshStore::new(refresh.clone(), devices.clone(), clock);
        let family = TokenFamilyId::try_new(uuid::Uuid::from_u128(7).to_string()).unwrap();
        store
            .on_token_compromise(
                &axess_identity::testing::user("u1"),
                &family,
                &[(tenant, device_id)],
            )
            .await;

        let dev = devices.load(&tenant, &device_id).await.unwrap().unwrap();
        assert_eq!(dev.trust_level, DeviceTrustLevel::Revoked);
        let other = refresh.find_token("other").await.unwrap();
        assert!(
            other.is_none_or(|t| t.revoked),
            "the device's other refresh token must not stay usable"
        );
    }
}
