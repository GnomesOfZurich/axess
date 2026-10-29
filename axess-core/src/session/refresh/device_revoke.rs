//! Revoking a device revokes its refresh tokens, and a refresh can check the
//! device before it rotates.

use super::test_support::{fixture_tenant, fixture_user, now, store, test_config};
use super::*;
use crate::authn::ids::DeviceId;
use crate::device::{
    CascadingRefreshStore, Device, DeviceStore, DeviceTrustLevel, FingerprintHash,
    MemoryDeviceStore, RevokeDeviceError, revoke_device,
};
use crate::testing::mock_random::MockRng;
use axess_clock::testing::MockClock;
use std::sync::Arc;

fn device_id(name: &str) -> DeviceId {
    axess_identity::testing::device(name)
}

fn trusted(tenant: &TenantId, id: &DeviceId, fp: u8) -> Device {
    Device {
        id: *id,
        tenant_id: *tenant,
        user_id: Some(fixture_user()),
        trust_level: DeviceTrustLevel::Trusted,
        fingerprint_hash: FingerprintHash::from_bytes([fp; 32]),
        first_seen_at: now(),
        last_seen_at: now(),
        revoked_at: None,
        demoted_at: None,
        bindings: Vec::new(),
    }
}

async fn issue<S: RefreshTokenStore>(
    store: &S,
    rng: &MockRng,
    device: Option<DeviceId>,
    info: Option<&str>,
) -> String {
    issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: info.map(str::to_owned),
            family_id: None,
            device_id: device,
        },
        &test_config(),
        store,
        rng,
        now(),
    )
    .await
    .unwrap()
    .0
}

/// Revoking device D revokes every token issued to D, so the next refresh
/// with one of them fails and issues nothing, while a token for another
/// device of the same user still refreshes.
#[tokio::test]
async fn revoking_a_device_revokes_its_tokens_and_only_its_tokens() {
    let (refresh, devices, rng) = (store(), MemoryDeviceStore::new(), MockRng::new(7));
    let tenant = fixture_tenant();
    let (d1, d2) = (device_id("laptop"), device_id("phone"));
    for (id, fp) in [(&d1, 1u8), (&d2, 2u8)] {
        devices
            .save(&trusted(&tenant, id, fp), crate::device::test_now())
            .await
            .unwrap();
    }
    let laptop = issue(&refresh, &rng, Some(d1), Some("ua-laptop")).await;
    let phone = issue(&refresh, &rng, Some(d2), Some("ua-phone")).await;

    let revoked = revoke_device(&devices, &refresh, &tenant, &d1, now())
        .await
        .unwrap();
    assert_eq!(revoked, 1);

    let device = devices.load(&tenant, &d1).await.unwrap().unwrap();
    assert_eq!(device.trust_level, DeviceTrustLevel::Revoked);
    let outcome = refresh_session_with_status_check(
        &laptop,
        &refresh,
        &test_config(),
        &rng,
        now(),
        Some("ua-laptop"),
        |_| async { true },
    )
    .await;
    assert!(
        matches!(outcome, Err(RefreshError::Revoked)),
        "the revoked device's token must not refresh"
    );
    let ok = refresh_session_with_status_check(
        &phone,
        &refresh,
        &test_config(),
        &rng,
        now(),
        Some("ua-phone"),
        |_| async { true },
    )
    .await;
    assert!(ok.is_ok(), "another device's token still refreshes");
}

/// Setting the trust level alone leaves the tokens refreshing; that is the
/// gap the opt-in check closes before the token is rotated.
#[tokio::test]
async fn the_device_check_refuses_a_token_whose_device_is_revoked() {
    let (refresh, devices, rng) = (store(), MemoryDeviceStore::new(), MockRng::new(8));
    let tenant = fixture_tenant();
    let d = device_id("laptop");
    devices
        .save(&trusted(&tenant, &d, 1), crate::device::test_now())
        .await
        .unwrap();
    let token = issue(&refresh, &rng, Some(d), None).await;

    devices
        .set_trust_level(&tenant, &d, DeviceTrustLevel::Revoked, now())
        .await
        .unwrap();

    // The plain refresh does not look at the device.
    let plain = refresh_session_with_status_check(
        &token,
        &refresh,
        &test_config(),
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(plain.is_ok(), "set_trust_level alone does not stop it");
    // A second token (the first was rotated) shows the checked path.
    let token = issue(&refresh, &rng, Some(d), None).await;
    let checked = refresh_session_with_device_check(
        &token,
        &refresh,
        &test_config(),
        &rng,
        now(),
        None,
        &devices,
    )
    .await;
    assert!(matches!(checked, Err(RefreshError::DeviceRevoked)));
    // Nothing was rotated: the token is still the live one.
    let record = refresh
        .find_token(&hash_token(&token, None))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !record.revoked,
        "a refused refresh does not consume the token"
    );
}

#[tokio::test]
async fn the_device_check_lets_a_live_device_a_deviceless_token_and_a_missing_device_behave() {
    let (refresh, devices, rng) = (store(), MemoryDeviceStore::new(), MockRng::new(9));
    let tenant = fixture_tenant();
    let live = device_id("live");
    devices
        .save(&trusted(&tenant, &live, 1), crate::device::test_now())
        .await
        .unwrap();
    let cfg = test_config();

    let on_live = issue(&refresh, &rng, Some(live), None).await;
    assert!(
        refresh_session_with_device_check(&on_live, &refresh, &cfg, &rng, now(), None, &devices)
            .await
            .is_ok()
    );

    let none = issue(&refresh, &rng, None, None).await;
    assert!(
        refresh_session_with_device_check(&none, &refresh, &cfg, &rng, now(), None, &devices)
            .await
            .is_ok(),
        "a token with no device id has nothing to check"
    );

    let gone = issue(&refresh, &rng, Some(device_id("purged")), None).await;
    assert!(matches!(
        refresh_session_with_device_check(&gone, &refresh, &cfg, &rng, now(), None, &devices).await,
        Err(RefreshError::DeviceRevoked)
    ));
}

/// A store that cannot revoke by device is reported, not silently skipped.
#[tokio::test]
async fn revoke_device_reports_a_store_that_cannot_revoke_by_device() {
    struct NoDeviceIndex(crate::testing::MemoryRefreshTokenStore);
    impl RefreshTokenStore for NoDeviceIndex {
        type Error = std::convert::Infallible;
        async fn store_token(&self, t: &RefreshToken) -> Result<(), Self::Error> {
            self.0.store_token(t).await
        }
        async fn find_token(&self, h: &str) -> Result<Option<RefreshToken>, Self::Error> {
            self.0.find_token(h).await
        }
        async fn revoke_token(&self, id: &RefreshTokenId) -> Result<(), Self::Error> {
            self.0.revoke_token(id).await
        }
        async fn revoke_user_tokens(&self, u: &UserId) -> Result<(), Self::Error> {
            self.0.revoke_user_tokens(u).await
        }
        async fn active_tokens(&self, u: &UserId) -> Result<Vec<RefreshToken>, Self::Error> {
            self.0.active_tokens(u).await
        }
        async fn revoke_family(&self, u: &UserId, f: &TokenFamilyId) -> Result<(), Self::Error> {
            self.0.revoke_family(u, f).await
        }
        async fn issue_capped(&self, t: &RefreshToken, max: usize) -> Result<(), Self::Error> {
            self.0.issue_capped(t, max).await
        }
        async fn rotate_token(
            &self,
            p: &RefreshTokenId,
            t: &RefreshToken,
        ) -> Result<RotationOutcome, Self::Error> {
            self.0.rotate_token(p, t).await
        }
    }

    let devices = MemoryDeviceStore::new();
    let tenant = fixture_tenant();
    let d = device_id("laptop");
    devices
        .save(&trusted(&tenant, &d, 1), crate::device::test_now())
        .await
        .unwrap();
    let outcome = revoke_device(&devices, &NoDeviceIndex(store()), &tenant, &d, now()).await;
    assert!(matches!(outcome, Err(RevokeDeviceError::TokensUnsupported)));
    let device = devices.load(&tenant, &d).await.unwrap().unwrap();
    assert_eq!(
        device.trust_level,
        DeviceTrustLevel::Revoked,
        "the device half still ran"
    );
}

/// Reuse of a rotated-out token revokes the devices the family ran on when
/// the refresh store is wrapped with the cascading decorator; the bare store
/// only logs.
#[tokio::test]
async fn a_compromised_family_revokes_its_devices_through_the_decorator() {
    let (devices, rng) = (MemoryDeviceStore::new(), MockRng::new(11));
    let tenant = fixture_tenant();
    let d = device_id("stolen");
    devices
        .save(&trusted(&tenant, &d, 1), crate::device::test_now())
        .await
        .unwrap();
    let clock: Arc<dyn axess_clock::Clock> = Arc::new(MockClock::at(now()));
    let refresh = CascadingRefreshStore::new(store(), devices.clone(), clock);
    let v1 = issue(&refresh, &rng, Some(d), None).await;

    // v1 rotates to v2; presenting v1 again is reuse.
    refresh_session_with_status_check(
        &v1,
        &refresh,
        &test_config(),
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await
    .unwrap();
    let reuse = refresh_session_with_status_check(
        &v1,
        &refresh,
        &test_config(),
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(reuse, Err(RefreshError::Revoked)));

    let device = devices.load(&tenant, &d).await.unwrap().unwrap();
    assert_eq!(
        device.trust_level,
        DeviceTrustLevel::Revoked,
        "the compromise hook revoked the linked device"
    );
}
