//! Revoking a device revokes its refresh tokens, and a refresh can check the
//! device before it rotates.

use super::test_support::{SpyRefreshStore, fixture_tenant, fixture_user, now, store, test_config};
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
    let outcome = Refresh::new(&laptop, |_| async { true })
        .device_info(Some("ua-laptop"))
        .run(&refresh, &test_config(), &rng, now())
        .await;
    assert!(
        matches!(outcome, Err(RefreshError::Revoked)),
        "the revoked device's token must not refresh"
    );
    let ok = Refresh::new(&phone, |_| async { true })
        .device_info(Some("ua-phone"))
        .run(&refresh, &test_config(), &rng, now())
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
    let plain = Refresh::new(&token, |_| async { true })
        .run(&refresh, &test_config(), &rng, now())
        .await;
    assert!(plain.is_ok(), "set_trust_level alone does not stop it");
    // A second token (the first was rotated) shows the checked path.
    let token = issue(&refresh, &rng, Some(d), None).await;
    let checked = Refresh::new(&token, |_| async { true })
        .device_store(&devices)
        .run(&refresh, &test_config(), &rng, now())
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
        Refresh::new(&on_live, |_| async { true })
            .device_store(&devices)
            .run(&refresh, &cfg, &rng, now())
            .await
            .is_ok()
    );

    let none = issue(&refresh, &rng, None, None).await;
    assert!(
        Refresh::new(&none, |_| async { true })
            .device_store(&devices)
            .run(&refresh, &cfg, &rng, now())
            .await
            .is_ok(),
        "a token with no device id has nothing to check"
    );

    let gone = issue(&refresh, &rng, Some(device_id("purged")), None).await;
    assert!(matches!(
        Refresh::new(&gone, |_| async { true })
            .device_store(&devices)
            .run(&refresh, &cfg, &rng, now())
            .await,
        Err(RefreshError::DeviceRevoked)
    ));
}

/// A store that cannot revoke by device is reported, not silently skipped.
#[tokio::test]
async fn revoke_device_reports_a_store_that_cannot_revoke_by_device() {
    let devices = MemoryDeviceStore::new();
    let tenant = fixture_tenant();
    let d = device_id("laptop");
    devices
        .save(&trusted(&tenant, &d, 1), crate::device::test_now())
        .await
        .unwrap();
    let outcome = revoke_device(
        &devices,
        &SpyRefreshStore::new().without_device_index(),
        &tenant,
        &d,
        now(),
    )
    .await;
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
    Refresh::new(&v1, |_| async { true })
        .run(&refresh, &test_config(), &rng, now())
        .await
        .unwrap();
    let reuse = Refresh::new(&v1, |_| async { true })
        .run(&refresh, &test_config(), &rng, now())
        .await;
    assert!(matches!(reuse, Err(RefreshError::Revoked)));

    let device = devices.load(&tenant, &d).await.unwrap().unwrap();
    assert_eq!(
        device.trust_level,
        DeviceTrustLevel::Revoked,
        "the compromise hook revoked the linked device"
    );
}

/// The device check in a tenant: a token of another tenant is not found, the
/// device store is not consulted and nothing is rotated; in its own tenant a
/// revoked device refuses the refresh before anything is rotated.
#[tokio::test]
async fn the_device_check_in_tenant_rails_the_tenant_before_the_device() {
    let (refresh, devices, rng) = (store(), MemoryDeviceStore::new(), MockRng::new(12));
    let tenant = fixture_tenant();
    let other = axess_identity::testing::tenant("tenant-2");
    let d = device_id("laptop");
    devices
        .save(&trusted(&tenant, &d, 1), crate::device::test_now())
        .await
        .unwrap();
    let token = issue(&refresh, &rng, Some(d), None).await;
    let cfg = test_config();

    // An empty device store for the foreign call: had the device been
    // loaded first, the answer would have been DeviceRevoked.
    let foreign = Refresh::new(&token, |_| async { true })
        .in_tenant(&other)
        .device_store(&MemoryDeviceStore::new())
        .run(&refresh, &cfg, &rng, now())
        .await;
    assert!(
        matches!(foreign, Err(RefreshError::NotFound)),
        "{foreign:?}"
    );
    let record = refresh
        .find_token(&hash_token(&token, None))
        .await
        .unwrap()
        .unwrap();
    assert!(!record.revoked, "the foreign attempt rotated nothing");

    let own = Refresh::new(&token, |_| async { true })
        .in_tenant(&tenant)
        .device_store(&devices)
        .run(&refresh, &cfg, &rng, now())
        .await;
    let (_, next) = own.expect("own tenant, live device");
    assert!(next.is_some(), "rotated");

    revoke_device(&devices, &refresh, &tenant, &d, now())
        .await
        .unwrap();
    let token = issue(&refresh, &rng, Some(d), None).await;
    let refused = Refresh::new(&token, |_| async { true })
        .in_tenant(&tenant)
        .device_store(&devices)
        .run(&refresh, &cfg, &rng, now())
        .await;
    assert!(matches!(refused, Err(RefreshError::DeviceRevoked)));
    let record = refresh
        .find_token(&hash_token(&token, None))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !record.revoked,
        "a refused refresh issues and consumes nothing"
    );
}

/// One refresh checks the tenant, the account status, the device and the
/// binding together, in that order, which no single earlier entry point
/// could.
#[tokio::test]
async fn one_refresh_checks_tenant_status_device_and_binding_together() {
    let (refresh, devices, rng) = (store(), MemoryDeviceStore::new(), MockRng::new(15));
    let tenant = fixture_tenant();
    let d = device_id("laptop");
    devices
        .save(&trusted(&tenant, &d, 1), crate::device::test_now())
        .await
        .unwrap();
    let token = issue(&refresh, &rng, Some(d), Some("ua-laptop")).await;
    let cfg = test_config();
    let (token, tenant_ref, devices_ref) = (token.as_str(), &tenant, &devices);
    let full = move |active: bool, info: &'static str| {
        Refresh::new(token, move |_: &UserId| async move { active })
            .in_tenant(tenant_ref)
            .device_info(Some(info))
            .device_store(devices_ref)
    };

    let inactive = full(false, "ua-laptop")
        .run(&refresh, &cfg, &rng, now())
        .await;
    assert!(
        matches!(inactive, Err(RefreshError::AccountInactive)),
        "{inactive:?}"
    );
    let mismatch = full(true, "ua-other")
        .run(&refresh, &cfg, &rng, now())
        .await;
    assert!(
        matches!(mismatch, Err(RefreshError::DeviceMismatch)),
        "{mismatch:?}"
    );
    revoke_device(&devices, &SpyRefreshStore::new(), &tenant, &d, now())
        .await
        .unwrap();
    let revoked = full(true, "ua-laptop")
        .run(&refresh, &cfg, &rng, now())
        .await;
    assert!(
        matches!(revoked, Err(RefreshError::DeviceRevoked)),
        "{revoked:?}"
    );
    let record = refresh
        .find_token(&hash_token(token, None))
        .await
        .unwrap()
        .unwrap();
    assert!(!record.revoked, "every refusal left the token as it was");
}

/// A token revoked because its device was revoked, presented again, is a
/// stale client and not a thief: it is refused as `Revoked`, the family is
/// not revoked and the compromise hook does not run.
#[tokio::test]
async fn reuse_of_a_token_of_a_revoked_device_is_not_theft() {
    let refresh = SpyRefreshStore::new();
    let (devices, rng) = (MemoryDeviceStore::new(), MockRng::new(13));
    let tenant = fixture_tenant();
    let d = device_id("lost");
    devices
        .save(&trusted(&tenant, &d, 1), crate::device::test_now())
        .await
        .unwrap();
    let plaintext = issue(&refresh, &rng, Some(d), None).await;

    let revoked = revoke_device(&devices, &refresh, &tenant, &d, now())
        .await
        .unwrap();
    assert_eq!(revoked, 1);
    let row = refresh
        .find_token(&hash_token(&plaintext, None))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.revoked_reason,
        Some(RevocationReason::Device),
        "the revocation records why"
    );
    assert_eq!(row.revoked_at, Some(now()), "and when");

    let reuse = Refresh::new(&plaintext, |_| async { true })
        .run(&refresh, &test_config(), &rng, now())
        .await;
    assert!(matches!(reuse, Err(RefreshError::Revoked)), "{reuse:?}");
    assert_eq!(
        refresh.compromises(),
        0,
        "a device revocation presented again is not a compromise"
    );
}

/// The device check also matches the owner: a token whose device has since
/// been claimed by another user is refused, and nothing is rotated.
#[tokio::test]
async fn the_device_check_refuses_a_device_owned_by_another_user() {
    let (refresh, devices, rng) = (store(), MemoryDeviceStore::new(), MockRng::new(14));
    let tenant = fixture_tenant();
    let d = device_id("shared");
    let mut device = trusted(&tenant, &d, 1);
    device.user_id = Some(axess_identity::testing::user("someone-else"));
    devices
        .save(&device, crate::device::test_now())
        .await
        .unwrap();
    let token = issue(&refresh, &rng, Some(d), None).await;

    let refused = Refresh::new(&token, |_| async { true })
        .device_store(&devices)
        .run(&refresh, &test_config(), &rng, now())
        .await;
    assert!(
        matches!(refused, Err(RefreshError::DeviceMismatch)),
        "{refused:?}"
    );
    let record = refresh
        .find_token(&hash_token(&token, None))
        .await
        .unwrap()
        .unwrap();
    assert!(!record.revoked, "a refused refresh consumes nothing");

    // An unowned device, and the user's own, pass.
    for owner in [None, Some(fixture_user())] {
        device.user_id = owner;
        let d2 = device_id(&format!("own-{owner:?}"));
        device.id = d2;
        device.fingerprint_hash = FingerprintHash::from_bytes([owner.is_some() as u8 + 5; 32]);
        devices
            .save(&device, crate::device::test_now())
            .await
            .unwrap();
        let token = issue(&refresh, &rng, Some(d2), None).await;
        let ok = Refresh::new(&token, |_| async { true })
            .device_store(&devices)
            .run(&refresh, &test_config(), &rng, now())
            .await;
        assert!(ok.is_ok(), "{owner:?}: {ok:?}");
    }
}
