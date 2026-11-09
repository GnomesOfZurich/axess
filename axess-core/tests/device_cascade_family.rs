#![cfg(all(feature = "testing", feature = "memory", feature = "device"))]
//! The family-compromise handler revokes the device and every refresh token
//! bound to it, whatever family the token is in.

use axess_core::authn::ids::testing;
use axess_core::session::refresh::{
    IssueRequest, Refresh, RefreshError, RefreshTokenConfig, issue_refresh_token,
};
use axess_core::testing::{MemoryRefreshTokenStore, MockRng};
use axess_core::{
    Device, DeviceBinding, DeviceStore, DeviceTrustLevel, FingerprintHash, MemoryDeviceStore,
    cascade_revoke_by_refresh_family_and_tokens,
};
use chrono::Utc;

#[tokio::test]
async fn compromise_of_one_family_ends_the_devices_other_families() {
    let tenant = testing::tenant("t1");
    let user = testing::user("u1");
    let device_id = testing::device("dev-1");
    let now = Utc::now();
    let rng = MockRng::new(4);
    let config = RefreshTokenConfig {
        rotation: true,
        ..Default::default()
    };
    let tokens = MemoryRefreshTokenStore::new();
    let mut issued = Vec::new();
    for _ in 0..2 {
        issued.push(
            issue_refresh_token(
                IssueRequest {
                    user_id: &user,
                    tenant_id: &tenant,
                    device_info: None,
                    family_id: None,
                    device_id: Some(device_id),
                },
                &config,
                &tokens,
                &rng,
                now,
            )
            .await
            .unwrap(),
        );
    }
    let compromised = issued[0].1.family_id.expect("a family").to_string();
    let other = issued[1].0.clone();

    let devices = MemoryDeviceStore::new();
    devices
        .save(
            &Device {
                id: device_id,
                tenant_id: tenant,
                user_id: Some(user),
                trust_level: DeviceTrustLevel::Trusted,
                fingerprint_hash: FingerprintHash::from_bytes([7; 32]),
                first_seen_at: now,
                last_seen_at: now,
                revoked_at: None,
                demoted_at: None,
                bindings: vec![DeviceBinding::Refresh {
                    family_id: compromised.clone(),
                    issued_at: now,
                    last_used_at: now,
                }],
            },
            now,
        )
        .await
        .unwrap();

    let revoked =
        cascade_revoke_by_refresh_family_and_tokens(&devices, &tokens, &tenant, &compromised, now)
            .await
            .unwrap();

    assert_eq!(revoked, 1, "the device was revoked");
    let stored = devices.load(&tenant, &device_id).await.unwrap().unwrap();
    assert_eq!(stored.trust_level, DeviceTrustLevel::Revoked);
    let outcome = Refresh::any_tenant(&other, |_| async { true })
        .run(&tokens, &config, &rng, now)
        .await;
    assert!(
        matches!(outcome, Err(RefreshError::Revoked)),
        "the device's other family still refreshes: {outcome:?}"
    );
}
