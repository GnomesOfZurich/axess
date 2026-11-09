#![cfg(all(feature = "testing", feature = "memory", feature = "device"))]
//! A device revoked through one instance stops the refresh on another
//! instance at once, though that instance's device cache still holds the
//! trusted row.

use axess_core::authn::ids::testing;
use axess_core::session::refresh::{
    IssueRequest, Refresh, RefreshError, RefreshTokenConfig, issue_refresh_token,
};
use axess_core::testing::{MemoryRefreshTokenStore, MockRng};
use axess_core::{
    CachedDeviceStore, Device, DeviceStore, DeviceTrustLevel, FingerprintHash, MemoryDeviceStore,
};
use chrono::Utc;

#[tokio::test]
async fn a_device_revoked_elsewhere_stops_the_refresh_despite_a_cached_trusted_row() {
    let tenant = testing::tenant("t1");
    let user = testing::user("u1");
    let device_id = testing::device("dev-1");
    let now = Utc::now();
    let rng = MockRng::new(4);
    let config = RefreshTokenConfig {
        rotation: true,
        ..Default::default()
    };

    // One backing store, two instances in front of it, each with its cache.
    let backing = MemoryDeviceStore::new();
    let pod_a = CachedDeviceStore::new(backing.clone());
    let pod_b = CachedDeviceStore::new(backing.clone());
    backing
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
                bindings: vec![],
            },
            now,
        )
        .await
        .unwrap();
    let tokens = MemoryRefreshTokenStore::new();
    let (plaintext, _) = issue_refresh_token(
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
    .unwrap();

    // Instance B has the trusted row cached.
    assert!(pod_b.load(&tenant, &device_id).await.unwrap().is_some());
    // The revocation goes through instance A, which clears only its own cache.
    pod_a
        .set_trust_level(&tenant, &device_id, DeviceTrustLevel::Revoked, now)
        .await
        .unwrap();

    let outcome = Refresh::any_tenant(&plaintext, |_| async { true })
        .device_store(&pod_b)
        .run(&tokens, &config, &rng, now)
        .await;

    assert!(
        matches!(outcome, Err(RefreshError::DeviceRevoked)),
        "the refresh went through on a stale cached row: {outcome:?}"
    );
}
