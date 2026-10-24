//! A device is reused only by the user who owns it.

use super::*;
use crate::authn::service::{StepUpPolicy, decide_step_up_for_user};
use crate::device::store::MemoryDeviceStore;
use chrono::TimeZone;

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 9, 0, 0).unwrap()
}

fn fp() -> FingerprintHash {
    FingerprintHash::from_bytes([7u8; 32])
}

fn tenant() -> TenantId {
    crate::authn::ids::testing::tenant("tenant-1")
}

/// The victim's Trusted device, as stored.
async fn victim_with_trusted_device()
-> (DeviceLifecycleService<MemoryDeviceStore>, UserId, DeviceId) {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let victim = crate::authn::ids::testing::user("victim");
    let id = crate::authn::ids::testing::device("victim-device");
    svc.ensure_device(&tenant(), Some(&victim), fp(), at(), || id)
        .await
        .unwrap();
    svc.store()
        .set_trust_level(&tenant(), &id, DeviceTrustLevel::Trusted, at())
        .await
        .unwrap();
    (svc, victim, id)
}

#[tokio::test]
async fn another_user_with_the_same_fingerprint_gets_a_new_unknown_device() {
    let (svc, _victim, victim_device) = victim_with_trusted_device().await;
    let attacker = crate::authn::ids::testing::user("attacker");
    let fresh = crate::authn::ids::testing::device("attacker-device");

    let got = svc
        .ensure_device(&tenant(), Some(&attacker), fp(), at(), || fresh)
        .await
        .unwrap();

    assert_ne!(got, victim_device, "must not inherit the victim's device");
    let device = svc.store().load(&tenant(), &got).await.unwrap().unwrap();
    assert_eq!(device.trust_level, DeviceTrustLevel::Unknown);
    assert_eq!(device.user_id, Some(attacker));
    assert!(
        decide_step_up_for_user(&device, &attacker, &StepUpPolicy::default()).is_some(),
        "an unknown device must ask for step-up"
    );
}

#[tokio::test]
async fn each_user_finds_their_own_device_again() {
    let (svc, victim, victim_device) = victim_with_trusted_device().await;
    let attacker = crate::authn::ids::testing::user("attacker");
    let first = svc
        .ensure_device(&tenant(), Some(&attacker), fp(), at(), || {
            crate::authn::ids::testing::device("attacker-device")
        })
        .await
        .unwrap();

    // The attacker comes back: same device, no new row.
    let again = svc
        .ensure_device(&tenant(), Some(&attacker), fp(), at(), || {
            crate::authn::ids::testing::device("unused-1")
        })
        .await
        .unwrap();
    assert_eq!(again, first);

    // The victim comes back: still their own Trusted device.
    let back = svc
        .ensure_device(&tenant(), Some(&victim), fp(), at(), || {
            crate::authn::ids::testing::device("unused-2")
        })
        .await
        .unwrap();
    assert_eq!(back, victim_device);
    let device = svc.store().load(&tenant(), &back).await.unwrap().unwrap();
    assert_eq!(device.trust_level, DeviceTrustLevel::Trusted);
}

#[tokio::test]
async fn a_guest_request_still_resolves_the_fingerprint_device() {
    let (svc, _victim, victim_device) = victim_with_trusted_device().await;
    let got = svc
        .ensure_device(&tenant(), None, fp(), at(), || {
            crate::authn::ids::testing::device("unused")
        })
        .await
        .unwrap();
    assert_eq!(got, victim_device);
}
