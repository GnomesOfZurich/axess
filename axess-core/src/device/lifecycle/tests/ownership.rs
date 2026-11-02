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

/// A guest request cannot be compared with an owner, so it resolves the
/// fingerprint's device (the alternative is a new row per page view). That
/// is safe only because trust is decided for the user who then logs in:
/// the person behind the guest session is asked for step-up on someone
/// else's Trusted device, and once authenticated is given a device of
/// their own.
#[tokio::test]
async fn a_guest_resolves_the_fingerprint_device_but_inherits_none_of_its_trust() {
    let (svc, _victim, victim_device) = victim_with_trusted_device().await;
    let got = svc
        .ensure_device(&tenant(), None, fp(), at(), || {
            crate::authn::ids::testing::device("unused")
        })
        .await
        .unwrap();
    assert_eq!(
        got, victim_device,
        "a guest cannot be told apart from the owner"
    );

    // The guest then logs in as someone else: the victim's Trusted device
    // demands the same step-up as an unknown one...
    let attacker = crate::authn::ids::testing::user("attacker");
    let guest_device = svc.store().load(&tenant(), &got).await.unwrap().unwrap();
    assert_eq!(guest_device.trust_level, DeviceTrustLevel::Trusted);
    assert!(
        decide_step_up_for_user(&guest_device, &attacker, &StepUpPolicy::default()).is_some(),
        "another user's Trusted device must not skip step-up"
    );
    // ...and the authenticated request gets a device of their own.
    let own = svc
        .ensure_device(&tenant(), Some(&attacker), fp(), at(), || {
            crate::authn::ids::testing::device("attacker-device")
        })
        .await
        .unwrap();
    assert_ne!(own, victim_device);
}

/// A device made during a guest request has no owner. The first user to
/// reach it while authenticated claims it, and from then on another user
/// who resolves the same fingerprint gets a device of their own instead of
/// the claimed one.
#[tokio::test]
async fn a_guest_made_device_is_claimed_by_the_first_user_and_closed_to_the_next() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let guest_device = crate::authn::ids::testing::device("guest-device");
    svc.ensure_device(&tenant(), None, fp(), at(), || guest_device)
        .await
        .unwrap();
    let row = svc.store().load(&tenant(), &guest_device).await.unwrap();
    assert_eq!(row.unwrap().user_id, None, "created unowned");

    let alice = crate::authn::ids::testing::user("alice");
    let got = svc
        .ensure_device(&tenant(), Some(&alice), fp(), at(), || {
            crate::authn::ids::testing::device("unused-a")
        })
        .await
        .unwrap();
    assert_eq!(got, guest_device, "alice reuses the guest-made device");
    let row = svc.store().load(&tenant(), &guest_device).await.unwrap();
    assert_eq!(row.unwrap().user_id, Some(alice), "and now owns it");

    let bob = crate::authn::ids::testing::user("bob");
    let bobs = svc
        .ensure_device(&tenant(), Some(&bob), fp(), at(), || {
            crate::authn::ids::testing::device("bob-device")
        })
        .await
        .unwrap();
    assert_ne!(bobs, guest_device, "bob cannot resolve alice's device");
    let row = svc.store().load(&tenant(), &bobs).await.unwrap().unwrap();
    assert_eq!(row.user_id, Some(bob));
}
