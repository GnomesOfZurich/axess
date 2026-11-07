#![cfg(all(feature = "memory", feature = "device"))]
//! A user who arrives without a valid device cookie, login after login, does
//! not add a device row per login without bound.

use axess_core::authn::ids::{DeviceId, TenantId, UserId, testing};
use axess_core::device::DEFAULT_MAX_UNKNOWN_DEVICES_PER_USER;
use axess_core::{
    DeviceLifecycleService, DeviceRequest, DeviceStore, DeviceTrustLevel, FingerprintHash,
    MemoryDeviceStore,
};
use axess_rng::SystemRng;
use chrono::{Duration, TimeZone, Utc};

fn tenant() -> TenantId {
    testing::tenant("tenant-1")
}

fn user(label: &str) -> UserId {
    testing::user(label)
}

async fn cookieless_login(
    svc: &DeviceLifecycleService<MemoryDeviceStore>,
    who: &UserId,
    n: i64,
) -> DeviceId {
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap() + Duration::seconds(n);
    let tenant = tenant();
    let request = DeviceRequest {
        tenant: &tenant,
        user: Some(who),
        fingerprint: FingerprintHash::from_bytes([7; 32]),
        presented: None,
        session_device: None,
    };
    svc.resolve_proven(request, now, &SystemRng, || {
        testing::device(&format!("device-{n}"))
    })
    .await
    .unwrap()
    .expect("a user always resolves to a device")
    .id
}

#[tokio::test]
async fn cookieless_logins_do_not_grow_a_users_devices_without_bound() {
    let store = MemoryDeviceStore::new();
    let svc = DeviceLifecycleService::new(store.clone());
    let alice = user("alice");

    for n in 0..300 {
        cookieless_login(&svc, &alice, n).await;
    }

    let held = store.find_for_user(&tenant(), &alice, 1000).await.unwrap();
    assert!(
        held.len() <= DEFAULT_MAX_UNKNOWN_DEVICES_PER_USER,
        "{} devices after 300 cookieless logins",
        held.len()
    );
}

#[tokio::test]
async fn the_oldest_unknown_devices_go_first_and_other_users_are_untouched() {
    let store = MemoryDeviceStore::new();
    let svc = DeviceLifecycleService::new(store.clone()).with_max_unknown_devices_per_user(3);
    let alice = user("alice");
    let bob = user("bob");
    let bobs = cookieless_login(&svc, &bob, 0).await;

    let first = cookieless_login(&svc, &alice, 1).await;
    for n in 2..=4 {
        cookieless_login(&svc, &alice, n).await;
    }

    assert!(
        store.load(&tenant(), &first).await.unwrap().is_none(),
        "the least recently seen device was kept"
    );
    assert_eq!(
        store
            .find_for_user(&tenant(), &alice, 10)
            .await
            .unwrap()
            .len(),
        3
    );
    assert!(store.load(&tenant(), &bobs).await.unwrap().is_some());
}

#[tokio::test]
async fn a_device_the_user_was_recognised_on_is_never_evicted() {
    let store = MemoryDeviceStore::new();
    let svc = DeviceLifecycleService::new(store.clone()).with_max_unknown_devices_per_user(2);
    let alice = user("alice");
    let kept = cookieless_login(&svc, &alice, 0).await;
    store
        .set_trust_level(&tenant(), &kept, DeviceTrustLevel::Seen, Utc::now())
        .await
        .unwrap();

    for n in 1..=10 {
        cookieless_login(&svc, &alice, n).await;
    }

    let device = store.load(&tenant(), &kept).await.unwrap().expect("kept");
    assert_eq!(device.trust_level, DeviceTrustLevel::Seen);
}
