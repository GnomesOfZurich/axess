//! Sighting writes are throttled, and a user's own device is found however
//! many devices the user has.

use super::*;
use crate::authn::ids::testing;
use crate::device::store::MemoryDeviceStore;
use chrono::{Duration, TimeZone};

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 9, 0, 0).unwrap()
}

fn fp(byte: u8) -> FingerprintHash {
    FingerprintHash::from_bytes([byte; 32])
}

async fn last_seen(
    svc: &DeviceLifecycleService<MemoryDeviceStore>,
    id: &DeviceId,
) -> DateTime<Utc> {
    svc.store()
        .load(&testing::tenant("t"), id)
        .await
        .unwrap()
        .unwrap()
        .last_seen_at
}

#[tokio::test]
async fn a_known_device_is_written_once_per_granularity_window() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (tenant, user) = (testing::tenant("t"), testing::user("u"));
    let id = testing::device("d");
    svc.ensure_device(&tenant, Some(&user), fp(1), at(), || id)
        .await
        .unwrap();

    // Four minutes later: inside the five-minute window, no write.
    let soon = at() + Duration::minutes(4);
    svc.ensure_device(&tenant, Some(&user), fp(1), soon, || unreachable!())
        .await
        .unwrap();
    assert_eq!(last_seen(&svc, &id).await, at());

    // Five minutes after the recorded sighting the window has passed.
    let later = at() + Duration::minutes(5);
    svc.ensure_device(&tenant, Some(&user), fp(1), later, || unreachable!())
        .await
        .unwrap();
    assert_eq!(last_seen(&svc, &id).await, later);
}

#[tokio::test]
async fn zero_granularity_records_every_sighting() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new())
        .with_sighting_granularity(Duration::zero());
    let (tenant, user) = (testing::tenant("t"), testing::user("u"));
    let id = testing::device("d");
    svc.ensure_device(&tenant, Some(&user), fp(1), at(), || id)
        .await
        .unwrap();
    let next = at() + Duration::seconds(1);
    svc.ensure_device(&tenant, Some(&user), fp(1), next, || unreachable!())
        .await
        .unwrap();
    assert_eq!(last_seen(&svc, &id).await, next);
}

fn device_of(user: UserId, id: &str, fingerprint: FingerprintHash, seen: DateTime<Utc>) -> Device {
    Device {
        id: testing::device(id),
        tenant_id: testing::tenant("t"),
        user_id: Some(user),
        trust_level: DeviceTrustLevel::Seen,
        fingerprint_hash: fingerprint,
        first_seen_at: seen,
        last_seen_at: seen,
        revoked_at: None,
        demoted_at: None,
        bindings: Vec::new(),
    }
}

/// A user with more devices than the old scan limit, whose matching device
/// is the least recently seen, behind a fingerprint another user's device
/// also carries. The matching device must be found, not duplicated.
#[tokio::test]
async fn an_old_device_beyond_the_scan_limit_is_still_found() {
    let store = MemoryDeviceStore::new();
    let svc = DeviceLifecycleService::new(store.clone());
    let (tenant, user) = (testing::tenant("t"), testing::user("u"));
    let shared = fp(9);

    // The user's own device with the shared fingerprint is the oldest.
    store
        .save(
            &device_of(user, "mine", shared, at() - Duration::days(30)),
            at(),
        )
        .await
        .unwrap();
    // 150 newer devices push it past the 100 most recent.
    for i in 0..150u8 {
        let seen = at() - Duration::days(1) + Duration::seconds(i64::from(i));
        store
            .save(
                &device_of(user, &format!("other-{i}"), fp(100 + (i % 100)), seen),
                at(),
            )
            .await
            .unwrap();
    }
    // Another user's device now owns the fingerprint index entry.
    let stranger = testing::user("stranger");
    store
        .save(
            &device_of(stranger, "theirs", shared, at() - Duration::days(2)),
            at(),
        )
        .await
        .unwrap();
    let before = store.len();

    let got = svc
        .ensure_device(&tenant, Some(&user), shared, at(), || {
            testing::device("new")
        })
        .await
        .unwrap();

    assert_eq!(
        got,
        testing::device("mine"),
        "the user's own device is reused"
    );
    assert_eq!(store.len(), before, "no device is minted");
}

/// A request that arrives with a time older than the recorded sighting (an
/// out-of-order arrival, or a node whose clock lags) records nothing.
#[tokio::test]
async fn an_older_request_does_not_move_the_last_sighting_back() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (tenant, user) = (testing::tenant("t"), testing::user("u"));
    let id = testing::device("d");
    svc.ensure_device(&tenant, Some(&user), fp(1), at(), || id)
        .await
        .unwrap();
    let later = at() + Duration::hours(2);
    svc.ensure_device(&tenant, Some(&user), fp(1), later, || unreachable!())
        .await
        .unwrap();
    assert_eq!(last_seen(&svc, &id).await, later);

    let lagging = at() + Duration::hours(1);
    svc.ensure_device(&tenant, Some(&user), fp(1), lagging, || unreachable!())
        .await
        .unwrap();
    assert_eq!(
        last_seen(&svc, &id).await,
        later,
        "the later sighting stands"
    );
}
