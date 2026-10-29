//! What the lifecycle does with a revoked device, with a device revoked
//! after the load, and with two first sightings of one fingerprint that race.

use super::races::AfterLoad;
use super::*;
use crate::device::store::MemoryDeviceStore;
use chrono::TimeZone;

fn at(minutes: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 9, 0, 0).unwrap() + chrono::Duration::minutes(minutes)
}

fn tenant() -> TenantId {
    crate::authn::ids::testing::tenant("tenant-1")
}

fn user() -> UserId {
    crate::authn::ids::testing::user("user-1")
}

fn fingerprint() -> FingerprintHash {
    FingerprintHash::from_bytes([5u8; 32])
}

fn device_at(label: &str, level: DeviceTrustLevel, owner: Option<UserId>, seen: i64) -> Device {
    Device {
        id: crate::authn::ids::testing::device(label),
        tenant_id: tenant(),
        user_id: owner,
        trust_level: level,
        fingerprint_hash: fingerprint(),
        first_seen_at: at(seen),
        last_seen_at: at(seen),
        revoked_at: (level == DeviceTrustLevel::Revoked).then_some(at(seen)),
        demoted_at: None,
        bindings: Vec::new(),
    }
}

/// A `Seen` or `Trusted` device revoked after the lifecycle loaded it is
/// reported as `Revoked` and its `last_seen_at` is not bumped.
async fn revoked_after_the_load_is_reported<S: DeviceStore>(store: S, level: DeviceTrustLevel) {
    let racing = AfterLoad::new(store);
    let device = device_at("loaded", level, Some(user()), 0);
    racing.save(&device, at(0)).await.unwrap();
    racing.revoke_after_next_load(tenant(), device.id, at(5));

    let outcome = DeviceLifecycleService::new(racing.clone())
        .promote_on_authn(&tenant(), &device.id, at(6))
        .await
        .unwrap();

    assert_eq!(
        outcome,
        Some(DeviceTrustLevel::Revoked),
        "{level:?} revoked meanwhile is reported as Revoked"
    );
    let row = racing
        .inner
        .load(&tenant(), &device.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(row.last_seen_at, at(0), "last_seen_at is not bumped");
}

#[tokio::test]
async fn a_seen_device_revoked_after_the_load_is_reported_revoked() {
    revoked_after_the_load_is_reported(MemoryDeviceStore::new(), DeviceTrustLevel::Seen).await;
}

#[tokio::test]
async fn a_trusted_device_revoked_after_the_load_is_reported_revoked() {
    revoked_after_the_load_is_reported(MemoryDeviceStore::new(), DeviceTrustLevel::Trusted).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_a_seen_device_revoked_after_the_load_is_reported_revoked() {
    revoked_after_the_load_is_reported(
        crate::device::storage::sqlite::tests_support::store().await,
        DeviceTrustLevel::Seen,
    )
    .await;
}

/// A request whose fingerprint matches a revoked device gets a new `Unknown`
/// device: the revoked row is neither reused nor touched.
#[tokio::test]
async fn a_revoked_device_is_not_reused_or_touched() {
    let store = MemoryDeviceStore::new();
    let revoked = device_at("revoked", DeviceTrustLevel::Revoked, Some(user()), 0);
    store.save(&revoked, at(0)).await.unwrap();
    let svc = DeviceLifecycleService::new(store.clone());
    let fresh = crate::authn::ids::testing::device("fresh");

    let id = svc
        .ensure_device(&tenant(), Some(&user()), fingerprint(), at(30), || fresh)
        .await
        .unwrap();

    assert_eq!(id, fresh, "a new device was minted");
    let new = store.load(&tenant(), &id).await.unwrap().unwrap();
    assert_eq!(new.trust_level, DeviceTrustLevel::Unknown);
    let old = store.load(&tenant(), &revoked.id).await.unwrap().unwrap();
    assert_eq!(old.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(old.last_seen_at, at(0), "the revoked row is not touched");

    // And the lookup now names the new device.
    let again = svc
        .ensure_device(&tenant(), Some(&user()), fingerprint(), at(40), || {
            panic!("the new device is found")
        })
        .await
        .unwrap();
    assert_eq!(again, fresh);
}

/// An unowned revoked device cannot be claimed by an authenticated user.
#[tokio::test]
async fn an_unowned_revoked_device_cannot_be_claimed() {
    let store = MemoryDeviceStore::new();
    let revoked = device_at("orphan", DeviceTrustLevel::Revoked, None, 0);
    store.save(&revoked, at(0)).await.unwrap();
    let svc = DeviceLifecycleService::new(store.clone());
    let fresh = crate::authn::ids::testing::device("claimant-own");

    let id = svc
        .ensure_device(&tenant(), Some(&user()), fingerprint(), at(30), || fresh)
        .await
        .unwrap();

    assert_eq!(id, fresh);
    let old = store.load(&tenant(), &revoked.id).await.unwrap().unwrap();
    assert_eq!(old.user_id, None, "the revoked device has no new owner");
}

/// Two first sightings of one fingerprint that both miss and both create
/// settle on one device: the one that sorts later removes itself and returns
/// the other's id.
#[tokio::test]
async fn racing_first_sightings_settle_on_one_device() {
    let racing = AfterLoad::new(MemoryDeviceStore::new());
    let a = crate::authn::ids::testing::device("racer-a");
    let b = crate::authn::ids::testing::device("racer-b");
    let (small, large) = if a < b { (a, b) } else { (b, a) };

    // Guest requests, whose only lookup is the one the hook follows. The
    // rival creates the smaller-id device while the lookup of the other
    // request is in flight, so that request then creates the larger one.
    let rival = DeviceLifecycleService::new(racing.inner.clone());
    racing.after_next_find(Box::new(move || {
        Box::pin(async move {
            let id = rival
                .ensure_device(&tenant(), None, fingerprint(), at(0), || small)
                .await
                .unwrap();
            assert_eq!(id, small);
        })
    }));

    let svc = DeviceLifecycleService::new(racing.clone());
    let id = svc
        .ensure_device(&tenant(), None, fingerprint(), at(0), || large)
        .await
        .unwrap();

    assert_eq!(
        id, small,
        "the request that sorts later returns the other id"
    );
    assert_eq!(racing.inner.len(), 1, "one device remains");
    assert!(
        racing
            .inner
            .load(&tenant(), &small)
            .await
            .unwrap()
            .is_some()
    );
}
