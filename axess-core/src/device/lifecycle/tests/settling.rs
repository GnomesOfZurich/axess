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

/// Arm `racing` so `device` is revoked right after the next fingerprint
/// lookup returns it.
fn revoke_after_next_find(racing: &AfterLoad<MemoryDeviceStore>, device: DeviceId, when: i64) {
    let inner = racing.inner.clone();
    racing.after_next_find(Box::new(move || {
        Box::pin(async move {
            inner
                .set_trust_level(&tenant(), &device, DeviceTrustLevel::Revoked, at(when))
                .await
                .unwrap();
        })
    }));
}

/// The row of `device` after a race: still revoked, never sighted.
async fn assert_untouched_and_revoked(store: &MemoryDeviceStore, device: &DeviceId) {
    let row = store.load(&tenant(), device).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(row.last_seen_at, at(0), "the revoked row is not sighted");
}

/// A device the lookup found but which is revoked before the sighting is
/// recorded is not served: the request gets a new `Unknown` device.
async fn ensure_device_does_not_serve_a_device_revoked_after_the_find(owner: Option<UserId>) {
    let racing = AfterLoad::new(MemoryDeviceStore::new());
    let device = device_at("found", DeviceTrustLevel::Seen, owner, 0);
    racing.save(&device, at(0)).await.unwrap();
    revoke_after_next_find(&racing, device.id, 5);
    let fresh = crate::authn::ids::testing::device("fresh");

    let id = DeviceLifecycleService::new(racing.clone())
        .ensure_device(&tenant(), owner.as_ref(), fingerprint(), at(6), || fresh)
        .await
        .unwrap();

    assert_eq!(id, fresh, "a device revoked after the find is not served");
    assert_untouched_and_revoked(&racing.inner, &device.id).await;
}

#[tokio::test]
async fn ensure_device_for_a_guest_does_not_serve_a_device_revoked_after_the_find() {
    ensure_device_does_not_serve_a_device_revoked_after_the_find(None).await;
}

#[tokio::test]
async fn ensure_device_for_a_user_does_not_serve_a_device_revoked_after_the_find() {
    ensure_device_does_not_serve_a_device_revoked_after_the_find(Some(user())).await;
}

/// A device that proves itself with its token but is revoked between the load
/// and the sighting is not served: the request gets a new device, and the
/// revoked row is left as it is.
#[tokio::test]
async fn a_proven_device_revoked_after_the_load_is_not_served() {
    use crate::device::proof::{DeviceToken, PresentedDevice};
    let rng = crate::testing::mock_random::MockRng::new(3);
    let racing = AfterLoad::new(MemoryDeviceStore::new());
    let token = DeviceToken::mint(&rng);
    let mut device = device_at("proven", DeviceTrustLevel::Seen, Some(user()), 0);
    device.bindings = vec![token.binding(at(0))];
    racing.save(&device, at(0)).await.unwrap();
    racing.revoke_after_next_load(tenant(), device.id, at(5));
    let fresh = crate::authn::ids::testing::device("fresh");
    let presented = PresentedDevice {
        id: device.id,
        token,
    };

    let resolved = DeviceLifecycleService::new(racing.clone())
        .resolve_proven(
            DeviceRequest {
                tenant: &tenant(),
                user: Some(&user()),
                fingerprint: fingerprint(),
                presented: Some(&presented),
                session_device: None,
            },
            at(6),
            &rng,
            || fresh,
        )
        .await
        .unwrap()
        .expect("a device");

    assert_eq!(resolved.id, fresh, "the revoked device is never served");
    assert!(resolved.issued.is_some(), "the new device gets a token");
    assert_untouched_and_revoked(&racing.inner, &device.id).await;
}

/// The device a session was bound to, revoked between the load and the
/// sighting, is not kept either.
#[tokio::test]
async fn a_session_device_revoked_after_the_load_is_not_served() {
    let rng = crate::testing::mock_random::MockRng::new(4);
    let racing = AfterLoad::new(MemoryDeviceStore::new());
    let device = device_at("bound", DeviceTrustLevel::Trusted, Some(user()), 0);
    racing.save(&device, at(0)).await.unwrap();
    racing.revoke_after_next_load(tenant(), device.id, at(5));
    let fresh = crate::authn::ids::testing::device("fresh");

    let resolved = DeviceLifecycleService::new(racing.clone())
        .resolve_proven(
            DeviceRequest {
                tenant: &tenant(),
                user: Some(&user()),
                fingerprint: fingerprint(),
                presented: None,
                session_device: Some(&device.id),
            },
            at(6),
            &rng,
            || fresh,
        )
        .await
        .unwrap()
        .expect("a device");

    assert_eq!(resolved.id, fresh, "the revoked device is never served");
    assert_untouched_and_revoked(&racing.inner, &device.id).await;
}

/// Two first sightings that both miss and both create, where the request
/// that creates second would sort first (its sighting is newer): both
/// requests end on the first one's device and no second row is left. The
/// rival creates its device while this request's last lookup is in flight,
/// so this request's create is the one that has to notice it.
async fn racing_creates_never_leave_two_devices<S>(store: S, owner: Option<UserId>)
where
    S: DeviceStore,
    S::Error: std::fmt::Debug,
{
    let racing = AfterLoad::new(store);
    let rival_id = crate::authn::ids::testing::device("rival");
    let mine = crate::authn::ids::testing::device("mine");
    let rival = DeviceLifecycleService::new(racing.inner.clone());
    let create_rival: super::races::Hook = Box::new(move || {
        Box::pin(async move {
            let id = rival
                .ensure_device(&tenant(), owner.as_ref(), fingerprint(), at(0), || rival_id)
                .await
                .unwrap();
            assert_eq!(id, rival_id);
        })
    });
    // An owned request looks up twice (its own device, then any device);
    // the rival lands after the last of those lookups.
    if owner.is_some() {
        let re_arm = racing.clone();
        racing.after_next_find(Box::new(move || {
            Box::pin(async move { re_arm.after_next_find(create_rival) })
        }));
    } else {
        racing.after_next_find(create_rival);
    }

    let id = DeviceLifecycleService::new(racing.clone())
        .ensure_device(&tenant(), owner.as_ref(), fingerprint(), at(1), || mine)
        .await
        .unwrap();

    assert_eq!(id, rival_id, "the later creator returns the first one's id");
    assert!(
        racing.inner.load(&tenant(), &mine).await.unwrap().is_none(),
        "no second device is left behind"
    );
    let kept = racing.inner.load(&tenant(), &rival_id).await.unwrap();
    assert!(kept.is_some(), "the first device remains");
}

#[tokio::test]
async fn memory_racing_guest_creates_never_leave_two_devices() {
    racing_creates_never_leave_two_devices(MemoryDeviceStore::new(), None).await;
}

#[tokio::test]
async fn memory_racing_user_creates_never_leave_two_devices() {
    racing_creates_never_leave_two_devices(MemoryDeviceStore::new(), Some(user())).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_racing_guest_creates_never_leave_two_devices() {
    racing_creates_never_leave_two_devices(
        crate::device::storage::sqlite::tests_support::store().await,
        None,
    )
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_racing_user_creates_never_leave_two_devices() {
    racing_creates_never_leave_two_devices(
        crate::device::storage::sqlite::tests_support::store().await,
        Some(user()),
    )
    .await;
}

/// Many truly concurrent first sightings of one fingerprint by one user
/// return one id and leave one row, round after round.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_sightings_create_one_device() {
    for round in 0..50u8 {
        let store = MemoryDeviceStore::new();
        let svc = DeviceLifecycleService::new(store.clone());
        let fp = FingerprintHash::from_bytes([round; 32]);
        let tasks: Vec<_> = (0..8u8)
            .map(|i| {
                let svc = svc.clone();
                let label = format!("racer-{round}-{i}");
                tokio::spawn(async move {
                    svc.ensure_device(&tenant(), Some(&user()), fp, at(0), || {
                        crate::authn::ids::testing::device(&label)
                    })
                    .await
                    .unwrap()
                })
            })
            .collect();
        let mut ids = Vec::new();
        for task in tasks {
            ids.push(task.await.unwrap());
        }
        ids.dedup();
        assert_eq!(ids.len(), 1, "round {round}: every request got the same id");
        assert_eq!(store.len(), 1, "round {round}: one device remains");
    }
}
