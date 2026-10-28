//! Backend-independent checks of the device-store contract, run against every
//! backend that can be stood up in a test (memory, SQLite, and Valkey when a
//! server is available): tie order, monotonic sightings, revoked rows that
//! stay revoked, revoked rows that can be purged, and sweep decisions that
//! agree to the second.

use std::fmt::Debug;

use chrono::{DateTime, Duration, TimeZone, Utc};

use crate::authn::ids::{DeviceId, TenantId, UserId, testing};
use crate::device::store::{DeviceStore, SweepConfig};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};

/// A fixed instant, `secs` seconds after 2027-01-15.
pub(crate) fn at(secs: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 1, 15, 0, 0, 0).unwrap() + Duration::seconds(secs)
}

pub(crate) fn tenant() -> TenantId {
    testing::tenant("consistency-tenant")
}

pub(crate) fn user() -> UserId {
    testing::user("consistency-user")
}

pub(crate) fn dev_id(label: &str) -> DeviceId {
    testing::device(label)
}

pub(crate) fn device(
    label: &str,
    fp: u8,
    level: DeviceTrustLevel,
    last_seen: DateTime<Utc>,
) -> Device {
    Device {
        id: dev_id(label),
        tenant_id: tenant(),
        user_id: Some(user()),
        trust_level: level,
        fingerprint_hash: FingerprintHash::from_bytes([fp; 32]),
        first_seen_at: last_seen,
        last_seen_at: last_seen,
        revoked_at: (level == DeviceTrustLevel::Revoked).then_some(last_seen),
        demoted_at: None,
        bindings: Vec::new(),
    }
}

fn refresh(family: &str, now: DateTime<Utc>) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.to_string(),
        issued_at: now,
        last_used_at: now,
    }
}

async fn last_seen<S: DeviceStore>(store: &S, label: &str) -> DateTime<Utc> {
    store
        .load(&tenant(), &dev_id(label))
        .await
        .unwrap()
        .unwrap()
        .last_seen_at
}

/// Two devices with one `last_seen_at` are returned smaller id first by
/// every finder, whatever the backend's internal order.
pub(crate) async fn ties_are_broken_by_the_smaller_id<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let seen = at(0);
    let mut a = device("tie-a", 0x31, DeviceTrustLevel::Seen, seen);
    let mut b = device("tie-b", 0x31, DeviceTrustLevel::Seen, seen);
    a.bindings = vec![refresh("tie-family", seen)];
    b.bindings = vec![refresh("tie-family", seen)];
    // Saved in the order that would favour the larger id if order leaked.
    let smaller = a.id.min(b.id);
    let (first, second) = if a.id < b.id { (&b, &a) } else { (&a, &b) };
    store.save(first, seen).await.unwrap();
    store.save(second, seen).await.unwrap();

    let (t, u) = (tenant(), user());
    let listed = store.find_for_user(&t, &u, 10).await.unwrap();
    assert_eq!(listed.first().map(|d| d.id), Some(smaller), "find_for_user");
    let own = store
        .find_by_fingerprint_for_user(&t, &u, &a.fingerprint_hash)
        .await
        .unwrap();
    assert_eq!(
        own.map(|d| d.id),
        Some(smaller),
        "find_by_fingerprint_for_user"
    );
    let family = store
        .find_by_refresh_family(&t, "tie-family")
        .await
        .unwrap();
    assert_eq!(
        family.first().map(|d| d.id),
        Some(smaller),
        "find_by_refresh_family"
    );
}

/// Devices of one tenant that share a fingerprint and have no owner stay
/// findable by that fingerprint until the last of them is gone: the finder
/// answers with the newest sighting (the smaller id on a tie), and neither
/// the lifecycle nor the finder loses the others when one is deleted.
pub(crate) async fn a_shared_fingerprint_stays_findable_while_any_device_carries_it<S>(store: S)
where
    S: DeviceStore + Clone,
    S::Error: Debug,
{
    use crate::device::lifecycle::DeviceLifecycleService;

    let t = tenant();
    let fingerprint = FingerprintHash::from_bytes([0x32; 32]);
    let mut older = device("share-old", 0x32, DeviceTrustLevel::Seen, at(10));
    let mut twin_x = device("share-x", 0x32, DeviceTrustLevel::Seen, at(30));
    let mut twin_y = device("share-y", 0x32, DeviceTrustLevel::Seen, at(30));
    for d in [&mut older, &mut twin_x, &mut twin_y] {
        d.user_id = None;
    }
    // The tied pair, smaller id first, then the older one.
    let (first, second) = if twin_x.id < twin_y.id {
        (twin_x.clone(), twin_y.clone())
    } else {
        (twin_y.clone(), twin_x.clone())
    };
    // Saved so that the device a "last writer wins" index would name is the
    // one that is deleted first.
    for d in [&older, &second, &first] {
        store.save(d, at(30)).await.unwrap();
    }

    let found = |store: S| async move {
        store
            .find_by_fingerprint(&t, &fingerprint)
            .await
            .unwrap()
            .map(|d| d.id)
    };
    assert_eq!(found(store.clone()).await, Some(first.id), "tie order");

    // The lifecycle recognises the guest device instead of minting one. The
    // sighting time is before every `last_seen_at`, so it moves nothing.
    let service = DeviceLifecycleService::new(store.clone());
    let id = service
        .ensure_device(&t, None, fingerprint, at(0), || {
            dev_id("must-not-be-minted")
        })
        .await
        .unwrap();
    assert_eq!(id, first.id);

    store.delete(&t, &first.id).await.unwrap();
    assert_eq!(
        found(store.clone()).await,
        Some(second.id),
        "after the first is deleted"
    );
    let id = service
        .ensure_device(&t, None, fingerprint, at(0), || {
            dev_id("must-not-be-minted")
        })
        .await
        .unwrap();
    assert_eq!(id, second.id, "the lifecycle does not mint a new device");

    store.delete(&t, &second.id).await.unwrap();
    assert_eq!(found(store.clone()).await, Some(older.id), "the last one");
    store.delete(&t, &older.id).await.unwrap();
    assert_eq!(found(store.clone()).await, None, "none left");
}

/// A sighting moves `last_seen_at` forward only, and never touches a
/// revoked row.
pub(crate) async fn a_sighting_never_rewinds_and_skips_a_revoked_row<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("sight"));
    let base = at(10_000);
    store
        .save(&device("sight", 0x41, DeviceTrustLevel::Seen, base), base)
        .await
        .unwrap();

    store
        .record_sighting(&t, &id, base - Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(
        last_seen(&store, "sight").await,
        base,
        "an older sighting is ignored"
    );
    store
        .record_sighting(&t, &id, base + Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(last_seen(&store, "sight").await, base + Duration::hours(1));

    store
        .set_trust_level(
            &t,
            &id,
            DeviceTrustLevel::Revoked,
            base + Duration::hours(2),
        )
        .await
        .unwrap();
    store
        .record_sighting(&t, &id, base + Duration::hours(3))
        .await
        .unwrap();
    assert_eq!(
        last_seen(&store, "sight").await,
        base + Duration::hours(1),
        "a revoked row is not touched"
    );
    assert!(
        store
            .record_sighting(&t, &dev_id("absent"), base)
            .await
            .is_err(),
        "a missing device is still an error"
    );
}

/// A save of a device that was loaded before a revocation leaves the row
/// revoked; reinstating takes an explicit trust change.
pub(crate) async fn a_save_never_un_revokes<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("stale"));
    let base = at(20_000);
    let stale = device("stale", 0x51, DeviceTrustLevel::Trusted, base);
    store.save(&stale, base).await.unwrap();
    let revoked_at = base + Duration::minutes(5);
    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Revoked, revoked_at)
        .await
        .unwrap();

    store
        .save(&stale, base + Duration::minutes(6))
        .await
        .unwrap();
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(
        row.revoked_at.map(|r| r.timestamp()),
        Some(revoked_at.timestamp())
    );

    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Seen, base + Duration::minutes(7))
        .await
        .unwrap();
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(
        row.trust_level,
        DeviceTrustLevel::Seen,
        "explicit reinstatement works"
    );
}

/// A revoked device saved with no revocation time is stamped with the
/// write time and is purged once the grace has passed.
pub(crate) async fn a_revoked_save_without_a_time_is_stamped_and_purged<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("unstamped"));
    let saved = at(30_000);
    let mut d = device("unstamped", 0x61, DeviceTrustLevel::Revoked, saved);
    d.revoked_at = None;
    store.save(&d, saved).await.unwrap();
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(
        row.revoked_at.map(|r| r.timestamp()),
        Some(saved.timestamp())
    );

    let grace = SweepConfig::default().revoked_grace;
    let early = store.sweep(&t, saved + grace).await.unwrap();
    assert_eq!(
        early.revoked_purged, 0,
        "not purged until the grace has passed"
    );
    let counts = store
        .sweep(&t, saved + grace + Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(counts.revoked_purged, 1);
    assert!(store.load(&t, &id).await.unwrap().is_none());
}

/// The sweep configuration [`sweep_decisions_agree_to_the_second`] needs: a
/// trusted-idle window of ten seconds.
pub(crate) fn tight_config() -> SweepConfig {
    SweepConfig::builder()
        .trusted_idle(Duration::seconds(10))
        .build()
        .unwrap()
}

/// A trusted-idle window of ten seconds: a row last seen at 0.9 s and swept
/// at 10.95 s is not yet due (whole seconds: 10 is not more than 10), on
/// every backend; at 11.0 s it is.
///
/// `store` must have been built with [`tight_config`].
pub(crate) async fn sweep_decisions_agree_to_the_second<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let cfg = tight_config();
    let t = tenant();
    let base = at(40_000);
    let last = base + Duration::milliseconds(900);
    store
        .save(
            &device("subsec", 0x71, DeviceTrustLevel::Trusted, last),
            base,
        )
        .await
        .unwrap();

    let not_yet = base + Duration::milliseconds(10_950);
    assert_eq!(
        cfg.level_after(DeviceTrustLevel::Trusted, last, None, not_yet),
        DeviceTrustLevel::Trusted
    );
    let counts = store.sweep(&t, not_yet).await.unwrap();
    assert_eq!(
        counts.trusted_to_seen, 0,
        "10 whole seconds is not more than 10"
    );
    let counts = store.sweep(&t, base + Duration::seconds(11)).await.unwrap();
    assert_eq!(counts.trusted_to_seen, 1);
}
