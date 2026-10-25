//! Conditional writes, missing-device errors, duplicate refresh families,
//! the Revoked filter ahead of the limit, and the retention ladder, all
//! against a real in-memory SQLite database.

use super::*;
use crate::device::store::{BindingsUpdate, OwnerClaim, TrustTransition};

fn refresh(family: &str) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.into(),
        issued_at: now_at(10, 0),
        last_used_at: now_at(10, 0),
    }
}

async fn saved(store: &SqliteDeviceStore, level: DeviceTrustLevel) -> (TenantId, DeviceId) {
    let (t, u, d) = ids();
    let mut device = build_device(&t, Some(&u), &d, 0x11, vec![]);
    device.trust_level = level;
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();
    (t, d)
}

#[tokio::test]
async fn set_trust_level_if_applies_only_from_the_expected_level() {
    let store = fresh_store().await;
    let (t, d) = saved(&store, DeviceTrustLevel::Unknown).await;

    let got = store
        .set_trust_level_if(
            &t,
            &d,
            DeviceTrustLevel::Unknown,
            DeviceTrustLevel::Seen,
            now_at(11, 0),
        )
        .await
        .unwrap();
    assert_eq!(got, TrustTransition::Applied);
    assert_eq!(
        store.load(&t, &d).await.unwrap().unwrap().trust_level,
        DeviceTrustLevel::Seen
    );

    // Revoked meanwhile: the same promotion is now refused, and the
    // revocation and its timestamp stay.
    store
        .set_trust_level(&t, &d, DeviceTrustLevel::Revoked, now_at(12, 0))
        .await
        .unwrap();
    let got = store
        .set_trust_level_if(
            &t,
            &d,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Trusted,
            now_at(13, 0),
        )
        .await
        .unwrap();
    assert_eq!(
        got,
        TrustTransition::Refused {
            current: DeviceTrustLevel::Revoked
        }
    );
    let row = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(row.revoked_at, Some(now_at(12, 0)));

    let ghost = crate::authn::ids::testing::device("ghost");
    let got = store
        .set_trust_level_if(
            &t,
            &ghost,
            DeviceTrustLevel::Unknown,
            DeviceTrustLevel::Seen,
            now_at(13, 0),
        )
        .await
        .unwrap();
    assert_eq!(got, TrustTransition::Missing);
}

#[tokio::test]
async fn replace_bindings_refuses_a_revoked_device_and_writes_only_bindings() {
    let store = fresh_store().await;
    let (t, d) = saved(&store, DeviceTrustLevel::Trusted).await;

    let got = store
        .replace_bindings(&t, &d, &[], &[refresh("fam-a")], crate::device::test_now())
        .await
        .unwrap();
    assert_eq!(got, BindingsUpdate::Written);
    let row = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Trusted);
    assert_eq!(row.bindings, vec![refresh("fam-a")]);
    assert_eq!(
        store
            .find_by_refresh_family(&t, "fam-a")
            .await
            .unwrap()
            .len(),
        1
    );

    store
        .set_trust_level(&t, &d, DeviceTrustLevel::Revoked, now_at(12, 0))
        .await
        .unwrap();
    let got = store
        .replace_bindings(
            &t,
            &d,
            &[refresh("fam-a")],
            &[refresh("fam-b")],
            crate::device::test_now(),
        )
        .await
        .unwrap();
    assert_eq!(got, BindingsUpdate::Revoked);
    let row = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(row.revoked_at, Some(now_at(12, 0)));
    assert_eq!(row.bindings, vec![refresh("fam-a")], "no binding added");
    assert!(
        store
            .find_by_refresh_family(&t, "fam-b")
            .await
            .unwrap()
            .is_empty()
    );

    let ghost = crate::authn::ids::testing::device("ghost");
    assert_eq!(
        store
            .replace_bindings(&t, &ghost, &[], &[], crate::device::test_now())
            .await
            .unwrap(),
        BindingsUpdate::Missing
    );
}

#[tokio::test]
async fn a_duplicated_refresh_family_does_not_poison_later_saves() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    let device = build_device(
        &t,
        Some(&u),
        &d,
        0x22,
        vec![refresh("fam"), refresh("fam"), refresh("other")],
    );
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();
    store
        .save(&device, crate::device::test_now())
        .await
        .expect("second save of the same device");

    store
        .set_trust_level(&t, &d, DeviceTrustLevel::Trusted, now_at(11, 0))
        .await
        .unwrap();
    let mut changed = store.load(&t, &d).await.unwrap().unwrap();
    changed.last_seen_at = now_at(12, 0);
    store
        .save(&changed, crate::device::test_now())
        .await
        .expect("save after a trust change");

    assert_eq!(
        store.find_by_refresh_family(&t, "fam").await.unwrap().len(),
        1
    );
    assert_eq!(
        store
            .find_by_refresh_family(&t, "other")
            .await
            .unwrap()
            .len(),
        1
    );
}

/// The insert itself is idempotent, independent of the de-duplication in
/// front of it: handing it the same family twice must not fail.
#[tokio::test]
async fn the_family_index_insert_is_idempotent() {
    let store = fresh_store().await;
    let (t, d) = saved(&store, DeviceTrustLevel::Seen).await;
    let mut tx = store.pool.begin().await.unwrap();
    rewrite_family_index(
        &mut tx,
        &t.to_string(),
        &d.to_string(),
        &["f".to_string(), "f".to_string()],
    )
    .await
    .expect("duplicate family ids in one rewrite");
    tx.commit().await.unwrap();
    assert_eq!(
        store.find_by_refresh_family(&t, "f").await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn writes_to_a_missing_device_are_not_found_errors() {
    let store = fresh_store().await;
    let (t, _u, _d) = ids();
    let ghost = crate::authn::ids::testing::device("ghost");

    let err = store
        .record_sighting(&t, &ghost, now_at(11, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SqlDeviceStoreError::NotFound { .. }),
        "{err:?}"
    );
    let err = store
        .set_trust_level(&t, &ghost, DeviceTrustLevel::Revoked, now_at(11, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SqlDeviceStoreError::NotFound { .. }),
        "{err:?}"
    );

    // A device in another tenant is missing too.
    let (_, d) = saved(&store, DeviceTrustLevel::Seen).await;
    let other = crate::authn::ids::testing::tenant("tenant-other");
    assert!(
        store
            .record_sighting(&other, &d, now_at(11, 0))
            .await
            .is_err()
    );

    // The same second twice is a match, not a miss.
    store
        .record_sighting(&t, &d, now_at(10, 0))
        .await
        .expect("unchanged value");
}

#[tokio::test]
async fn revoked_devices_never_use_up_the_active_limit() {
    let store = fresh_store().await;
    let (t, u, _d) = ids();
    // Five revoked devices, all more recently sighted than the three
    // active ones, so a LIMIT applied first would return only revoked rows.
    for i in 0..8u8 {
        let id = crate::authn::ids::testing::device(&format!("dev-{i}"));
        let mut device = build_device(&t, Some(&u), &id, i, vec![]);
        if i < 5 {
            device.trust_level = DeviceTrustLevel::Revoked;
            device.revoked_at = Some(now_at(12, 0));
            device.last_seen_at = now_at(12, i as u32);
        } else {
            device.trust_level = DeviceTrustLevel::Seen;
            device.last_seen_at = now_at(10, i as u32);
        }
        store
            .save(&device, crate::device::test_now())
            .await
            .unwrap();
    }

    let got = store.find_active_for_user(&t, &u, 2).await.unwrap();
    assert_eq!(got.len(), 2, "two active devices, not zero");
    assert!(
        got.iter()
            .all(|d| d.trust_level != DeviceTrustLevel::Revoked)
    );
    assert_eq!(got[0].last_seen_at, now_at(10, 7), "newest active first");
    assert_eq!(
        store.find_active_for_user(&t, &u, 10).await.unwrap().len(),
        3
    );
    assert_eq!(store.find_for_user(&t, &u, 10).await.unwrap().len(), 8);
}

use crate::device::store::ladder::LADDER;

#[tokio::test]
async fn sweep_follows_the_ladder_table() {
    let store = fresh_store().await;
    let (t, u, _d) = ids();
    let now = now_at(20, 0);
    for (i, r) in LADDER.iter().enumerate() {
        let id = crate::authn::ids::testing::device(&format!("row-{i}"));
        let mut device = build_device(&t, Some(&u), &id, i as u8, vec![]);
        device.trust_level = r.level;
        device.last_seen_at = r.last_seen(now);
        device.first_seen_at = device.last_seen_at;
        device.demoted_at = r.demoted_at(now);
        store
            .save(&device, crate::device::test_now())
            .await
            .unwrap();
    }
    store.sweep(&t, now).await.unwrap();
    for (i, r) in LADDER.iter().enumerate() {
        let id = crate::authn::ids::testing::device(&format!("row-{i}"));
        let got = store.load(&t, &id).await.unwrap().unwrap();
        assert_eq!(
            got.trust_level, r.want,
            "{:?} idle {}d demoted {:?}d ago",
            r.level, r.idle_days, r.demoted_days_ago
        );
    }
}

/// The sweep stamps the demotion it performs, the stamp survives a reload,
/// and the demoted device then gets its whole Seen window from the stamp.
#[tokio::test]
async fn sweep_stamps_the_demotion_and_counts_the_seen_window_from_it() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    let now = now_at(20, 0);
    let mut device = build_device(&t, Some(&u), &d, 1, vec![]);
    device.trust_level = DeviceTrustLevel::Trusted;
    device.last_seen_at = now - chrono::Duration::days(100);
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();

    store.sweep(&t, now).await.unwrap();
    let row = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Seen);
    assert_eq!(row.demoted_at, Some(now));

    let later = now + chrono::Duration::days(29);
    let counts = store.sweep(&t, later).await.unwrap();
    assert_eq!(counts.seen_to_revoked, 0);
    let later = now + chrono::Duration::days(31);
    let counts = store.sweep(&t, later).await.unwrap();
    assert_eq!(counts.seen_to_revoked, 1);
    let row = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(row.demoted_at, None, "a revoked row carries no demotion");
}

/// Every explicit transition applies the same stamp rule as the memory store:
/// Trusted to Seen stamps, Seen to Seen keeps it, a promotion clears it.
#[tokio::test]
async fn explicit_transitions_stamp_and_clear_the_demotion() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    let mut device = build_device(&t, Some(&u), &d, 1, vec![]);
    device.trust_level = DeviceTrustLevel::Trusted;
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();
    let stamp = |s: SqliteDeviceStore| {
        let (t, d) = (t, d);
        async move { s.load(&t, &d).await.unwrap().unwrap().demoted_at }
    };

    store
        .set_trust_level(&t, &d, DeviceTrustLevel::Seen, now_at(11, 0))
        .await
        .unwrap();
    assert_eq!(stamp(store.clone()).await, Some(now_at(11, 0)));
    store
        .set_trust_level(&t, &d, DeviceTrustLevel::Seen, now_at(12, 0))
        .await
        .unwrap();
    assert_eq!(stamp(store.clone()).await, Some(now_at(11, 0)));
    store
        .set_trust_level(&t, &d, DeviceTrustLevel::Trusted, now_at(13, 0))
        .await
        .unwrap();
    assert_eq!(stamp(store.clone()).await, None);

    let got = store
        .set_trust_level_if(
            &t,
            &d,
            DeviceTrustLevel::Trusted,
            DeviceTrustLevel::Seen,
            now_at(14, 0),
        )
        .await
        .unwrap();
    assert_eq!(got, TrustTransition::Applied);
    assert_eq!(stamp(store.clone()).await, Some(now_at(14, 0)));
    let got = store
        .set_trust_level_if(
            &t,
            &d,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Seen,
            now_at(15, 0),
        )
        .await
        .unwrap();
    assert_eq!(got, TrustTransition::Applied);
    assert_eq!(stamp(store.clone()).await, Some(now_at(14, 0)));
    let got = store
        .set_trust_level_if(
            &t,
            &d,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Trusted,
            now_at(16, 0),
        )
        .await
        .unwrap();
    assert_eq!(got, TrustTransition::Applied);
    assert_eq!(stamp(store.clone()).await, None);
}

/// Two users racing for one unowned device: exactly one claims it, and the
/// stored owner is that one.
#[tokio::test]
async fn racing_owner_claims_have_exactly_one_winner() {
    let store = fresh_store().await;
    let (t, _u, d) = ids();
    let mut device = build_device(&t, None, &d, 1, vec![]);
    device.user_id = None;
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();
    let (a, b) = (
        crate::authn::ids::testing::user("a"),
        crate::authn::ids::testing::user("b"),
    );
    let (ra, rb) = tokio::join!(
        store.claim_owner(&t, &d, &a, crate::device::test_now()),
        store.claim_owner(&t, &d, &b, crate::device::test_now())
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    let claimed = [ra, rb]
        .iter()
        .filter(|c| **c == OwnerClaim::Claimed)
        .count();
    assert_eq!(claimed, 1, "{ra:?} {rb:?}");
    let winner = if ra == OwnerClaim::Claimed { a } else { b };
    assert_eq!(
        store.load(&t, &d).await.unwrap().unwrap().user_id,
        Some(winner)
    );
    let ghost = crate::authn::ids::testing::device("ghost");
    assert_eq!(
        store
            .claim_owner(&t, &ghost, &a, crate::device::test_now())
            .await
            .unwrap(),
        OwnerClaim::Missing
    );
}

/// The second of two editors that read the same bindings is refused, and
/// the first one's binding is what the row holds.
#[tokio::test]
async fn a_stale_bindings_write_conflicts() {
    let store = fresh_store().await;
    let (t, d) = saved(&store, DeviceTrustLevel::Seen).await;
    let first = store
        .replace_bindings(&t, &d, &[], &[refresh("fam-1")], crate::device::test_now())
        .await
        .unwrap();
    assert_eq!(first, BindingsUpdate::Written);
    let second = store
        .replace_bindings(&t, &d, &[], &[refresh("fam-2")], crate::device::test_now())
        .await
        .unwrap();
    assert_eq!(second, BindingsUpdate::Conflict);
    let row = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(row.bindings, vec![refresh("fam-1")]);
    assert!(
        store
            .find_by_refresh_family(&t, "fam-2")
            .await
            .unwrap()
            .is_empty()
    );
    // With the bindings it just read, the second editor succeeds.
    let retry = store
        .replace_bindings(
            &t,
            &d,
            &[refresh("fam-1")],
            &[refresh("fam-1"), refresh("fam-2")],
            crate::device::test_now(),
        )
        .await
        .unwrap();
    assert_eq!(retry, BindingsUpdate::Written);
}
