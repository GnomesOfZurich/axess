//! Valkey device store: index consistency, stale index entries, tolerance of
//! a damaged row, and the shared contract. Live-server tests, ignored by
//! default (`VALKEY_URL=redis://127.0.0.1:6404`).

use super::*;
use crate::device::cascade::cascade_revoke_by_refresh_family;
use crate::device::lifecycle::DeviceLifecycleService;
use crate::device::store::consistency::{self as shared, at, dev_id, tenant, user};
use crate::device::store::{BindingsUpdate, OwnerClaim};

/// A key prefix no earlier run on the same server has used.
fn fresh_prefix(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("axc_{tag}_{nanos}")
}

async fn store(tag: &str) -> ValkeyDeviceStore {
    live_store(&fresh_prefix(tag)).await
}

fn refresh(family: &str, now: DateTime<Utc>) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.into(),
        issued_at: now,
        last_used_at: now,
    }
}

async fn member(s: &ValkeyDeviceStore, key: String, id: &str) -> bool {
    s.client.sismember(key, id).await.unwrap()
}

fn fam_key(s: &ValkeyDeviceStore, family: &str) -> String {
    family_index_key(&s.prefix, &tenant().to_string(), family)
}

fn user_key(s: &ValkeyDeviceStore, u: &UserId) -> String {
    user_index_key(&s.prefix, &tenant().to_string(), &u.to_string())
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_shared_contract() {
    shared::ties_are_broken_by_the_smaller_id(store("ties").await).await;
    shared::a_shared_fingerprint_stays_findable_while_any_device_carries_it(store("twins").await)
        .await;
    shared::a_sighting_never_rewinds_and_skips_a_revoked_row(store("sight").await).await;
    shared::a_save_never_un_revokes(store("unrevoke").await).await;
    shared::a_revoked_save_without_a_time_is_stamped_and_purged(store("stamp").await).await;
    shared::sweep_decisions_agree_to_the_second(
        store("second")
            .await
            .with_sweep_config(shared::tight_config()),
    )
    .await;
}

/// The index changes of a write are part of the script that writes the row:
/// nothing but the one `apply` call has run when the indexes are read.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_bindings_write_moves_the_family_index_in_the_same_script() {
    let s = store("atomic").await;
    let now = at(0);
    let mut d = shared::device("atomic", 0x81, DeviceTrustLevel::Seen, now);
    d.bindings = vec![refresh("fam-a", now)];
    s.save(&d, now).await.unwrap();
    let (t, id) = (tenant().to_string(), d.id.to_string());

    let applied = s
        .apply(&t, &id, now, |row| {
            let mut next = row.clone();
            next.bindings = vec![refresh("fam-b", now)];
            Step::Write(next)
        })
        .await
        .unwrap();
    assert!(matches!(applied, Applied::Written { .. }));
    assert!(!member(&s, fam_key(&s, "fam-a"), &id).await, "left fam-a");
    assert!(member(&s, fam_key(&s, "fam-b"), &id).await, "joined fam-b");
}

/// Several writers swapping one device between two families at once leave
/// each family index exactly as the final row says.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_racing_bindings_swaps_leave_the_indexes_matching_the_row() {
    let s = store("swaps").await;
    let now = at(0);
    let mut d = shared::device("swapper", 0x82, DeviceTrustLevel::Seen, now);
    d.bindings = vec![refresh("fam-a", now)];
    s.save(&d, now).await.unwrap();
    let (t, id) = (tenant(), d.id);

    let mut tasks = Vec::new();
    for _ in 0..6 {
        let s = s.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..60 {
                let row = s.load(&t, &id).await.unwrap().unwrap();
                let next = if row.bindings == vec![refresh("fam-a", now)] {
                    "fam-b"
                } else {
                    "fam-a"
                };
                let outcome = s
                    .replace_bindings(&t, &id, &row.bindings, &[refresh(next, now)], now)
                    .await
                    .unwrap();
                assert!(matches!(
                    outcome,
                    BindingsUpdate::Written | BindingsUpdate::Conflict
                ));
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let row = s.load(&t, &id).await.unwrap().unwrap();
    for family in ["fam-a", "fam-b"] {
        let bound = row
            .bindings
            .iter()
            .any(|b| matches!(b, DeviceBinding::Refresh { family_id, .. } if family_id == family));
        assert_eq!(
            member(&s, fam_key(&s, family), &id.to_string()).await,
            bound,
            "{family}"
        );
    }
}

/// A save, an owner claim and a bindings swap racing on one device leave the
/// tenant, user and family indexes matching whichever row won.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_save_racing_a_claim_and_a_swap_leaves_the_indexes_consistent() {
    let now = at(0);
    let (t, u) = (tenant(), user());
    for round in 0..60 {
        let s = store(&format!("mix{round}")).await;
        let mut d = shared::device("mixed", 0x83, DeviceTrustLevel::Seen, now);
        d.user_id = None;
        d.bindings = vec![refresh("fam-a", now)];
        s.save(&d, now).await.unwrap();
        let (s1, s2, s3) = (s.clone(), s.clone(), s.clone());
        let stale = d.clone();
        let (claim, swap, save) = tokio::join!(
            tokio::spawn(async move { s1.claim_owner(&t, &d.id, &u, now).await.unwrap() }),
            tokio::spawn(async move {
                s2.replace_bindings(
                    &t,
                    &stale.id,
                    &stale.bindings,
                    &[refresh("fam-b", now)],
                    now,
                )
                .await
                .unwrap()
            }),
            tokio::spawn({
                let again = d.clone();
                async move { s3.save(&again, now).await.unwrap() }
            }),
        );
        assert!(matches!(
            claim.unwrap(),
            OwnerClaim::Claimed | OwnerClaim::Missing
        ));
        assert!(matches!(
            swap.unwrap(),
            BindingsUpdate::Written | BindingsUpdate::Conflict
        ));
        save.unwrap();

        let row = s.load(&t, &d.id).await.unwrap().unwrap();
        let id = d.id.to_string();
        assert!(member(&s, tenant_index_key(&s.prefix, &t.to_string()), &id).await);
        assert_eq!(
            member(&s, user_key(&s, &u), &id).await,
            row.user_id == Some(u),
            "round {round}: user index"
        );
        for family in ["fam-a", "fam-b"] {
            let bound = row.bindings.iter().any(
                |b| matches!(b, DeviceBinding::Refresh { family_id, .. } if family_id == family),
            );
            assert_eq!(
                member(&s, fam_key(&s, family), &id).await,
                bound,
                "round {round}: {family}"
            );
        }
    }
}

/// A device that moved to another family, with its old family entry put
/// back by hand, is not returned for the old family, is not revoked by a
/// cascade on it, and the entry is dropped.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_stale_family_entry_neither_lists_nor_revokes_the_device() {
    let s = store("stalefam").await;
    let now = at(0);
    let t = tenant();
    let mut d = shared::device("mover", 0x84, DeviceTrustLevel::Seen, now);
    d.bindings = vec![refresh("fam-1", now)];
    s.save(&d, now).await.unwrap();
    let moved = s
        .replace_bindings(&t, &d.id, &d.bindings, &[refresh("fam-2", now)], now)
        .await
        .unwrap();
    assert_eq!(moved, BindingsUpdate::Written);
    let _: () = s
        .client
        .sadd(fam_key(&s, "fam-1"), d.id.to_string())
        .await
        .unwrap();

    assert!(
        s.find_by_refresh_family(&t, "fam-1")
            .await
            .unwrap()
            .is_empty()
    );
    let revoked = cascade_revoke_by_refresh_family(&s, &t, "fam-1", now)
        .await
        .unwrap();
    assert_eq!(
        revoked, 0,
        "the cascade on the old family reaches no device"
    );
    let row = s.load(&t, &d.id).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Seen);
    assert!(
        !member(&s, fam_key(&s, "fam-1"), &d.id.to_string()).await,
        "the stale entry was dropped"
    );
    assert_eq!(
        s.find_by_refresh_family(&t, "fam-2").await.unwrap().len(),
        1
    );
}

/// An entry in another user's index does not make the device that user's.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_stale_user_entry_does_not_hand_over_a_device() {
    let s = store("staleuser").await;
    let now = at(0);
    let t = tenant();
    let other = crate::authn::ids::testing::user("someone-else");
    let d = shared::device("owned", 0x85, DeviceTrustLevel::Seen, now);
    s.save(&d, now).await.unwrap();
    let _: () = s
        .client
        .sadd(user_key(&s, &other), d.id.to_string())
        .await
        .unwrap();

    assert!(s.find_for_user(&t, &other, 10).await.unwrap().is_empty());
    assert!(
        s.find_by_fingerprint_for_user(&t, &other, &d.fingerprint_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !member(&s, user_key(&s, &other), &d.id.to_string()).await,
        "the stale entry was dropped"
    );
    assert_eq!(s.find_for_user(&t, &user(), 10).await.unwrap().len(), 1);
}

/// A fingerprint entry that points at a device whose row says otherwise
/// finds nothing and is removed.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_stale_fingerprint_entry_finds_nothing_and_is_removed() {
    let s = store("stalefp").await;
    let now = at(0);
    let t = tenant();
    let d = shared::device("fp-owner", 0x86, DeviceTrustLevel::Seen, now);
    s.save(&d, now).await.unwrap();
    let fp3 = FingerprintHash::from_bytes([0x87; 32]);
    let fp3_key = fingerprint_key(&s.prefix, &t.to_string(), &fingerprint_hex(&fp3));
    let _: () = s
        .client
        .set(&fp3_key, d.id.to_string(), None, None, false)
        .await
        .unwrap();

    assert!(s.find_by_fingerprint(&t, &fp3).await.unwrap().is_none());
    let left: Option<String> = s.client.get(&fp3_key).await.unwrap();
    assert!(left.is_none(), "the stale key is gone");
    let own = s
        .find_by_fingerprint(&t, &d.fingerprint_hash)
        .await
        .unwrap();
    assert_eq!(own.map(|x| x.id), Some(d.id), "the real entry is untouched");
}

/// One row that cannot be decoded does not stop retention for the others.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_damaged_row_does_not_stop_the_sweep() {
    let s = store("damaged").await;
    let now = at(0);
    let t = tenant();
    let idle = |label: &str, fp: u8| {
        shared::device(
            label,
            fp,
            DeviceTrustLevel::Trusted,
            now - Duration::days(91),
        )
    };
    let (bad, good) = (idle("bad", 0x91), idle("good", 0x92));
    s.save(&bad, now).await.unwrap();
    s.save(&good, now).await.unwrap();
    let bad_key = device_key(&s.prefix, &t.to_string(), &bad.id.to_string());
    let _: () = s
        .client
        .set(&bad_key, vec![0xc1u8, 0, 1], None, None, false)
        .await
        .unwrap();

    let counts = s.sweep(&t, now).await.unwrap();
    assert_eq!(counts.trusted_to_seen, 1, "the readable row was demoted");
    let row = s.load(&t, &good.id).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Seen);
    assert!(
        s.load(&t, &bad.id).await.is_err(),
        "the damaged row is still reported when read directly"
    );
}

/// A legacy revoked row with no time is stamped by a sweep and purged later.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_legacy_revoked_row_without_a_time_ages_out() {
    let s = store("legacyrev").await;
    let now = at(0);
    let t = tenant();
    let mut d = shared::device("legacy", 0x93, DeviceTrustLevel::Revoked, now);
    d.revoked_at = None;
    let key = device_key(&s.prefix, &t.to_string(), &d.id.to_string());
    let _: () = s
        .client
        .set(&key, s.encode_row(&d).unwrap(), None, None, false)
        .await
        .unwrap();
    let _: () = s
        .client
        .sadd(
            tenant_index_key(&s.prefix, &t.to_string()),
            d.id.to_string(),
        )
        .await
        .unwrap();

    s.sweep(&t, now).await.unwrap();
    assert_eq!(
        s.load(&t, &d.id).await.unwrap().unwrap().revoked_at,
        Some(now)
    );
    let grace = SweepConfig::default().revoked_grace;
    let counts = s
        .sweep(&t, now + grace + Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(counts.revoked_purged, 1);
}

/// After the device the fingerprint index named is deleted, a user whose
/// other device carries the same fingerprint is still matched to it rather
/// than given a new device.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_deleting_the_indexed_device_does_not_orphan_its_twin() {
    let s = store("twin").await;
    let now = at(0);
    let (t, u) = (tenant(), user());
    let a = shared::device("twin-a", 0x94, DeviceTrustLevel::Seen, now);
    let b = shared::device("twin-b", 0x94, DeviceTrustLevel::Seen, now);
    s.save(&a, now).await.unwrap();
    s.save(&b, now).await.unwrap(); // the index points at b
    s.delete(&t, &b.id).await.unwrap();
    assert_eq!(
        s.find_by_fingerprint(&t, &a.fingerprint_hash)
            .await
            .unwrap()
            .map(|d| d.id),
        Some(a.id)
    );

    let svc = DeviceLifecycleService::new(s.clone());
    let id = svc
        .ensure_device(&t, Some(&u), a.fingerprint_hash, now, || {
            dev_id("must-not-be-minted")
        })
        .await
        .unwrap();
    assert_eq!(id, a.id);
}
