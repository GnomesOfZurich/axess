//! The in-memory store under concurrency, and its tie order and fingerprint
//! index, which the shared contract checks cannot reach into.

use super::*;
use crate::device::store::consistency::{self as shared, at, dev_id, device, tenant};
use chrono::Duration;

/// Revocations that land while a sweep is running are never undone by it:
/// every row ends `Revoked` whichever side got there first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_during_a_sweep_is_never_undone() {
    let (t, now, rows) = (tenant(), at(0), 2_000);
    for round in 0..40 {
        let store = MemoryDeviceStore::new();
        for i in 0..rows {
            let idle = device(
                &format!("r{i}"),
                (i % 200) as u8,
                DeviceTrustLevel::Trusted,
                now - Duration::days(91),
            );
            store.save(&idle, now).await.unwrap();
        }
        let sweeper = {
            let s = store.clone();
            tokio::spawn(async move { s.sweep(&t, now).await.unwrap() })
        };
        let revoker = {
            let s = store.clone();
            tokio::spawn(async move {
                for i in 0..rows {
                    s.set_trust_level(
                        &t,
                        &dev_id(&format!("r{i}")),
                        DeviceTrustLevel::Revoked,
                        now,
                    )
                    .await
                    .unwrap();
                }
            })
        };
        let counts = sweeper.await.unwrap();
        revoker.await.unwrap();
        for i in 0..rows {
            let row = store
                .load(&t, &dev_id(&format!("r{i}")))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                row.trust_level,
                DeviceTrustLevel::Revoked,
                "round {round} row r{i}"
            );
            assert_eq!(row.revoked_at, Some(now), "round {round} row r{i}");
        }
        assert!(counts.trusted_to_seen <= rows as u64);
    }
}

/// A sweep counts a demotion only when it wrote one: a row that was revoked
/// first is left alone and not counted.
#[tokio::test]
async fn a_sweep_counts_only_the_writes_it_made() {
    let (t, now) = (tenant(), at(0));
    let store = MemoryDeviceStore::new();
    let idle = device(
        "idle",
        0x11,
        DeviceTrustLevel::Trusted,
        now - Duration::days(91),
    );
    store.save(&idle, now).await.unwrap();
    store
        .set_trust_level(
            &t,
            &idle.id,
            DeviceTrustLevel::Revoked,
            now - Duration::days(1),
        )
        .await
        .unwrap();
    let counts = store.sweep(&t, now).await.unwrap();
    assert_eq!(counts, SweepCounts::default());
    let row = store.load(&t, &idle.id).await.unwrap().unwrap();
    assert_eq!(row.revoked_at, Some(now - Duration::days(1)));
}

/// Two saves of one device under different fingerprints, racing, leave no
/// index entry for a fingerprint the row does not carry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_saves_leave_no_index_entry_for_a_fingerprint_the_row_lost() {
    let now = at(0);
    for round in 0..200 {
        let store = MemoryDeviceStore::new();
        let mut tasks = Vec::new();
        for worker in 0..8u8 {
            let s = store.clone();
            tasks.push(tokio::spawn(async move {
                for k in 0..25u8 {
                    let d = device("racer", (worker + k) % 6, DeviceTrustLevel::Seen, now);
                    s.save(&d, now).await.unwrap();
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        for entry in store.fingerprint_index.iter() {
            let ((tenant_id, hash), id) = (entry.key(), *entry.value());
            let row = store
                .devices
                .get(&(*tenant_id, id))
                .expect("indexed device exists");
            assert_eq!(
                row.fingerprint_hash, *hash,
                "round {round}: stale index entry"
            );
        }
    }
}

/// Deleting the device the fingerprint index points at hands the entry to
/// another device that carries the same fingerprint.
#[tokio::test]
async fn deleting_one_of_two_devices_sharing_a_fingerprint_keeps_the_other_findable() {
    let (t, now) = (tenant(), at(0));
    let store = MemoryDeviceStore::new();
    let a = device("share-a", 0x22, DeviceTrustLevel::Seen, now);
    let b = device("share-b", 0x22, DeviceTrustLevel::Seen, now);
    store.save(&a, now).await.unwrap();
    store.save(&b, now).await.unwrap(); // the index now points at b
    store.delete(&t, &b.id).await.unwrap();
    let found = store
        .find_by_fingerprint(&t, &a.fingerprint_hash)
        .await
        .unwrap();
    assert_eq!(found.map(|d| d.id), Some(a.id));
    store.delete(&t, &a.id).await.unwrap();
    assert!(
        store
            .find_by_fingerprint(&t, &a.fingerprint_hash)
            .await
            .unwrap()
            .is_none()
    );
}

/// The fingerprint index is a hint: an entry whose device no longer carries
/// the fingerprint finds nothing.
#[tokio::test]
async fn a_stale_fingerprint_entry_finds_nothing() {
    let (t, now) = (tenant(), at(0));
    let store = MemoryDeviceStore::new();
    let d = device("stale-fp", 0x33, DeviceTrustLevel::Seen, now);
    store.save(&d, now).await.unwrap();
    let other = FingerprintHash::from_bytes([0x34; 32]);
    store.fingerprint_index.insert((t, other), d.id);
    assert!(
        store
            .find_by_fingerprint(&t, &other)
            .await
            .unwrap()
            .is_none()
    );
}

/// A revoked row saved without a revocation time before this version (it
/// is written straight into the table here) is stamped by a sweep and
/// purged by a later one.
#[tokio::test]
async fn a_legacy_revoked_row_without_a_time_ages_out() {
    let (t, now) = (tenant(), at(0));
    let store = MemoryDeviceStore::new();
    let mut d = device("legacy", 0x44, DeviceTrustLevel::Revoked, now);
    d.revoked_at = None;
    store.devices.insert((d.tenant_id, d.id), d.clone());
    store.sweep(&t, now).await.unwrap();
    let stamped = store.load(&t, &d.id).await.unwrap().unwrap();
    assert_eq!(stamped.revoked_at, Some(now));
    let grace = SweepConfig::default().revoked_grace;
    let counts = store
        .sweep(&t, now + grace + Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(counts.revoked_purged, 1);
}

#[tokio::test]
async fn shared_contract() {
    shared::ties_are_broken_by_the_smaller_id(MemoryDeviceStore::new()).await;
    shared::a_shared_fingerprint_stays_findable_while_any_device_carries_it(
        MemoryDeviceStore::new(),
    )
    .await;
    shared::a_sighting_never_rewinds_and_skips_a_revoked_row(MemoryDeviceStore::new()).await;
    shared::a_save_never_un_revokes(MemoryDeviceStore::new()).await;
    shared::a_revoked_save_without_a_time_is_stamped_and_purged(MemoryDeviceStore::new()).await;
    shared::sweep_decisions_agree_to_the_second(
        MemoryDeviceStore::new().with_sweep_config(shared::tight_config()),
    )
    .await;
}

/// Tie order must not depend on the map's iteration order, which a fresh
/// store reseeds: fifty stores, one answer.
#[tokio::test]
async fn tie_order_is_the_same_across_fresh_stores() {
    for _ in 0..50 {
        shared::ties_are_broken_by_the_smaller_id(MemoryDeviceStore::new()).await;
    }
}

#[test]
fn the_sweep_builder_refuses_a_window_with_a_fraction() {
    let err = SweepConfig::builder()
        .seen_idle(Duration::milliseconds(1_500))
        .build()
        .unwrap_err();
    assert_eq!(
        err,
        crate::device::store::SweepConfigError::SubSecondWindow {
            window: "seen_idle"
        }
    );
    assert!(
        SweepConfig::builder()
            .trusted_idle(Duration::seconds(10))
            .build()
            .is_ok()
    );
}
