//! Devices of one tenant that share a fingerprint, with no owner to find them
//! through: the fingerprint stays findable until the last of them is gone,
//! and an index entry written by an earlier release still reads and is
//! replaced by the next write. Live-server tests, ignored by default
//! (`VALKEY_URL=redis://127.0.0.1:56382`).

use super::*;
use crate::device::lifecycle::DeviceLifecycleService;
use crate::device::store::consistency::{self as shared, at, dev_id, tenant};

async fn store(tag: &str) -> ValkeyDeviceStore {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    live_store(&format!("axw_{tag}_{nanos}")).await
}

/// A device nobody owns, as a guest request makes it.
fn guest(label: &str, fp: u8, level: DeviceTrustLevel, seen: DateTime<Utc>) -> Device {
    let mut d = shared::device(label, fp, level, seen);
    d.user_id = None;
    d
}

async fn found(s: &ValkeyDeviceStore, fp: &FingerprintHash) -> Option<DeviceId> {
    s.find_by_fingerprint(&tenant(), fp)
        .await
        .unwrap()
        .map(|d| d.id)
}

async fn mint_or_find(s: &ValkeyDeviceStore, fp: FingerprintHash, now: DateTime<Utc>) -> DeviceId {
    DeviceLifecycleService::new(s.clone())
        .ensure_device(&tenant(), None, fp, now, || dev_id("must-not-be-minted"))
        .await
        .unwrap()
}

fn set_key(s: &ValkeyDeviceStore, fp: &FingerprintHash) -> String {
    fingerprint_set_key(&s.prefix, &tenant().to_string(), &fingerprint_hex(fp))
}

fn legacy_key(s: &ValkeyDeviceStore, fp: &FingerprintHash) -> String {
    fingerprint_key(&s.prefix, &tenant().to_string(), &fingerprint_hex(fp))
}

/// Make the index look as an earlier release left it: no set, one id.
async fn make_legacy(s: &ValkeyDeviceStore, fp: &FingerprintHash, points_at: &DeviceId) {
    let _: i64 = s.client.del(set_key(s, fp)).await.unwrap();
    let _: () = s
        .client
        .set(legacy_key(s, fp), points_at.to_string(), None, None, false)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_deleting_the_indexed_unowned_device_keeps_its_twin_findable() {
    let s = store("delunowned").await;
    let now = at(0);
    let a = guest("guest-a", 0x95, DeviceTrustLevel::Seen, now);
    let b = guest("guest-b", 0x95, DeviceTrustLevel::Seen, now);
    s.save(&a, now).await.unwrap();
    s.save(&b, now).await.unwrap(); // the last writer, which a single-id index names
    s.delete(&tenant(), &b.id).await.unwrap();

    assert_eq!(found(&s, &a.fingerprint_hash).await, Some(a.id));
    assert_eq!(mint_or_find(&s, a.fingerprint_hash, now).await, a.id);

    s.delete(&tenant(), &a.id).await.unwrap();
    assert_eq!(found(&s, &a.fingerprint_hash).await, None);
    let left: i64 = s
        .client
        .exists(set_key(&s, &a.fingerprint_hash))
        .await
        .unwrap();
    assert_eq!(left, 0, "the last device takes its fingerprint key with it");
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_sweep_purge_keeps_an_unowned_twin_findable() {
    let s = store("purgeunowned").await;
    let day = chrono::Duration::days(1);
    let a = guest("purge-a", 0x96, DeviceTrustLevel::Seen, at(0) + day * 29);
    let b = guest("purge-b", 0x96, DeviceTrustLevel::Revoked, at(0));
    s.save(&a, a.last_seen_at).await.unwrap();
    s.save(&b, at(0)).await.unwrap(); // the last writer
    assert!(found(&s, &a.fingerprint_hash).await.is_some());

    let counts = s.sweep(&tenant(), at(0) + day * 30).await.unwrap();
    assert_eq!(counts.revoked_purged, 1, "the revoked twin is purged");
    assert!(s.load(&tenant(), &b.id).await.unwrap().is_none());

    assert_eq!(found(&s, &a.fingerprint_hash).await, Some(a.id));
    assert_eq!(
        mint_or_find(&s, a.fingerprint_hash, a.last_seen_at).await,
        a.id
    );
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_three_twins_come_back_newest_first_then_smaller_id() {
    let s = store("threetwins").await;
    let fp = FingerprintHash::from_bytes([0x97; 32]);
    let old = guest("tri-old", 0x97, DeviceTrustLevel::Seen, at(5));
    let x = guest("tri-x", 0x97, DeviceTrustLevel::Seen, at(50));
    let y = guest("tri-y", 0x97, DeviceTrustLevel::Seen, at(50));
    let (small, large) = if x.id < y.id { (&x, &y) } else { (&y, &x) };
    // Saved with the ids and times in the order that would favour a
    // last-writer index.
    for d in [small, &old, large] {
        s.save(d, at(50)).await.unwrap();
    }
    assert_eq!(found(&s, &fp).await, Some(small.id));
    s.delete(&tenant(), &small.id).await.unwrap();
    assert_eq!(found(&s, &fp).await, Some(large.id));
    s.delete(&tenant(), &large.id).await.unwrap();
    assert_eq!(found(&s, &fp).await, Some(old.id));
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_single_id_index_entry_still_finds_its_device_and_the_next_write_migrates_it()
 {
    let s = store("legacy").await;
    let now = at(0);
    let a = guest("old-a", 0x98, DeviceTrustLevel::Seen, now);
    let b = guest("old-b", 0x98, DeviceTrustLevel::Seen, now);
    s.save(&a, now).await.unwrap();
    s.save(&b, now).await.unwrap();
    make_legacy(&s, &a.fingerprint_hash, &b.id).await;

    // Read as before: the entry names its device.
    assert_eq!(found(&s, &a.fingerprint_hash).await, Some(b.id));
    let in_set: bool = s
        .client
        .sismember(set_key(&s, &a.fingerprint_hash), b.id.to_string())
        .await
        .unwrap();
    assert!(!in_set, "a read does not rewrite the index");

    // The next write of that device lists it in the set and removes the old key.
    s.record_sighting(&tenant(), &b.id, now + chrono::Duration::seconds(5))
        .await
        .unwrap();
    let old: Option<String> = s
        .client
        .get(legacy_key(&s, &a.fingerprint_hash))
        .await
        .unwrap();
    assert!(old.is_none(), "the single-id key is gone");
    let in_set: bool = s
        .client
        .sismember(set_key(&s, &a.fingerprint_hash), b.id.to_string())
        .await
        .unwrap();
    assert!(in_set);
    assert_eq!(found(&s, &a.fingerprint_hash).await, Some(b.id));

    // The twin the old key never named is listed by its own next write, and
    // deleting the one found first then leaves it findable.
    s.record_sighting(&tenant(), &a.id, now + chrono::Duration::seconds(1))
        .await
        .unwrap();
    s.delete(&tenant(), &b.id).await.unwrap();
    assert_eq!(found(&s, &a.fingerprint_hash).await, Some(a.id));
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_single_id_entry_and_a_set_are_ranked_together() {
    let s = store("mixed").await;
    let older = guest("mix-old", 0x99, DeviceTrustLevel::Seen, at(10));
    let newer = guest("mix-new", 0x99, DeviceTrustLevel::Seen, at(20));
    s.save(&older, at(20)).await.unwrap();
    s.save(&newer, at(20)).await.unwrap();
    // The set lists the older device; the old key names the newer one.
    let _: i64 = s
        .client
        .del(set_key(&s, &older.fingerprint_hash))
        .await
        .unwrap();
    let _: i64 = s
        .client
        .sadd(set_key(&s, &older.fingerprint_hash), older.id.to_string())
        .await
        .unwrap();
    let _: () = s
        .client
        .set(
            legacy_key(&s, &older.fingerprint_hash),
            newer.id.to_string(),
            None,
            None,
            false,
        )
        .await
        .unwrap();
    assert_eq!(found(&s, &older.fingerprint_hash).await, Some(newer.id));
}
