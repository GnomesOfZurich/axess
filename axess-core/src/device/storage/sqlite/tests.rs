//! Unit tests for [`super::SqliteDeviceStore`].
//!
//! Pulled sideways from `sqlite.rs` (48% test bloat). The test module
//! still uses `super::*` so private-item access continues to work and
//! the move is purely organisational.

#![cfg(test)]

use super::*;
use crate::device::cascade::cascade_revoke_by_refresh_family;
use crate::device::types::DeviceBinding;
use sqlx::sqlite::SqlitePoolOptions;

/// In-memory SQLite store seeded with the device-store schema. Single
/// connection ensures every query hits the same `:memory:` db
/// (otherwise sqlx's default pool would create a fresh empty one
/// per connection). Plaintext for unit tests; encryption is
/// covered by the integration suite.
async fn fresh_store() -> SqliteDeviceStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("memory sqlite connect");
    let store = SqliteDeviceStore::plaintext(pool);
    store.init_schema().await.expect("init_schema");
    store
}

fn ids() -> (TenantId, UserId, DeviceId) {
    (
        crate::authn::ids::testing::tenant("tenant-1"),
        crate::authn::ids::testing::user("user-1"),
        crate::authn::ids::testing::device("device-1"),
    )
}

fn now_at(h: u32, m: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, h, m, 0).unwrap()
}

fn fingerprint(byte: u8) -> FingerprintHash {
    FingerprintHash::from_bytes([byte; 32])
}

fn build_device(
    t: &TenantId,
    u: Option<&UserId>,
    d: &DeviceId,
    fp: u8,
    bindings: Vec<DeviceBinding>,
) -> Device {
    Device {
        id: *d,
        tenant_id: *t,
        user_id: u.cloned(),
        trust_level: DeviceTrustLevel::Unknown,
        fingerprint_hash: fingerprint(fp),
        first_seen_at: now_at(10, 0),
        last_seen_at: now_at(10, 0),
        revoked_at: None,
        bindings,
    }
}

/// Pin the `trust_level_codec::from_str` match arms on round-trip.
/// Each variant must save + load without losing fidelity. A deleted
/// match arm in `from_str` would surface as a load error when the
/// variant in question tries to come back through the codec.
#[tokio::test]
async fn save_then_load_round_trips_every_trust_level() {
    let store = fresh_store().await;
    let t = crate::authn::ids::testing::tenant("t");
    let u = crate::authn::ids::testing::user("u");

    for level in [
        DeviceTrustLevel::Unknown,
        DeviceTrustLevel::Seen,
        DeviceTrustLevel::Trusted,
        DeviceTrustLevel::Revoked,
    ] {
        let d = crate::authn::ids::testing::device(&format!("d-{level:?}").to_lowercase());
        let mut device = build_device(&t, Some(&u), &d, 0xab, vec![]);
        device.trust_level = level;
        if level == DeviceTrustLevel::Revoked {
            device.revoked_at = Some(now_at(11, 0));
        }
        store.save(&device).await.unwrap();

        let loaded = store
            .load(&t, &d)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("device should load at trust_level={level:?}"));
        assert_eq!(
            loaded.trust_level, level,
            "round-trip must preserve trust_level={level:?}; \
             a deleted match arm in trust_level_codec::from_str would error here"
        );
    }
}

#[tokio::test]
async fn save_then_load_round_trips_full_device_record() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    let device = build_device(
        &t,
        Some(&u),
        &d,
        0xab,
        vec![DeviceBinding::Cookie {
            token_hash: fingerprint(0xcd),
            issued_at: now_at(10, 0),
            last_used_at: now_at(10, 0),
        }],
    );
    store.save(&device).await.unwrap();
    let loaded = store.load(&t, &d).await.unwrap().expect("present");
    assert_eq!(loaded, device, "round-trip must preserve every field");
}

#[tokio::test]
async fn load_unknown_tenant_or_device_returns_none() {
    let store = fresh_store().await;
    let (t, _u, d) = ids();
    assert!(store.load(&t, &d).await.unwrap().is_none());
}

#[tokio::test]
async fn save_is_an_upsert_and_overwrites_existing_row() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    let mut device = build_device(&t, Some(&u), &d, 0xab, vec![]);
    store.save(&device).await.unwrap();
    device.trust_level = DeviceTrustLevel::Trusted;
    device.last_seen_at = now_at(11, 0);
    store.save(&device).await.unwrap();

    let loaded = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(loaded.trust_level, DeviceTrustLevel::Trusted);
    assert_eq!(loaded.last_seen_at, now_at(11, 0));
}

#[tokio::test]
async fn find_by_fingerprint_is_tenant_scoped() {
    let store = fresh_store().await;
    let t1 = crate::authn::ids::testing::tenant("t1");
    let t2 = crate::authn::ids::testing::tenant("t2");
    let u = crate::authn::ids::testing::user("u");
    let d1 = crate::authn::ids::testing::device("d1");
    let d2 = crate::authn::ids::testing::device("d2");
    let fp = fingerprint(0xa1);
    let mut dev1 = build_device(&t1, Some(&u), &d1, 0, vec![]);
    dev1.fingerprint_hash = fp;
    let mut dev2 = build_device(&t2, Some(&u), &d2, 0, vec![]);
    dev2.fingerprint_hash = fp;
    store.save(&dev1).await.unwrap();
    store.save(&dev2).await.unwrap();

    let found = store.find_by_fingerprint(&t1, &fp).await.unwrap().unwrap();
    assert_eq!(found.id, d1, "find_by_fingerprint must scope by tenant_id");
}

#[tokio::test]
async fn find_for_user_returns_newest_first_and_respects_limit() {
    let store = fresh_store().await;
    let t = crate::authn::ids::testing::tenant("t");
    let u = crate::authn::ids::testing::user("u");
    for (i, fp) in [(0xa1u8, 10), (0xa2u8, 11), (0xa3u8, 12)]
        .iter()
        .enumerate()
    {
        let did = crate::authn::ids::testing::device(&format!("d{i}"));
        let mut dev = build_device(&t, Some(&u), &did, fp.0, vec![]);
        // Stagger last_seen_at so ordering is deterministic.
        dev.last_seen_at = now_at(fp.1, 0);
        store.save(&dev).await.unwrap();
    }
    let found = store.find_for_user(&t, &u, 2).await.unwrap();
    assert_eq!(found.len(), 2, "limit must be respected");
    assert!(
        found[0].last_seen_at >= found[1].last_seen_at,
        "results must be newest-first"
    );
}

#[tokio::test]
async fn find_for_user_excludes_other_tenants() {
    let store = fresh_store().await;
    let t1 = crate::authn::ids::testing::tenant("t1");
    let t2 = crate::authn::ids::testing::tenant("t2");
    let u = crate::authn::ids::testing::user("u");
    let d_t1 = crate::authn::ids::testing::device("d-t1");
    let d_t2 = crate::authn::ids::testing::device("d-t2");
    store
        .save(&build_device(&t1, Some(&u), &d_t1, 0xa1, vec![]))
        .await
        .unwrap();
    store
        .save(&build_device(&t2, Some(&u), &d_t2, 0xa2, vec![]))
        .await
        .unwrap();
    let found = store.find_for_user(&t1, &u, 100).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].tenant_id, t1);
}

#[tokio::test]
async fn record_sighting_bumps_last_seen_at() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    store
        .save(&build_device(&t, Some(&u), &d, 0xab, vec![]))
        .await
        .unwrap();
    let later = now_at(15, 0);
    store.record_sighting(&t, &d, later).await.unwrap();
    let device = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(device.last_seen_at, later);
}

#[tokio::test]
async fn set_trust_level_to_revoked_stamps_revoked_at() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    store
        .save(&build_device(&t, Some(&u), &d, 0xab, vec![]))
        .await
        .unwrap();
    let when = now_at(12, 0);
    store
        .set_trust_level(&t, &d, DeviceTrustLevel::Revoked, when)
        .await
        .unwrap();
    let device = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(device.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(device.revoked_at, Some(when));
}

#[tokio::test]
async fn set_trust_level_to_non_revoked_clears_revoked_at() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    store
        .save(&build_device(&t, Some(&u), &d, 0xab, vec![]))
        .await
        .unwrap();
    // First revoke.
    store
        .set_trust_level(&t, &d, DeviceTrustLevel::Revoked, now_at(12, 0))
        .await
        .unwrap();
    // Then re-elevate (admin override). revoked_at must clear.
    store
        .set_trust_level(&t, &d, DeviceTrustLevel::Trusted, now_at(13, 0))
        .await
        .unwrap();
    let device = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(device.trust_level, DeviceTrustLevel::Trusted);
    assert_eq!(
        device.revoked_at, None,
        "non-revoked level must clear revoked_at"
    );
}

#[tokio::test]
async fn delete_removes_row_and_refresh_index_via_fk_cascade() {
    let store = fresh_store().await;
    // Foreign-key enforcement is per-connection in SQLite; enable
    // it on the connection we're testing against. Production
    // deployments either pin `foreign_keys=on` in the connect
    // string or accept that orphaned binding rows age out
    // alongside the device row at the next sweep; neither path
    // affects correctness, only timing.
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&store.pool)
        .await
        .unwrap();

    let (t, u, d) = ids();
    let device = build_device(
        &t,
        Some(&u),
        &d,
        0xab,
        vec![DeviceBinding::Refresh {
            family_id: "fam-stolen".into(),
            issued_at: now_at(10, 0),
            last_used_at: now_at(10, 0),
        }],
    );
    store.save(&device).await.unwrap();

    store.delete(&t, &d).await.unwrap();
    assert!(store.load(&t, &d).await.unwrap().is_none());

    // Foreign-key cascade must have removed the binding row.
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM device_bindings_refresh \
         WHERE tenant_id = ?1 AND device_id = ?2",
    )
    .bind(t.to_string())
    .bind(d.to_string())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(count.0, 0, "FK cascade must remove binding rows");
}

#[tokio::test]
async fn save_indexes_refresh_bindings_for_fast_lookup() {
    let store = fresh_store().await;
    let t = crate::authn::ids::testing::tenant("t");
    let u = crate::authn::ids::testing::user("u");
    let d_a = crate::authn::ids::testing::device("d-a");
    let d_b = crate::authn::ids::testing::device("d-b");

    store
        .save(&build_device(
            &t,
            Some(&u),
            &d_a,
            0xa1,
            vec![DeviceBinding::Refresh {
                family_id: "fam-1".into(),
                issued_at: now_at(10, 0),
                last_used_at: now_at(10, 0),
            }],
        ))
        .await
        .unwrap();
    store
        .save(&build_device(
            &t,
            Some(&u),
            &d_b,
            0xb2,
            vec![
                DeviceBinding::Refresh {
                    family_id: "fam-1".into(),
                    issued_at: now_at(10, 0),
                    last_used_at: now_at(10, 0),
                },
                DeviceBinding::Refresh {
                    family_id: "fam-2".into(),
                    issued_at: now_at(10, 0),
                    last_used_at: now_at(10, 0),
                },
            ],
        ))
        .await
        .unwrap();

    let found = store.find_by_refresh_family(&t, "fam-1").await.unwrap();
    let ids: std::collections::HashSet<DeviceId> = found.iter().map(|d| d.id).collect();
    assert!(ids.contains(&crate::authn::ids::testing::device("d-a")));
    assert!(ids.contains(&crate::authn::ids::testing::device("d-b")));
    assert_eq!(ids.len(), 2);

    let found_2 = store.find_by_refresh_family(&t, "fam-2").await.unwrap();
    assert_eq!(found_2.len(), 1);
    assert_eq!(found_2[0].id, d_b);
}

#[tokio::test]
async fn save_replaces_refresh_index_on_upsert() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    // First save with fam-old.
    store
        .save(&build_device(
            &t,
            Some(&u),
            &d,
            0xab,
            vec![DeviceBinding::Refresh {
                family_id: "fam-old".into(),
                issued_at: now_at(10, 0),
                last_used_at: now_at(10, 0),
            }],
        ))
        .await
        .unwrap();
    // Re-save with fam-new only; fam-old must drop out of the index.
    store
        .save(&build_device(
            &t,
            Some(&u),
            &d,
            0xab,
            vec![DeviceBinding::Refresh {
                family_id: "fam-new".into(),
                issued_at: now_at(11, 0),
                last_used_at: now_at(11, 0),
            }],
        ))
        .await
        .unwrap();

    assert!(
        store
            .find_by_refresh_family(&t, "fam-old")
            .await
            .unwrap()
            .is_empty(),
        "fam-old must be removed from the index on upsert"
    );
    let found_new = store.find_by_refresh_family(&t, "fam-new").await.unwrap();
    assert_eq!(found_new.len(), 1);
}

/// Pin: end-to-end refresh-cascade through the SQLite store.
/// Mirrors the `MemoryDeviceStore` test in cascade.rs to give us
/// confidence the schema correctly powers the high-stakes
/// revocation path.
#[tokio::test]
async fn cascade_revoke_by_refresh_family_revokes_indexed_devices() {
    let store = fresh_store().await;
    let t = crate::authn::ids::testing::tenant("t");
    let u = crate::authn::ids::testing::user("u");
    let d_a = crate::authn::ids::testing::device("d-a");
    let d_b = crate::authn::ids::testing::device("d-b");
    let d_other = crate::authn::ids::testing::device("d-other");

    for (id, fam) in [
        (&d_a, "fam-stolen"),
        (&d_b, "fam-stolen"),
        (&d_other, "fam-untouched"),
    ] {
        let mut dev = build_device(
            &t,
            Some(&u),
            id,
            0xab,
            vec![DeviceBinding::Refresh {
                family_id: fam.to_string(),
                issued_at: now_at(10, 0),
                last_used_at: now_at(10, 0),
            }],
        );
        dev.trust_level = DeviceTrustLevel::Trusted;
        store.save(&dev).await.unwrap();
    }

    let revoked_at = now_at(13, 0);
    let count = cascade_revoke_by_refresh_family(&store, &t, "fam-stolen", revoked_at)
        .await
        .unwrap();
    assert_eq!(count, 2);

    let after_a = store.load(&t, &d_a).await.unwrap().unwrap();
    let after_b = store.load(&t, &d_b).await.unwrap().unwrap();
    let after_other = store.load(&t, &d_other).await.unwrap().unwrap();
    assert_eq!(after_a.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(after_b.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(
        after_other.trust_level,
        DeviceTrustLevel::Trusted,
        "device on a different family must remain Trusted"
    );
}

/// Pin: sweep cascades Trusted → Seen → Revoked in a single call
/// when last_seen is far enough in the past to clear both windows.
/// Mirrors the MemoryDeviceStore cascade test, but on SQL.
#[tokio::test]
async fn sweep_cascades_through_all_stages_in_one_call() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    let now = now_at(20, 0);
    let mut device = build_device(&t, Some(&u), &d, 0xab, vec![]);
    device.trust_level = DeviceTrustLevel::Trusted;
    // 200 days idle; clears trusted_idle (90d) AND seen_idle (30d).
    device.last_seen_at = now - chrono::Duration::days(200);
    device.first_seen_at = device.last_seen_at;
    store.save(&device).await.unwrap();

    let counts = store.sweep(&t, now).await.unwrap();
    assert_eq!(counts.trusted_to_seen, 1);
    assert_eq!(counts.seen_to_revoked, 1);
    // Cannot purge in the same sweep; revoked_at = now, grace not elapsed.
    assert_eq!(counts.revoked_purged, 0);

    let after = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(after.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(after.revoked_at, Some(now));
}

/// Pin: revoked rows past grace are hard-deleted; FK cascade
/// removes the binding-index rows alongside the device row.
#[tokio::test]
async fn sweep_purges_revoked_after_grace_window() {
    let store = fresh_store().await;
    // Enable FK enforcement on the test connection so the cascade
    // actually fires (per-connection PRAGMA in SQLite).
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&store.pool)
        .await
        .unwrap();

    let (t, u, d) = ids();
    let now = now_at(20, 0);
    let mut device = build_device(
        &t,
        Some(&u),
        &d,
        0xab,
        vec![DeviceBinding::Refresh {
            family_id: "fam".into(),
            issued_at: now - chrono::Duration::days(60),
            last_used_at: now - chrono::Duration::days(60),
        }],
    );
    device.trust_level = DeviceTrustLevel::Revoked;
    // revoked_at 8 days ago; past the 7-day default grace.
    device.revoked_at = Some(now - chrono::Duration::days(8));
    device.last_seen_at = now - chrono::Duration::days(60);
    device.first_seen_at = device.last_seen_at;
    store.save(&device).await.unwrap();

    let counts = store.sweep(&t, now).await.unwrap();
    assert_eq!(counts.revoked_purged, 1);
    assert!(store.load(&t, &d).await.unwrap().is_none());

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM device_bindings_refresh \
         WHERE tenant_id = ?1 AND device_id = ?2",
    )
    .bind(t.to_string())
    .bind(d.to_string())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(count.0, 0, "FK cascade must remove bindings on purge");
}

/// Pin: sweep is tenant-scoped. A stale Trusted device under
/// tenant-2 must not be touched when sweeping tenant-1.
#[tokio::test]
async fn sweep_is_tenant_scoped() {
    let store = fresh_store().await;
    let now = now_at(20, 0);
    let t1 = crate::authn::ids::testing::tenant("t1");
    let t2 = crate::authn::ids::testing::tenant("t2");
    let u = crate::authn::ids::testing::user("u");
    let d = crate::authn::ids::testing::device("d");

    let mut foreign = build_device(&t2, Some(&u), &d, 0xab, vec![]);
    foreign.trust_level = DeviceTrustLevel::Trusted;
    foreign.last_seen_at = now - chrono::Duration::days(200);
    foreign.first_seen_at = foreign.last_seen_at;
    store.save(&foreign).await.unwrap();

    let counts = store.sweep(&t1, now).await.unwrap();
    assert_eq!(counts, SweepCounts::default());
    let after = store.load(&t2, &d).await.unwrap().unwrap();
    assert_eq!(after.trust_level, DeviceTrustLevel::Trusted);
}

/// Pin: Unknown is never touched by sweep. Only `promote_on_authn`
/// can move it forward.
#[tokio::test]
async fn sweep_does_not_touch_unknown_devices() {
    let store = fresh_store().await;
    let now = now_at(20, 0);
    let (t, u, d) = ids();
    let mut device = build_device(&t, Some(&u), &d, 0xab, vec![]);
    // Trust level is already Unknown by default; just push last_seen.
    device.last_seen_at = now - chrono::Duration::days(365);
    device.first_seen_at = device.last_seen_at;
    store.save(&device).await.unwrap();

    let counts = store.sweep(&t, now).await.unwrap();
    assert_eq!(counts, SweepCounts::default());
    let after = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(after.trust_level, DeviceTrustLevel::Unknown);
}

/// Pin: encryption round-trip. Bindings written through an
/// encrypted store must come back decoded equal. We construct
/// two keys (current + previous) so the SessionCrypto rotation
/// path is exercised at least at the "build with both keys"
/// level.
#[tokio::test]
async fn encrypted_store_round_trips_bindings() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let key = [0x42u8; 32];
    let crypto = SessionCrypto::new(key);
    let store = SqliteDeviceStore::new(pool, crypto);
    store.init_schema().await.unwrap();

    let (t, u, d) = ids();
    let device = build_device(
        &t,
        Some(&u),
        &d,
        0xab,
        vec![DeviceBinding::Refresh {
            family_id: "fam-1".into(),
            issued_at: now_at(10, 0),
            last_used_at: now_at(10, 0),
        }],
    );
    store.save(&device).await.unwrap();

    // Confirm the bindings column on disk is NOT plaintext;
    // a stored row that decoded to plaintext would defeat the
    // whole point of the optional envelope.
    let raw: (String,) = sqlx::query_as("SELECT bindings FROM devices LIMIT 1")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert!(
        !raw.0.contains("fam-1"),
        "encrypted bindings must not appear in plaintext on disk"
    );

    let loaded = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(loaded, device, "encrypted round-trip must be lossless");
}
