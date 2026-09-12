//! `tests`: extracted from `cache.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use crate::device::store::MemoryDeviceStore;
use crate::device::types::{Device, FingerprintHash};
use axess_clock::testing::MockClock;
use chrono::TimeZone;

fn fixed_clock() -> Arc<MockClock> {
    Arc::new(MockClock::at(
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
    ))
}

fn ids() -> (TenantId, UserId, DeviceId) {
    (
        crate::authn::ids::testing::tenant("tenant-1"),
        crate::authn::ids::testing::user("user-1"),
        crate::authn::ids::testing::device("device-1"),
    )
}

fn build_device(t: &TenantId, u: &UserId, d: &DeviceId) -> Device {
    Device {
        id: *d,
        tenant_id: *t,
        user_id: Some(*u),
        trust_level: DeviceTrustLevel::Seen,
        fingerprint_hash: FingerprintHash::from_bytes([0u8; 32]),
        first_seen_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        last_seen_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        revoked_at: None,
        bindings: Vec::new(),
    }
}

#[tokio::test]
async fn load_caches_after_first_hit() {
    let inner = MemoryDeviceStore::new();
    let (t, u, d) = ids();
    inner.save(&build_device(&t, &u, &d)).await.unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    // First load; cache miss → populates.
    drop(cached.load(&t, &d).await.unwrap().expect("first load"));
    let stats_after_miss = cached.stats();
    assert_eq!(stats_after_miss.misses, 1);
    assert_eq!(stats_after_miss.hits, 0);

    // Second load; cache hit, no storage call.
    drop(cached.load(&t, &d).await.unwrap().expect("second load"));
    let stats_after_hit = cached.stats();
    assert_eq!(stats_after_hit.hits, 1, "second load must hit cache");
}

#[tokio::test]
async fn load_does_not_cache_none_results() {
    let inner = MemoryDeviceStore::new();
    let (t, _u, d) = ids();
    let cached = CachedDeviceStore::new(inner).with_clock(fixed_clock() as _);

    // No device saved; load returns None.
    assert!(cached.load(&t, &d).await.unwrap().is_none());
    // Cache size stays zero; Nones are not cached.
    let stats = cached.stats();
    assert_eq!(stats.inserts, 0, "None results must not be cached");
}

#[tokio::test]
async fn save_invalidates_and_repopulates() {
    let inner = MemoryDeviceStore::new();
    let (t, u, d) = ids();
    inner.save(&build_device(&t, &u, &d)).await.unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    // Warm cache.
    drop(cached.load(&t, &d).await.unwrap());

    // Mutate via cached store: trust-level promotion.
    let mut updated = build_device(&t, &u, &d);
    updated.trust_level = DeviceTrustLevel::Trusted;
    cached.save(&updated).await.unwrap();

    // Next load returns the new value (no stale cached version).
    let loaded = cached.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(
        loaded.trust_level,
        DeviceTrustLevel::Trusted,
        "save must invalidate the cached row so load sees the update"
    );
}

#[tokio::test]
async fn set_trust_level_invalidates_cached_row() {
    let inner = MemoryDeviceStore::new();
    let (t, u, d) = ids();
    inner.save(&build_device(&t, &u, &d)).await.unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    drop(cached.load(&t, &d).await.unwrap()); // warm

    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 5, 0).unwrap();
    cached
        .set_trust_level(&t, &d, DeviceTrustLevel::Revoked, now)
        .await
        .unwrap();

    let loaded = cached.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(
        loaded.trust_level,
        DeviceTrustLevel::Revoked,
        "set_trust_level must invalidate the cached row"
    );
}

#[tokio::test]
async fn delete_invalidates_and_subsequent_load_is_none() {
    let inner = MemoryDeviceStore::new();
    let (t, u, d) = ids();
    inner.save(&build_device(&t, &u, &d)).await.unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    drop(cached.load(&t, &d).await.unwrap()); // warm

    cached.delete(&t, &d).await.unwrap();
    assert!(
        cached.load(&t, &d).await.unwrap().is_none(),
        "delete must invalidate so the next load reflects absence"
    );
}

#[tokio::test]
async fn record_sighting_does_not_invalidate() {
    // Documented behaviour: record_sighting is intentionally NOT a
    // cache-invalidating path, because it runs on every request
    // and would defeat the cache. This test pins that contract.
    let inner = MemoryDeviceStore::new();
    let (t, u, d) = ids();
    inner.save(&build_device(&t, &u, &d)).await.unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    drop(cached.load(&t, &d).await.unwrap()); // warm
    let stats_before = cached.stats();

    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 5, 0).unwrap();
    cached.record_sighting(&t, &d, now).await.unwrap();
    drop(cached.load(&t, &d).await.unwrap()); // should hit cache

    let stats_after = cached.stats();
    assert_eq!(
        stats_after.hits,
        stats_before.hits + 1,
        "record_sighting must not invalidate the cache"
    );
}

#[tokio::test]
async fn find_by_fingerprint_primes_by_id_cache() {
    let inner = MemoryDeviceStore::new();
    let (t, u, d) = ids();
    let device = build_device(&t, &u, &d);
    let fp = device.fingerprint_hash;
    inner.save(&device).await.unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    // Cold fingerprint lookup; pass-through to inner, then primes
    // the by-id cache.
    drop(
        cached
            .find_by_fingerprint(&t, &fp)
            .await
            .unwrap()
            .expect("device found by fingerprint"),
    );

    // Subsequent load hits cache (no second storage round-trip).
    drop(cached.load(&t, &d).await.unwrap());
    let stats = cached.stats();
    assert_eq!(
        stats.hits, 1,
        "find_by_fingerprint must prime the by-id cache so load is warm"
    );
}

/// Pin: refresh-family cascade revocation propagates through the
/// cache. When `cascade_revoke_by_refresh_family` walks N devices
/// and calls `set_trust_level(Revoked)` on each, every cached row
/// must be invalidated so subsequent loads see `Revoked`. Without
/// per-call invalidation we'd serve stale `Trusted` from cache for
/// up to TTL_SECS, a critical security regression after a refresh
/// token theft signal.
#[tokio::test]
async fn refresh_cascade_revocation_propagates_through_cache() {
    use crate::device::cascade::cascade_revoke_by_refresh_family;
    use crate::device::types::DeviceBinding;

    let inner = MemoryDeviceStore::new();
    let tenant = crate::authn::ids::testing::tenant("tenant-1");
    let user = crate::authn::ids::testing::user("user-1");
    let dev_a = crate::authn::ids::testing::device("dev-a");
    let dev_b = crate::authn::ids::testing::device("dev-b");
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();

    for (id, fp_byte) in [(&dev_a, 0xa1u8), (&dev_b, 0xb2u8)] {
        let device = Device {
            id: *id,
            tenant_id: tenant,
            user_id: Some(user),
            trust_level: DeviceTrustLevel::Trusted,
            fingerprint_hash: FingerprintHash::from_bytes([fp_byte; 32]),
            first_seen_at: now,
            last_seen_at: now,
            revoked_at: None,
            bindings: vec![DeviceBinding::Refresh {
                family_id: "fam-stolen".to_string(),
                issued_at: now,
                last_used_at: now,
            }],
        };
        inner.save(&device).await.unwrap();
    }

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);

    // Warm the cache for both devices; both Trusted now.
    let warm_a = cached.load(&tenant, &dev_a).await.unwrap().unwrap();
    let warm_b = cached.load(&tenant, &dev_b).await.unwrap().unwrap();
    assert_eq!(warm_a.trust_level, DeviceTrustLevel::Trusted);
    assert_eq!(warm_b.trust_level, DeviceTrustLevel::Trusted);

    // Refresh-family compromise → cascade revocation through the
    // cached store. Every device bound to `fam-stolen` must end up
    // Revoked, and the cache must reflect that on the next load.
    let revoked_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 5, 0).unwrap();
    let count = cascade_revoke_by_refresh_family(&cached, &tenant, "fam-stolen", revoked_at)
        .await
        .unwrap();
    assert_eq!(count, 2, "both refresh-bound devices must be revoked");

    // Critical: subsequent loads MUST see Revoked, not stale Trusted.
    let after_a = cached.load(&tenant, &dev_a).await.unwrap().unwrap();
    let after_b = cached.load(&tenant, &dev_b).await.unwrap().unwrap();
    assert_eq!(
        after_a.trust_level,
        DeviceTrustLevel::Revoked,
        "cache must not serve stale Trusted after cascade revocation"
    );
    assert_eq!(
        after_b.trust_level,
        DeviceTrustLevel::Revoked,
        "cache must not serve stale Trusted after cascade revocation"
    );
}

/// mutant kill: pin `invalidate_all` against a no-op
/// replacement. After warming the cache, calling `invalidate_all`
/// must drop every entry so the next load is a miss for both
/// rows.
#[tokio::test]
async fn invalidate_all_drops_every_entry() {
    let inner = MemoryDeviceStore::new();
    let t1 = crate::authn::ids::testing::tenant("t1");
    let t2 = crate::authn::ids::testing::tenant("t2");
    let u = crate::authn::ids::testing::user("u1");
    let d1 = crate::authn::ids::testing::device("d1");
    let d2 = crate::authn::ids::testing::device("d2");
    inner.save(&build_device(&t1, &u, &d1)).await.unwrap();
    inner.save(&build_device(&t2, &u, &d2)).await.unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    drop(cached.load(&t1, &d1).await.unwrap());
    drop(cached.load(&t2, &d2).await.unwrap());
    let warm = cached.stats();
    assert_eq!(warm.misses, 2, "two cold loads landed two misses");

    cached.invalidate_all();

    // Both rows are gone; the next loads must miss again.
    drop(cached.load(&t1, &d1).await.unwrap());
    drop(cached.load(&t2, &d2).await.unwrap());
    let after = cached.stats();
    assert_eq!(
        after.misses,
        warm.misses + 2,
        "invalidate_all must drop every entry; a no-op mutant would \
             let the second pair of loads hit cache"
    );
}

#[tokio::test]
async fn invalidate_tenant_drops_only_matching_entries() {
    let inner = MemoryDeviceStore::new();
    let t1 = crate::authn::ids::testing::tenant("t1");
    let t2 = crate::authn::ids::testing::tenant("t2");
    let u = crate::authn::ids::testing::user("u1");
    let d1 = crate::authn::ids::testing::device("d1");
    let d2 = crate::authn::ids::testing::device("d2");
    inner.save(&build_device(&t1, &u, &d1)).await.unwrap();
    inner.save(&build_device(&t2, &u, &d2)).await.unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    drop(cached.load(&t1, &d1).await.unwrap());
    drop(cached.load(&t2, &d2).await.unwrap());

    cached.invalidate_tenant(&t1);

    // t1 entry is gone → next load is a miss.
    let stats_before = cached.stats();
    drop(cached.load(&t1, &d1).await.unwrap());
    let stats_after = cached.stats();
    assert_eq!(
        stats_after.misses,
        stats_before.misses + 1,
        "t1 entry should have been invalidated"
    );

    // t2 entry survives → next load is a hit.
    let stats_before2 = cached.stats();
    drop(cached.load(&t2, &d2).await.unwrap());
    let stats_after2 = cached.stats();
    assert_eq!(
        stats_after2.hits,
        stats_before2.hits + 1,
        "t2 entry must survive invalidate_tenant(t1)"
    );
}
