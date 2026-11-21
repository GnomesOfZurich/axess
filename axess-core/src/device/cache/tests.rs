//! `tests`: the unit tests of `cache.rs`, kept beside it per the
//! 200-line inline-test rule in AGENTS.md.

use super::*;
use crate::device::store::MemoryDeviceStore;
use crate::device::types::{Device, FingerprintHash};
use axess_clock::Timestamp;
use axess_clock::testing::MockClock;

fn fixed_clock() -> Arc<MockClock> {
    Arc::new(MockClock::at(
        Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap(),
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
        first_seen_at: Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap(),
        last_seen_at: Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap(),
        revoked_at: None,
        demoted_at: None,
        bindings: Vec::new(),
    }
}

#[tokio::test]
async fn load_caches_after_first_hit() {
    let inner = MemoryDeviceStore::new();
    let (t, u, d) = ids();
    inner
        .save(&build_device(&t, &u, &d), crate::device::test_now())
        .await
        .unwrap();

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
    let (t, _, d) = ids();
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
    inner
        .save(&build_device(&t, &u, &d), crate::device::test_now())
        .await
        .unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    // Warm cache.
    drop(cached.load(&t, &d).await.unwrap());

    // Mutate via cached store: trust-level promotion.
    let mut updated = build_device(&t, &u, &d);
    updated.trust_level = DeviceTrustLevel::Trusted;
    cached
        .save(&updated, crate::device::test_now())
        .await
        .unwrap();

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
    inner
        .save(&build_device(&t, &u, &d), crate::device::test_now())
        .await
        .unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    drop(cached.load(&t, &d).await.unwrap()); // warm

    let now = Timestamp::from_utc(2026, 1, 1, 0, 5, 0).unwrap();
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
    inner
        .save(&build_device(&t, &u, &d), crate::device::test_now())
        .await
        .unwrap();

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
    inner
        .save(&build_device(&t, &u, &d), crate::device::test_now())
        .await
        .unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    drop(cached.load(&t, &d).await.unwrap()); // warm
    let stats_before = cached.stats();

    let now = Timestamp::from_utc(2026, 1, 1, 0, 5, 0).unwrap();
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
async fn find_by_fingerprint_does_not_prime_by_id_cache() {
    let inner = MemoryDeviceStore::new();
    let (t, u, d) = ids();
    let device = build_device(&t, &u, &d);
    let fp = device.fingerprint_hash;
    inner
        .save(&device, crate::device::test_now())
        .await
        .unwrap();

    let cached = CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _);
    drop(
        cached
            .find_by_fingerprint(&t, &fp)
            .await
            .unwrap()
            .expect("device found by fingerprint"),
    );

    // The row read by fingerprint may be stale by the time it would be
    // stored, so the next load goes to storage.
    drop(cached.load(&t, &d).await.unwrap());
    assert_eq!(cached.stats().hits, 0, "find_by_fingerprint must not prime");
}

/// Pin: refresh-family cascade revocation propagates through the
/// cache. When the device-only cascade walks N devices
/// and calls `set_trust_level(Revoked)` on each, every cached row
/// must be invalidated so subsequent loads see `Revoked`. Without
/// per-call invalidation we'd serve stale `Trusted` from cache for
/// up to TTL_SECS, a critical security regression after a refresh
/// token theft signal.
#[tokio::test]
async fn refresh_cascade_revocation_propagates_through_cache() {
    use crate::device::cascade::cascade_revoke_devices;
    use crate::device::types::DeviceBinding;

    let inner = MemoryDeviceStore::new();
    let tenant = crate::authn::ids::testing::tenant("tenant-1");
    let user = crate::authn::ids::testing::user("user-1");
    let dev_a = crate::authn::ids::testing::device("dev-a");
    let dev_b = crate::authn::ids::testing::device("dev-b");
    let now = Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap();

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
            demoted_at: None,
            bindings: vec![DeviceBinding::Refresh {
                family_id: "fam-stolen".to_string(),
                issued_at: now,
                last_used_at: now,
            }],
        };
        inner
            .save(&device, crate::device::test_now())
            .await
            .unwrap();
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
    let revoked_at = Timestamp::from_utc(2026, 1, 1, 0, 5, 0).unwrap();
    let bound = cached
        .find_by_refresh_family(&tenant, "fam-stolen")
        .await
        .unwrap();
    let targets: Vec<_> = bound.iter().map(|d| (d.tenant_id, d.id)).collect();
    let count = cascade_revoke_devices(&cached, &targets, revoked_at).await;
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

/// After warming the cache, calling `invalidate_all` must drop every
/// entry, so the next load is a miss for both rows: an
/// `invalidate_all` that did nothing fails here.
#[tokio::test]
async fn invalidate_all_drops_every_entry() {
    let inner = MemoryDeviceStore::new();
    let t1 = crate::authn::ids::testing::tenant("t1");
    let t2 = crate::authn::ids::testing::tenant("t2");
    let u = crate::authn::ids::testing::user("u1");
    let d1 = crate::authn::ids::testing::device("d1");
    let d2 = crate::authn::ids::testing::device("d2");
    inner
        .save(&build_device(&t1, &u, &d1), crate::device::test_now())
        .await
        .unwrap();
    inner
        .save(&build_device(&t2, &u, &d2), crate::device::test_now())
        .await
        .unwrap();

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
    inner
        .save(&build_device(&t1, &u, &d1), crate::device::test_now())
        .await
        .unwrap();
    inner
        .save(&build_device(&t2, &u, &d2), crate::device::test_now())
        .await
        .unwrap();

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

mod races;

/// An adopter's store wrapped around the cache, forwarding every method the
/// trait requires.
#[derive(Clone)]
struct WrappedCache<S: DeviceStore>(CachedDeviceStore<S>);

impl<S: DeviceStore> DeviceStore for WrappedCache<S> {
    type Error = S::Error;

    fn load_fresh(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.0.load_fresh(t, id)
    }

    fn load(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.0.load(t, id)
    }
    fn find_by_fingerprint(
        &self,
        t: &TenantId,
        h: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.0.find_by_fingerprint(t, h)
    }
    fn find_for_user(
        &self,
        t: &TenantId,
        u: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        self.0.find_for_user(t, u, limit)
    }
    fn find_by_refresh_family(
        &self,
        t: &TenantId,
        f: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        self.0.find_by_refresh_family(t, f)
    }
    fn save(
        &self,
        d: &Device,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.0.save(d, now)
    }
    fn create_or_find(
        &self,
        d: &Device,
        now: Timestamp,
    ) -> impl Future<Output = Result<Device, Self::Error>> + Send {
        self.0.create_or_find(d, now)
    }
    fn record_sighting(
        &self,
        t: &TenantId,
        id: &DeviceId,
        now: Timestamp,
    ) -> impl Future<Output = Result<DeviceTrustLevel, Self::Error>> + Send {
        self.0.record_sighting(t, id, now)
    }
    fn set_trust_level(
        &self,
        t: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.0.set_trust_level(t, id, level, now)
    }
    fn set_trust_level_if(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> impl Future<Output = Result<TrustTransition, Self::Error>> + Send {
        self.0.set_trust_level_if(t, id, expected, level, now)
    }
    fn claim_owner(
        &self,
        t: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: Timestamp,
    ) -> impl Future<Output = Result<OwnerClaim, Self::Error>> + Send {
        self.0.claim_owner(t, id, user, now)
    }
    fn replace_bindings(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        now: Timestamp,
    ) -> impl Future<Output = Result<BindingsUpdate, Self::Error>> + Send {
        self.0.replace_bindings(t, id, expected, bindings, now)
    }
    fn delete(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.0.delete(t, id)
    }
    fn sweep(
        &self,
        t: &TenantId,
        now: Timestamp,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        self.0.sweep(t, now)
    }
}

/// The cache, and a store wrapped around it, keep the contract of the three
/// conditional writes, with the calls beneath them made to interleave: two
/// swaps, two trust changes and two claims from one read have one winner.
#[tokio::test]
async fn the_cache_and_a_wrapper_around_it_keep_the_conditional_writes_single() {
    use crate::device::store::consistency as shared;
    use crate::device::store::interleaving::Interleaved;
    let cached = || {
        CachedDeviceStore::new(Interleaved(MemoryDeviceStore::new())).with_clock(fixed_clock() as _)
    };
    shared::two_swaps_from_one_read_have_one_winner(cached()).await;
    shared::two_trust_changes_from_one_level_have_one_winner(cached()).await;
    shared::two_claims_of_one_unowned_device_have_one_winner(cached()).await;
    shared::two_swaps_from_one_read_have_one_winner(WrappedCache(cached())).await;
    shared::two_trust_changes_from_one_level_have_one_winner(WrappedCache(cached())).await;
    shared::two_claims_of_one_unowned_device_have_one_winner(WrappedCache(cached())).await;
}

/// A store wrapped around the cache, implementing what the trait requires
/// and nothing else, reads through on `load_fresh`: a revocation made on
/// the backing store (as another instance makes it) is seen at once, not
/// after the cached row expires.
#[tokio::test]
async fn a_wrapper_around_the_cache_reads_through_on_load_fresh() {
    let inner = MemoryDeviceStore::new();
    let (t, u, d) = ids();
    let mut device = build_device(&t, &u, &d);
    device.trust_level = DeviceTrustLevel::Trusted;
    inner
        .save(&device, crate::device::test_now())
        .await
        .unwrap();
    let wrapped =
        WrappedCache(CachedDeviceStore::new(inner.clone()).with_clock(fixed_clock() as _));

    let warm = wrapped.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(warm.trust_level, DeviceTrustLevel::Trusted);
    inner
        .set_trust_level(&t, &d, DeviceTrustLevel::Revoked, crate::device::test_now())
        .await
        .unwrap();

    let fresh = wrapped.load_fresh(&t, &d).await.unwrap().unwrap();
    assert_eq!(
        fresh.trust_level,
        DeviceTrustLevel::Revoked,
        "load_fresh through the wrapper served the cached row"
    );
}

/// The cache forwards the sweep and drops what it held of the tenant, so the
/// shared sweep contract holds through it: every level read after a sweep is
/// the one that sweep wrote, never the row cached before it.
#[tokio::test]
async fn the_sweep_contract_holds_through_the_cache() {
    use crate::device::store::consistency as shared;
    let inner = MemoryDeviceStore::new().with_sweep_config(shared::ladder_config());
    shared::a_sweep_walks_the_ladder_and_counts_what_it_wrote(
        CachedDeviceStore::new(inner).with_clock(fixed_clock() as _),
    )
    .await;
}
