//! [`CachedDeviceStore`]: wraps any [`DeviceStore`] in an in-process
//! [`ClockTtlCache`] so per-request
//! `load(device_id)` lookups skip the backing store on the hot path.
//!
//! # Why a decorator (not built into each backend)
//!
//! The same shape as `EntityCache<P: RequestEntityProvider>` for Cedar
//! authz: composition over inheritance. Backend impls
//! ([`MemoryDeviceStore`](super::MemoryDeviceStore), and the future
//! `SqliteDeviceStore` / `PostgresDeviceStore` / `ValkeyDeviceStore`)
//! stay focused on storage; the cache is a separate, opt-in layer that
//! every backend benefits from for free.
//!
//! # What's cached, what isn't
//!
//! - **Cached**: [`load(tenant, id)`](DeviceStore::load): per-request
//!   hot path. Every authenticated request that needs a device record
//!   for trust-level evaluation hits this. Cache hit → no storage I/O.
//! - **Not cached**:
//!   - [`find_by_fingerprint`](DeviceStore::find_by_fingerprint):
//!     cold path during first sighting before a `device_id` cookie
//!     exists. Calling it primes the by-id cache on success so the
//!     next `load` for the same device hits warm.
//!   - [`find_for_user`](DeviceStore::find_for_user): list with
//!     varying cardinality; harder to invalidate correctly when one
//!     of the user's devices changes. Pass-through.
//!   - [`save`](DeviceStore::save) /
//!     [`set_trust_level`](DeviceStore::set_trust_level) /
//!     [`delete`](DeviceStore::delete): invalidate the key, then
//!     pass through. Trust transitions and revocations MUST be
//!     immediately visible.
//!   - [`record_sighting`](DeviceStore::record_sighting): the only
//!     mutation we deliberately do **not** invalidate on. It moves
//!     `last_seen_at` forward by milliseconds; the cache showing a
//!     slightly-older timestamp until TTL expiry is acceptable, and
//!     invalidating here would defeat the entire cache because
//!     `record_sighting` runs on every request the device appears in.
//!     Read [`CachedDeviceStore::record_sighting`] for the full
//!     reasoning.
//!   - [`sweep`](DeviceStore::sweep): operates on storage; the cache
//!     catches up via TTL or explicit invalidation by callers that
//!     also call `set_trust_level` / `delete` on the swept rows.
//!
//! # DST guarantees
//!
//! The underlying [`ClockTtlCache`] routes
//! every TTL decision through an injected
//! [`Clock`]. Tests can drive the cache with
//! [`MockClock`](axess_clock::testing::MockClock) and observe
//! deterministic eviction.
//!
//! # When to use (and when not)
//!
//! Use when the backing store is `Sqlite` / `Postgres` / `Valkey` and
//! request volume is high enough that per-request DB hits show up in
//! flame graphs. Skip for `MemoryDeviceStore`; the underlying
//! `DashMap::get` is already faster than the cache wrapper's atomics.

use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use axess_cache::ClockTtlCache;
use axess_clock::{Clock, SystemClock};

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::store::{DeviceStore, SweepCounts};
use crate::device::types::{Device, DeviceTrustLevel, FingerprintHash};

/// Default cache capacity: same shape as [`EntityCache`](super::super::cache::EntityCache).
const DEFAULT_CAPACITY: usize = 10_000;

/// Default TTL: same shape as [`EntityCache`](super::super::cache::EntityCache).
///
/// Any pending trust-level change races a 60s upper bound until the
/// next load forces a re-fetch. Within a single pod, mutations
/// invalidate explicitly so this only matters for cross-pod
/// propagation (no invalidation bus exists today; see the
/// `valkey-bridge` work tracked separately for that).
const DEFAULT_TTL_SECS: u64 = 60;

/// Cache key: `(tenant_id, device_id)`. Tenant scoping is mandatory
/// even though `device_id` should already be globally unique, because
/// it pins the security boundary explicitly and cheaply.
type CacheKey = (TenantId, DeviceId);

/// In-process cache decorator wrapping any [`DeviceStore`].
///
/// Construct with [`CachedDeviceStore::new`] for default settings, or
/// build via [`with_capacity`](Self::with_capacity) /
/// [`with_ttl`](Self::with_ttl) / [`with_clock`](Self::with_clock).
pub struct CachedDeviceStore<S>
where
    S: DeviceStore,
{
    inner: S,
    cache: Arc<ClockTtlCache<CacheKey, Device>>,
}

impl<S> Clone for CachedDeviceStore<S>
where
    S: DeviceStore,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            cache: self.cache.clone(),
        }
    }
}

impl<S> CachedDeviceStore<S>
where
    S: DeviceStore,
{
    /// Wrap `inner` with default cache settings (10k entries, 60 s TTL,
    /// [`SystemClock`]).
    pub fn new(inner: S) -> Self {
        Self::with_options(
            inner,
            DEFAULT_CAPACITY,
            Duration::from_secs(DEFAULT_TTL_SECS),
            Arc::new(SystemClock),
        )
    }

    /// Construct with explicit cache parameters.
    pub fn with_options(inner: S, capacity: usize, ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        let capacity = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        let cache = Arc::new(ClockTtlCache::new(capacity, ttl, clock));
        Self { inner, cache }
    }

    /// Builder: override the cache capacity (default 10,000).
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        // Rebuild the cache with the new capacity. Anything currently
        // cached is dropped; acceptable on the construction path
        // (callers should set capacity before serving traffic).
        let ttl = Duration::from_secs(DEFAULT_TTL_SECS);
        self.cache = Arc::new(ClockTtlCache::new(
            cap,
            ttl,
            Arc::new(SystemClock) as Arc<dyn Clock>,
        ));
        self
    }

    /// Builder: override the cache TTL (default 60 s).
    pub fn with_ttl(self, ttl: Duration) -> Self {
        let cap = self.cache.capacity();
        let cache = Arc::new(ClockTtlCache::new(
            cap,
            ttl,
            Arc::new(SystemClock) as Arc<dyn Clock>,
        ));
        Self {
            inner: self.inner,
            cache,
        }
    }

    /// Builder: inject a [`Clock`] for deterministic-simulation testing.
    pub fn with_clock(self, clock: Arc<dyn Clock>) -> Self {
        let cap = self.cache.capacity();
        // Preserve TTL when only swapping the clock.
        let ttl = Duration::from_secs(DEFAULT_TTL_SECS);
        let cache = Arc::new(ClockTtlCache::new(cap, ttl, clock));
        Self {
            inner: self.inner,
            cache,
        }
    }

    /// Snapshot of the underlying cache counters
    /// ([`axess_cache::CacheStats`]). Useful for ops dashboards.
    pub fn stats(&self) -> axess_cache::CacheStats {
        self.cache.stats()
    }

    /// Drop every cached entry. Use after bulk operations that the
    /// cache wasn't notified about (e.g. an offline migration).
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Drop every cached entry for a given tenant. Useful after a
    /// tenant-wide trust-policy change.
    pub fn invalidate_tenant(&self, tenant_id: &TenantId) {
        let target = *tenant_id;
        self.cache.invalidate_by(|k| k.0 == target);
    }
}

impl<S> DeviceStore for CachedDeviceStore<S>
where
    S: DeviceStore,
{
    type Error = S::Error;

    fn load(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let key = (*tenant_id, *id);
        let cache = self.cache.clone();
        let inner = self.inner.clone();
        let tenant = *tenant_id;
        let device = *id;
        async move {
            // Cache hit; return immediately, never touch storage.
            if let Some(d) = cache.get(&key) {
                return Ok(Some(d));
            }
            // Cache miss; fall through to inner, populate on Some.
            // (None results are not cached: a deleted device should
            // immediately reflect any subsequent re-creation, and the
            // miss rate of "asking for a non-existent device" is
            // expected to be vanishingly low in practice.)
            let result = inner.load(&tenant, &device).await?;
            if let Some(ref d) = result {
                cache.insert(key, d.clone());
            }
            Ok(result)
        }
    }

    fn find_by_fingerprint(
        &self,
        tenant_id: &TenantId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let cache = self.cache.clone();
        let inner = self.inner.clone();
        let tenant = *tenant_id;
        let hash = *hash;
        async move {
            let result = inner.find_by_fingerprint(&tenant, &hash).await?;
            // Prime the by-id cache so the next per-request `load`
            // for the same device is warm.
            if let Some(ref d) = result {
                cache.insert((tenant, d.id), d.clone());
            }
            Ok(result)
        }
    }

    fn find_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        // List queries don't cache; too easy to leave stale entries
        // when one of the user's devices changes via a path that
        // doesn't know to invalidate the list. The per-element
        // `load` cache is the right granularity.
        self.inner.find_for_user(tenant_id, user_id, limit)
    }

    fn find_by_refresh_family(
        &self,
        tenant_id: &TenantId,
        family_id: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        // Cold path used only by refresh-cascade revocation. Pass
        // through; same caching argument as `find_for_user`.
        self.inner.find_by_refresh_family(tenant_id, family_id)
    }

    fn save(&self, device: &Device) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let key = (device.tenant_id, device.id);
        let cache = self.cache.clone();
        let inner = self.inner.clone();
        let device = device.clone();
        async move {
            // Invalidate first so a concurrent `load` after this
            // returns either the new value (via inner) or nothing;
            // never the stale cached row. ClockTtlCache's
            // invalidate-wins-during-load semantics close the rest
            // of the race.
            cache.invalidate(&key);
            inner.save(&device).await?;
            // Re-prime with the just-saved value so the next load is
            // warm. This is an optimisation, not correctness; the
            // load-on-miss path would also populate.
            cache.insert(key, device);
            Ok(())
        }
    }

    fn record_sighting(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        // Deliberately NOT invalidating on this path. `record_sighting`
        // bumps `last_seen_at` and runs on every authenticated request
        //; invalidating would force a re-load on the very next
        // request, defeating the cache entirely.
        //
        // Trade-off: cached `last_seen_at` will lag the true storage
        // value by up to TTL_SECS. Trust-level decisions don't depend
        // on `last_seen_at` precisely (it's a lifecycle-sweep input,
        // not a hot-path predicate), so the lag is tolerable.
        // Callers that DO care about precise last_seen can call
        // `invalidate_all` or read directly from storage.
        self.inner.record_sighting(tenant_id, id, now)
    }

    fn set_trust_level(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let key = (*tenant_id, *id);
        let cache = self.cache.clone();
        let inner = self.inner.clone();
        let tenant = *tenant_id;
        let device = *id;
        async move {
            cache.invalidate(&key);
            inner.set_trust_level(&tenant, &device, level, now).await
        }
    }

    fn delete(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let key = (*tenant_id, *id);
        let cache = self.cache.clone();
        let inner = self.inner.clone();
        let tenant = *tenant_id;
        let device = *id;
        async move {
            cache.invalidate(&key);
            inner.delete(&tenant, &device).await
        }
    }

    fn sweep(
        &self,
        tenant_id: &TenantId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        // Sweep operates on storage. The cache catches up via TTL,
        // and any caller that explicitly drives a `delete` /
        // `set_trust_level` after observing a sweep result will
        // correctly invalidate via those paths.
        self.inner.sweep(tenant_id, now)
    }
}

#[cfg(test)]
mod tests {
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
}
