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
//! `MockClock` and observe
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
mod tests;
