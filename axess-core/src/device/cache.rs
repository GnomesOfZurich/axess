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
//!     exists. It does not prime the by-id cache: a row read here can
//!     be overtaken by a revocation before it is stored, and a stale
//!     `Trusted` row must never be put back.
//!   - [`find_for_user`](DeviceStore::find_for_user): list with
//!     varying cardinality; harder to invalidate correctly when one
//!     of the user's devices changes. Pass-through.
//!   - [`save`](DeviceStore::save) /
//!     [`set_trust_level`](DeviceStore::set_trust_level) /
//!     [`delete`](DeviceStore::delete): write to storage, then
//!     invalidate the key. Invalidating after the write (and not
//!     before) means a load that read the old row while the write was
//!     in flight cannot leave it cached. Trust transitions and
//!     revocations MUST be immediately visible.
//!   - [`record_sighting`](DeviceStore::record_sighting): the only
//!     mutation we deliberately do **not** invalidate on. It moves
//!     `last_seen_at` forward by milliseconds; the cache showing a
//!     slightly-older timestamp until TTL expiry is acceptable, and
//!     invalidating here would defeat the entire cache because
//!     `record_sighting` runs on every request the device appears in.
//!     Read [`CachedDeviceStore::record_sighting`] for the full
//!     reasoning.
//!   - [`sweep`](DeviceStore::sweep): operates on storage; every
//!     cached row of the swept tenant is dropped afterwards, because
//!     the sweep demotes, revokes and purges rows the cache cannot see.
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
use crate::device::store::{BindingsUpdate, DeviceStore, OwnerClaim, SweepCounts, TrustTransition};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};

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

/// Drops a cached row when it goes out of scope, however the write it
/// guards ends: it returns, fails, or the future running it is dropped at
/// an `await` after the store has committed. The row is invalidated after
/// the write either way (a guard dropped on completion runs after the
/// write, like an explicit call would), and a cancelled write can no longer
/// leave the pre-write row cached for a full TTL.
struct InvalidateOnDrop {
    cache: Arc<ClockTtlCache<CacheKey, Device>>,
    key: CacheKey,
}

impl Drop for InvalidateOnDrop {
    fn drop(&mut self) {
        self.cache.invalidate(&self.key);
    }
}

/// [`InvalidateOnDrop`] for every cached row of one tenant, for the sweep.
struct InvalidateTenantOnDrop {
    cache: Arc<ClockTtlCache<CacheKey, Device>>,
    tenant: TenantId,
}

impl Drop for InvalidateTenantOnDrop {
    fn drop(&mut self) {
        let tenant = self.tenant;
        self.cache.invalidate_by(|k| k.0 == tenant);
    }
}

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
    capacity: NonZeroUsize,
    ttl: Duration,
    clock: Arc<dyn Clock>,
}

impl<S> Clone for CachedDeviceStore<S>
where
    S: DeviceStore,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            cache: self.cache.clone(),
            capacity: self.capacity,
            ttl: self.ttl,
            clock: self.clock.clone(),
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
        let cache = Arc::new(ClockTtlCache::new(capacity, ttl, clock.clone()));
        Self {
            inner,
            cache,
            capacity,
            ttl,
            clock,
        }
    }

    /// Rebuild the cache from the current settings. Anything cached is
    /// dropped; the builders below run before the store serves traffic.
    fn rebuilt(mut self) -> Self {
        self.cache = Arc::new(ClockTtlCache::new(
            self.capacity,
            self.ttl,
            self.clock.clone(),
        ));
        self
    }

    /// Builder: override the cache capacity (default 10,000). Keeps the
    /// TTL and clock set so far.
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        self.rebuilt()
    }

    /// Builder: override the cache TTL (default 60 s). Keeps the
    /// capacity and clock set so far.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self.rebuilt()
    }

    /// Builder: inject a [`Clock`] for deterministic-simulation testing.
    /// Keeps the capacity and TTL set so far.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self.rebuilt()
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
            // Single-flight through the cache: a concurrent write that
            // invalidates the key removes this in-flight load, so a row
            // read before a revocation is never promoted into the cache
            // after it. `None` results are not cached: a deleted device
            // should immediately reflect any subsequent re-creation.
            let loaded = cache
                .get_or_try_insert_with(key, || async {
                    match inner.load(&tenant, &device).await {
                        Ok(Some(d)) => Ok(d),
                        Ok(None) => Err(None),
                        Err(e) => Err(Some(e)),
                    }
                })
                .await;
            match loaded {
                Ok(d) => Ok(Some(d)),
                Err(None) => Ok(None),
                Err(Some(e)) => Err(e),
            }
        }
    }

    fn find_by_fingerprint(
        &self,
        tenant_id: &TenantId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        // Pass-through, deliberately not priming the by-id cache: the
        // row read here may be overtaken by a revocation before it
        // could be stored, and a stale row must never be re-cached.
        self.inner.find_by_fingerprint(tenant_id, hash)
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

    fn find_by_fingerprint_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        // Forwarded so the inner store's indexed lookup is used rather
        // than the trait's scan-based default. Not cached, for the same
        // reason as `find_for_user`.
        self.inner
            .find_by_fingerprint_for_user(tenant_id, user_id, hash)
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

    fn save(
        &self,
        device: &Device,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let key = (device.tenant_id, device.id);
        let cache = self.cache.clone();
        let inner = self.inner.clone();
        let device = device.clone();
        async move {
            // Write first, then invalidate: a load that read the old
            // row while the write was in flight is dropped by the
            // invalidation instead of staying cached. The invalidation
            // runs on failure too, since the stored row is then unknown.
            let _guard = InvalidateOnDrop { cache, key };
            inner.save(&device, now).await
        }
    }

    fn record_sighting(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<DeviceTrustLevel, Self::Error>> + Send {
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
            let _guard = InvalidateOnDrop { cache, key };
            inner.set_trust_level(&tenant, &device, level, now).await
        }
    }

    fn set_trust_level_if(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<TrustTransition, Self::Error>> + Send {
        let key = (*tenant_id, *id);
        let cache = self.cache.clone();
        let inner = self.inner.clone();
        let tenant = *tenant_id;
        let device = *id;
        async move {
            let _guard = InvalidateOnDrop { cache, key };
            inner
                .set_trust_level_if(&tenant, &device, expected, level, now)
                .await
        }
    }

    fn replace_bindings(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<BindingsUpdate, Self::Error>> + Send {
        let key = (*tenant_id, *id);
        let cache = self.cache.clone();
        let inner = self.inner.clone();
        let tenant = *tenant_id;
        let device = *id;
        let expected = expected.to_vec();
        let bindings = bindings.to_vec();
        async move {
            let _guard = InvalidateOnDrop { cache, key };
            inner
                .replace_bindings(&tenant, &device, &expected, &bindings, now)
                .await
        }
    }

    fn claim_owner(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<OwnerClaim, Self::Error>> + Send {
        let key = (*tenant_id, *id);
        let cache = self.cache.clone();
        let inner = self.inner.clone();
        let tenant = *tenant_id;
        let device = *id;
        let user = *user;
        async move {
            let _guard = InvalidateOnDrop { cache, key };
            inner.claim_owner(&tenant, &device, &user, now).await
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
            let _guard = InvalidateOnDrop { cache, key };
            inner.delete(&tenant, &device).await
        }
    }

    fn sweep(
        &self,
        tenant_id: &TenantId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        // The sweep demotes, revokes and purges rows the cache cannot
        // see, so drop the tenant's cached rows once it has run, also
        // when it failed part-way.
        let cache = self.cache.clone();
        let inner = self.inner.clone();
        let tenant = *tenant_id;
        async move {
            let _guard = InvalidateTenantOnDrop { cache, tenant };
            inner.sweep(&tenant, now).await
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod races;
