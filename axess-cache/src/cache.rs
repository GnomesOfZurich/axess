//! [`ClockTtlCache`] and its single-flight in-flight machinery.
//!
//! The cache implementation itself lives here; the public counters
//! snapshot is in [`crate::stats`].

use crate::stats::{CacheCounters, CacheStats};
use axess_clock::Clock;
use lru::LruCache;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::OnceCell;

/// Cached value plus the absolute (epoch-µs) instant at which it expires.
///
/// `expires_at_micros` is computed at insert time as `clock.now() + ttl`,
/// then compared against `clock.now()` at every read. Storing the absolute
/// expiry rather than the insert-time + a static TTL means changing the
/// cache's TTL doesn't retroactively re-validate stale entries.
struct Entry<V> {
    value: V,
    expires_at_micros: i64,
}

/// TTL+LRU cache with all time decisions routed through an injected [`Clock`].
///
/// # Capacity vs. TTL
///
/// Two independent eviction triggers:
///
/// - **TTL**: checked on read. Expired entries are removed lazily when
///   touched; [`cleanup_expired`](Self::cleanup_expired) sweeps the whole
///   map for callers who want to reclaim memory eagerly.
/// - **Capacity**: enforced at insert time by [`LruCache`]. Inserting into a
///   full cache evicts the least-recently-used entry.
///
/// # Concurrency
///
/// Internal state is wrapped in a [`parking_lot::Mutex`]. Reads briefly
/// acquire the lock to update LRU recency. The single mutex becomes the
/// bottleneck only once multiple threads contend on the same hot key;
/// `benches/cache_bench.rs` quantifies the regression. A sharded variant
/// is deferred until real profiling shows it matters.
///
/// # DST guarantees
///
/// Every TTL decision and every `expires_at_micros` calculation goes
/// through `clock.now()`. Tests using
/// [`MockClock`](axess_clock::testing::MockClock) can advance time in
/// arbitrary jumps and observe deterministic eviction. There are no
/// background tasks and no calls into `Instant::now()` /
/// `chrono::Utc::now()`.
pub struct ClockTtlCache<K, V>
where
    K: Hash + Eq + Send + Sync,
    V: Clone + Send + Sync,
{
    inner: Mutex<LruCache<K, Entry<V>>>,
    /// In-flight loads for [`Self::get_or_try_insert_with`]. Held under a
    /// dedicated mutex so cache reads aren't blocked by single-flight
    /// bookkeeping. The TOCTOU between this map and `inner` is benign:
    /// the worst case is one extra fetch (which is the work we'd be
    /// doing anyway), and `OnceCell` semantics still guarantee a single
    /// fetcher per cell across concurrent waiters.
    inflight: Mutex<HashMap<K, Arc<OnceCell<V>>>>,
    clock: Arc<dyn Clock>,
    ttl: Duration,
    pub(crate) stats: CacheCounters,
}

impl<K, V> ClockTtlCache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    /// Construct a cache with the given capacity, TTL, and Clock.
    pub fn new(capacity: NonZeroUsize, ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
            inflight: Mutex::new(HashMap::new()),
            clock,
            ttl,
            stats: CacheCounters::default(),
        }
    }

    /// Snapshot of the live observability counters (hits, misses, evictions,
    /// single-flight joins, …). See [`CacheStats`] for field semantics.
    ///
    /// Cheap (atomic loads only); safe to call on the hot path or from a
    /// metrics scrape endpoint.
    pub fn stats(&self) -> CacheStats {
        self.stats.snapshot()
    }

    /// Reset every counter to zero. Useful for tests and for resetting a
    /// metrics window after a scrape; production telemetry pipelines
    /// typically just take rate-of-change of the monotonic counters and
    /// shouldn't need this.
    pub fn reset_stats(&self) {
        self.stats.reset();
    }

    /// Look up a key. Returns `None` if absent or expired (and removes
    /// the expired entry as a side effect; lazy TTL sweep).
    pub fn get(&self, key: &K) -> Option<V> {
        let now_micros = self.clock.now().timestamp_micros();
        let mut guard = self.inner.lock();
        // LruCache::get updates recency, which is what we want on a hit;
        // on an expired-hit we then `pop` to evict.
        if let Some(entry) = guard.get(key) {
            if entry.expires_at_micros >= now_micros {
                let v = entry.value.clone();
                drop(guard);
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Some(v);
            }
        }
        // Either absent or stale. `pop` is a no-op for the absent case;
        // we count both as a miss (TTL-expired hits are semantically
        // misses to the caller; they get None).
        guard.pop(key);
        drop(guard);
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert or replace a value with the configured TTL.
    pub fn insert(&self, key: K, value: V) {
        let now_micros = self.clock.now().timestamp_micros();
        let expires_at_micros = now_micros.saturating_add(self.ttl.as_micros() as i64);
        let mut guard = self.inner.lock();
        let len_before = guard.len();
        let cap = guard.cap().get();
        guard.put(
            key,
            Entry {
                value,
                expires_at_micros,
            },
        );
        // LruCache::put on a full cache evicts the LRU entry to make room.
        // Detect the eviction by checking that we hit (or were already at)
        // capacity and the cache size didn't grow. Counts both
        // "displaced existing key" and "popped LRU" paths; the former
        // is also useful telemetry (tells you about overwrites under
        // capacity pressure).
        let inserted_displaced = len_before >= cap;
        drop(guard);
        self.stats.inserts.fetch_add(1, Ordering::Relaxed);
        if inserted_displaced {
            self.stats
                .capacity_evictions
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Remove a single entry. Also removes any in-flight load cell for
    /// the same key, so a concurrent
    /// [`get_or_try_insert_with`](Self::get_or_try_insert_with) load that
    /// resolves *after* this call cannot re-cache the now-invalidated
    /// value. Returns `true` if anything was removed (cache row, in-flight
    /// cell, or both).
    ///
    /// # Concurrency
    ///
    /// Two separate critical sections: inflight first, then LRU.
    /// Lock-ordering rule (inflight before LRU) is preserved. A concurrent
    /// load whose post-resolve runs *between* our inflight removal and
    /// our LRU removal sees its cell missing from inflight and skips the
    /// LRU promotion (see `get_or_try_insert_with`'s `Ok` arm). A
    /// concurrent load whose post-resolve runs *before* our inflight
    /// removal already inserted into LRU, which our LRU pop then
    /// removes. Both paths converge on "key is not cached afterward."
    pub fn invalidate(&self, key: &K) -> bool {
        let inflight_removed = self.inflight.lock().remove(key).is_some();
        let lru_removed = self.inner.lock().pop(key).is_some();
        let removed = inflight_removed || lru_removed;
        if removed {
            self.stats.invalidations.fetch_add(1, Ordering::Relaxed);
        }
        removed
    }

    /// Remove every cache entry whose key matches `predicate`. Also
    /// removes matching in-flight load cells so concurrent loads
    /// resolving after this call cannot re-cache invalidated values.
    /// Returns the number of cache entries removed (LRU entries only;
    /// in-flight removals are bookkeeping side effects).
    ///
    /// O(n) over the cache plus O(m) over the in-flight map. Use for
    /// "evict everything for principal X" after a role change; small N
    /// for typical caches; if your cardinality is large enough that
    /// this is too slow, consider maintaining a secondary index outside
    /// this primitive.
    #[tracing::instrument(
        name = "axess_cache.invalidate_by",
        skip(self, predicate),
        fields(removed = tracing::field::Empty),
    )]
    pub fn invalidate_by(&self, predicate: impl Fn(&K) -> bool) -> usize {
        // Inflight first, then LRU; lock-ordering rule.
        {
            let mut inflight = self.inflight.lock();
            let to_remove: Vec<K> = inflight.keys().filter(|k| predicate(k)).cloned().collect();
            for k in &to_remove {
                inflight.remove(k);
            }
        }

        let mut guard = self.inner.lock();
        let to_remove: Vec<K> = guard
            .iter()
            .filter_map(|(k, _)| if predicate(k) { Some(k.clone()) } else { None })
            .collect();
        let count = to_remove.len();
        for k in &to_remove {
            guard.pop(k);
        }
        drop(guard);
        if count > 0 {
            self.stats
                .invalidations
                .fetch_add(count as u64, Ordering::Relaxed);
        }
        tracing::Span::current().record("removed", count);
        count
    }

    /// Drop every entry from the cache. Also drops every in-flight load
    /// cell, so any load resolving after this call is barred from
    /// promoting its value to the cache (post-`invalidate_all` cache
    /// state must be empty).
    #[tracing::instrument(
        name = "axess_cache.invalidate_all",
        skip(self),
        fields(removed = tracing::field::Empty),
    )]
    pub fn invalidate_all(&self) {
        // Inflight first, then LRU; lock-ordering rule.
        self.inflight.lock().clear();

        let mut guard = self.inner.lock();
        let count = guard.len();
        guard.clear();
        drop(guard);
        if count > 0 {
            self.stats
                .invalidations
                .fetch_add(count as u64, Ordering::Relaxed);
        }
        tracing::Span::current().record("removed", count);
    }

    /// Walk the cache and remove every expired entry. Returns the number
    /// of entries reclaimed.
    ///
    /// Optional: the cache evicts expired entries lazily on access via
    /// [`get`](Self::get). Call this if you want to reclaim memory ahead
    /// of next access (e.g. from a periodic Clock-aware scheduled task).
    #[tracing::instrument(
        name = "axess_cache.cleanup_expired",
        skip(self),
        fields(removed = tracing::field::Empty),
    )]
    pub fn cleanup_expired(&self) -> usize {
        let now_micros = self.clock.now().timestamp_micros();
        let mut guard = self.inner.lock();
        let to_remove: Vec<K> = guard
            .iter()
            .filter_map(|(k, e)| {
                if e.expires_at_micros < now_micros {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        let count = to_remove.len();
        for k in &to_remove {
            guard.pop(k);
        }
        drop(guard);
        if count > 0 {
            self.stats
                .invalidations
                .fetch_add(count as u64, Ordering::Relaxed);
        }
        tracing::Span::current().record("removed", count);
        count
    }

    /// Load `key` from the cache, or run `fetcher` to populate it.
    /// Single-flight: concurrent calls for the same key share one fetcher
    /// invocation, and the rest await the in-flight cell.
    ///
    /// # Errors
    ///
    /// On `fetcher` error the in-flight cell is removed so subsequent
    /// callers retry rather than re-await a known-failing future. The
    /// error is propagated to every concurrent caller that joined this
    /// in-flight load.
    ///
    /// # Panic safety
    ///
    /// If `fetcher` panics, the in-flight cell is removed via an RAII
    /// guard whose `Drop` runs during panic-unwind. Subsequent callers
    /// for the same key get a fresh fetcher invocation rather than
    /// joining a permanently-uninitialised cell.
    ///
    /// # Interaction with concurrent `invalidate`
    ///
    /// Invalidate wins against concurrent loads. If `invalidate` /
    /// `invalidate_by` / `invalidate_all` runs while a load is in flight
    /// for `key`, the loaded value is **not** promoted to the cache. The
    /// caller that triggered the in-flight load (and joiners) still
    /// receive the loaded value (the load started before the
    /// invalidate), but the cache stays in its post-invalidate state and
    /// the next lookup runs a fresh load. Aborting an in-flight load to
    /// make joiners retry is not possible with [`tokio::sync::OnceCell`]
    /// semantics.
    ///
    /// # Fetcher determinism
    ///
    /// Concurrent callers may each pass a different `fetcher` closure,
    /// but only the first one to reach the cell is invoked; the rest are
    /// dropped. Callers should pass fetchers that are pure functions of
    /// the key, otherwise only the winning caller's side effects fire.
    #[tracing::instrument(
        name = "axess_cache.get_or_try_insert_with",
        skip(self, key, fetcher),
        fields(joined = tracing::field::Empty, error = tracing::field::Empty),
    )]
    pub async fn get_or_try_insert_with<F, Fut, E>(&self, key: K, fetcher: F) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<V, E>>,
    {
        // Fast path: cache hit.
        if let Some(v) = self.get(&key) {
            return Ok(v);
        }

        // Slow path: claim or join an in-flight cell.
        let (cell, joined) = {
            let mut inflight = self.inflight.lock();
            match inflight.get(&key) {
                Some(existing) => (existing.clone(), true),
                None => {
                    let cell = Arc::new(OnceCell::<V>::new());
                    inflight.insert(key.clone(), cell.clone());
                    (cell, false)
                }
            }
        };
        tracing::Span::current().record("joined", joined);
        if joined {
            self.stats
                .single_flight_joins
                .fetch_add(1, Ordering::Relaxed);
        }

        // RAII cleanup of the in-flight slot. Drops on Ok / Err / panic-
        // unwind, ensuring the slot doesn't leak even if `fetcher` panics
        // mid-await. Same `Arc::ptr_eq`-gated removal as before.
        let inflight_guard = InflightGuard {
            cache: self,
            key: key.clone(),
            cell: cell.clone(),
        };

        // Race-resolve: `OnceCell::get_or_try_init` ensures exactly one
        // closure runs across all concurrent callers for this cell.
        // Subsequent callers `.await` the same future internally.
        let result: Result<&V, E> = cell.get_or_try_init(fetcher).await;

        let outcome = match result {
            Ok(v_ref) => {
                let v = v_ref.clone();
                // Atomic publication against `invalidate*`: hold the
                // inflight lock while we (a) check that our cell is still
                // the active one and (b) promote to LRU. Since invalidate
                // *must* take inflight first (lock-ordering rule), it
                // cannot interleave between our check and our LRU insert.
                {
                    let mut inflight = self.inflight.lock();
                    if let Some(existing) = inflight.get(&key)
                        && Arc::ptr_eq(existing, &cell)
                    {
                        // Still our cell. Insert into LRU under inflight
                        // hold so a racing invalidate is forced to wait;
                        // when it does run, it'll then remove the just-
                        // inserted LRU entry, converging on "invalidated."
                        // Critically: when invalidate runs *during* our
                        // load (before this point), the cell is removed
                        // from inflight, so this `if let Some(...)` won't
                        // match and we skip the promotion entirely.
                        self.insert(key.clone(), v.clone());
                        inflight.remove(&key);
                    }
                    // else: either invalidate ran during our load, or
                    // another caller's cleanup ran first. Either way,
                    // refuse to promote.
                };
                // Guard's Drop is now a no-op for the active path (we
                // removed our own slot); for the !active path it's also
                // a no-op (slot was already gone).
                Ok(v)
            }
            Err(e) => {
                self.stats
                    .single_flight_errors
                    .fetch_add(1, Ordering::Relaxed);
                tracing::Span::current().record("error", true);
                // Guard's Drop removes the slot so retries get a fresh
                // fetcher rather than re-awaiting the failed future.
                Err(e)
            }
        };
        drop(inflight_guard);
        outcome
    }

    /// Current number of entries (including any that are expired but not
    /// yet evicted by a read or [`cleanup_expired`](Self::cleanup_expired)).
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// `true` if the cache holds zero entries.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().len() == 0
    }

    /// Configured capacity (LRU bound).
    pub fn capacity(&self) -> NonZeroUsize {
        self.inner.lock().cap()
    }

    /// Number of in-flight loads currently waiting to resolve.
    ///
    /// Useful for ops monitoring ("is this pod stuck on slow fetchers?")
    /// and for tests that verify `get_or_try_insert_with` cleans up its
    /// in-flight cells correctly even on panic-unwind.
    pub fn pending_loads_count(&self) -> usize {
        self.inflight.lock().len()
    }
}

/// RAII guard that removes an in-flight cell from the cache's
/// pending-loads map on drop (including panic-unwind), gated on
/// `Arc::ptr_eq` so a slot replaced mid-resolve is left intact.
struct InflightGuard<'a, K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    cache: &'a ClockTtlCache<K, V>,
    key: K,
    cell: Arc<OnceCell<V>>,
}

impl<K, V> Drop for InflightGuard<'_, K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    fn drop(&mut self) {
        let mut inflight = self.cache.inflight.lock();
        if let Some(existing) = inflight.get(&self.key)
            && Arc::ptr_eq(existing, &self.cell)
        {
            inflight.remove(&self.key);
        }
    }
}
