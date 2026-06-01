//! Observability counters for [`ClockTtlCache`](crate::ClockTtlCache).
//! [`CacheStats`] is the `Copy` snapshot returned to callers;
//! `CacheCounters` is the internal atomic-backed live shape.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counters reported by [`ClockTtlCache::stats`](crate::ClockTtlCache::stats).
/// Monotonic since construction (or the most recent `reset_stats` call);
/// returned by value so callers own a snapshot, not a reference into the
/// live atomics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Successful `get` hits. TTL-expired entries evicted on access count
    /// as misses, not hits.
    pub hits: u64,
    /// `get` calls that returned `None` (key absent or expired). Includes
    /// single-flight cache lookups inside `get_or_try_insert_with`.
    pub misses: u64,
    /// Successful inserts (fresh and overwriting).
    pub inserts: u64,
    /// Entries evicted by LRU capacity pressure during inserts.
    pub capacity_evictions: u64,
    /// Entries removed by explicit `invalidate` / `invalidate_by` /
    /// `invalidate_all` / `cleanup_expired` calls.
    pub invalidations: u64,
    /// Concurrent `get_or_try_insert_with` calls that joined an in-flight
    /// load instead of starting their own. High values mean duplicate
    /// fetches successfully avoided.
    pub single_flight_joins: u64,
    /// `get_or_try_insert_with` fetcher invocations that returned an
    /// error. The cell is removed on error so subsequent callers retry
    /// rather than re-await a known-failing future.
    pub single_flight_errors: u64,
}

/// Live atomic counters backing [`CacheStats`]. Internal; surfaced only
/// via the [`CacheStats`] snapshot.
#[derive(Default)]
pub(crate) struct CacheCounters {
    pub(crate) hits: AtomicU64,
    pub(crate) misses: AtomicU64,
    pub(crate) inserts: AtomicU64,
    pub(crate) capacity_evictions: AtomicU64,
    pub(crate) invalidations: AtomicU64,
    pub(crate) single_flight_joins: AtomicU64,
    pub(crate) single_flight_errors: AtomicU64,
}

impl CacheCounters {
    pub(crate) fn snapshot(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            inserts: self.inserts.load(Ordering::Relaxed),
            capacity_evictions: self.capacity_evictions.load(Ordering::Relaxed),
            invalidations: self.invalidations.load(Ordering::Relaxed),
            single_flight_joins: self.single_flight_joins.load(Ordering::Relaxed),
            single_flight_errors: self.single_flight_errors.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.inserts.store(0, Ordering::Relaxed);
        self.capacity_evictions.store(0, Ordering::Relaxed);
        self.invalidations.store(0, Ordering::Relaxed);
        self.single_flight_joins.store(0, Ordering::Relaxed);
        self.single_flight_errors.store(0, Ordering::Relaxed);
    }
}
