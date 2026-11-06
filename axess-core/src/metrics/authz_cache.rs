//! The authorization concern: the entity cache and the live policy reload.

/// Cache hit and miss signals from the Cedar entity-resolution cache on the
/// authorization decision path, and the policy reload counters of
/// [`AuthzStore`](crate::authz::AuthzStore).
///
/// The default `EntityCache` (and the opt-in Valkey decorator) report through
/// [`EntityCache::flush_metrics`](crate::authz::cache::EntityCache::flush_metrics)
/// so operations dashboards can compute hit rates without reading the
/// internal `axess_cache::CacheStats` snapshot.
pub trait AuthzCacheMetrics: Send + Sync + 'static {
    /// An authz entity lookup found the value in cache (saved a provider call).
    fn authz_cache_hit(&self) {}

    /// An authz entity lookup missed and had to call through to the provider.
    fn authz_cache_miss(&self) {}

    /// The cache rejected a write because the capacity-bounded LRU is full
    /// and evicted an existing entry to make room. Persistent high counts
    /// suggest the configured capacity is too small for the working set.
    fn authz_cache_eviction(&self) {}

    /// An invalidation channel cleared one or more cache entries (e.g.
    /// policy change, principal revocation). Useful for verifying that
    /// downstream invalidation actually reaches the cache layer.
    fn authz_cache_invalidation(&self) {}

    /// The Cedar policy set was replaced on this instance by
    /// [`AuthzStore::reload_policies`](crate::authz::AuthzStore::reload_policies)
    /// or by a follower. The digest is in the `axess::authz::reload` event.
    fn authz_policy_reloaded(&self) {}

    /// A policy reload was refused (the text did not parse or validate, or
    /// the entity provider did not fit the schema); the previous set stays in
    /// force. Any count is worth an alert: someone published a bad set.
    fn authz_policy_reload_refused(&self) {}

    /// `count` authz entity lookups were found in cache. Called by
    /// [`EntityCache::flush_metrics`](crate::authz::cache::EntityCache::flush_metrics)
    /// with a whole reporting window's total, so a counter backend can add
    /// it in one step. The default calls
    /// [`authz_cache_hit`](Self::authz_cache_hit) `count` times, so
    /// an implementation of the per-event method alone keeps working.
    fn authz_cache_hits(&self, count: u64) {
        for _ in 0..count {
            self.authz_cache_hit();
        }
    }

    /// `count` authz entity lookups missed. Batched form of
    /// [`authz_cache_miss`](Self::authz_cache_miss); see
    /// [`authz_cache_hits`](Self::authz_cache_hits).
    fn authz_cache_misses(&self, count: u64) {
        for _ in 0..count {
            self.authz_cache_miss();
        }
    }

    /// `count` entries were evicted by capacity pressure. Batched form of
    /// [`authz_cache_eviction`](Self::authz_cache_eviction); see
    /// [`authz_cache_hits`](Self::authz_cache_hits).
    fn authz_cache_evictions(&self, count: u64) {
        for _ in 0..count {
            self.authz_cache_eviction();
        }
    }

    /// `count` entries were cleared by invalidation. Batched form of
    /// [`authz_cache_invalidation`](Self::authz_cache_invalidation); see
    /// [`authz_cache_hits`](Self::authz_cache_hits).
    fn authz_cache_invalidations(&self, count: u64) {
        for _ in 0..count {
            self.authz_cache_invalidation();
        }
    }
}
