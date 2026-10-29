//! In-process LRU+TTL cache decorator for [`RequestEntityProvider`].
//!
//! Wraps any [`RequestEntityProvider`] in an [`axess_cache::ClockTtlCache`]
//! so that repeat authorization checks for the same `(principal, tenant,
//! resource, action)` tuple skip the inner provider's entity-build work.
//!
//! Backed by [`axess_cache::ClockTtlCache`]: every TTL decision goes
//! through an injected [`axess_clock::Clock`], preserving DST end-to-end.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use cedar_policy::{Entities, EntityUid};

use axess_cache::ClockTtlCache;
use axess_clock::{Clock, SystemClock};

use super::generation::{Generation, Generations};

use crate::authz::error::AuthzError;
use crate::authz::provider::RequestEntityProvider;
use crate::session::AuthSession;

/// Default capacity if the caller doesn't override it.
const DEFAULT_CAPACITY: usize = 10_000;
/// Default TTL if the caller doesn't override it.
const DEFAULT_TTL_SECS: u64 = 60;

/// Cache key for the (principal, tenant, resource, action) tuple, the
/// provider's cache discriminator and the invalidation generation the load
/// started under.
///
/// `tenant` is read from `AuthSession::tenant_id()` so cache entries for
/// the same physical user acting in different tenants stay distinct (a
/// user with memberships in multiple tenants has different role sets
/// per tenant).
///
/// `tenant` is `Option<String>` because guest / pre-tenant sessions can
/// theoretically still reach the cache; in production `require_authz!`
/// rejects unauthenticated callers before any provider call.
#[derive(Hash, Eq, PartialEq, Clone)]
struct EntityCacheKey {
    principal: EntityUid,
    tenant: Option<String>,
    resource: EntityUid,
    action: EntityUid,
    discriminator: Option<String>,
    generation: Generation,
}

/// In-process cache decorator over a [`RequestEntityProvider`].
///
/// # Tier
///
/// In-process LRU+TTL via [`axess_cache::ClockTtlCache`]. Sub-µs lookup,
/// per-pod scope. Use as the L1 tier; combine with the cluster-tier
/// [`super::ValkeyEntityCache`] (behind the `valkey-cache` feature) if
/// you need cross-pod sharing.
///
/// # DST
///
/// Time-to-live is evaluated against an injected [`Clock`] (default
/// [`SystemClock`]). Pass `MockClock`
/// via [`with_clock`](Self::with_clock) for reproducible expiry tests.
///
/// # Construction
///
/// ```rust,ignore
/// use axess_core::authz::cache::EntityCache;
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// let provider = MyEntityProvider::new(db);
/// let cached = EntityCache::new(provider)
///     .with_capacity(10_000)
///     .with_ttl(Duration::from_secs(60));
/// let provider: Arc<dyn axess_core::authz::RequestEntityProvider> = Arc::new(cached);
/// ```
///
/// # Caching contract
///
/// An entry is keyed on the principal, the session's tenant, the resource,
/// the action and the inner provider's
/// [`cache_discriminator`](RequestEntityProvider::cache_discriminator).
/// Entities that depend on any other session state are shared across
/// sessions of the same user and tenant for the TTL, so keep per-session
/// facts in the Cedar context, or return them from the discriminator.
///
/// # Invalidation
///
/// An invalidation also discards a load that was in flight when it ran: the
/// result of that load is returned to its caller but never served to anyone
/// else.
///
/// Call [`invalidate`](Self::invalidate) from any code path that mutates a
/// principal's role membership or a resource's authorization-relevant
/// attributes. axess does not (and cannot) auto-invalidate; the cache
/// has no view into your data model's mutation events.
///
/// # Errors
///
/// Errors from the inner provider are NOT cached. If `entities_for` fails
/// transiently (e.g. DB timeout), the next call retries. This avoids
/// pinning a transient failure into the cache for the TTL duration.
pub struct EntityCache<P>
where
    P: RequestEntityProvider,
{
    inner: P,
    cache: ClockTtlCache<EntityCacheKey, Arc<Entities>>,
    /// The settings the cache was built with, kept so a fluent setter
    /// changing one carries the others instead of resetting them.
    capacity: usize,
    ttl: Duration,
    clock: Arc<dyn Clock>,
    generations: Generations,
}

impl<P> EntityCache<P>
where
    P: RequestEntityProvider,
{
    /// Wrap `inner` in a cache with default capacity 10,000 entries and
    /// 60-second TTL backed by [`SystemClock`]. Override via
    /// [`with_capacity`](Self::with_capacity), [`with_ttl`](Self::with_ttl),
    /// or [`with_clock`](Self::with_clock).
    pub fn new(inner: P) -> Self {
        Self::with_options(
            inner,
            DEFAULT_CAPACITY,
            Duration::from_secs(DEFAULT_TTL_SECS),
            Arc::new(SystemClock) as Arc<dyn Clock>,
        )
    }

    /// Construct with explicit capacity, TTL, and Clock. Capacity must be
    /// non-zero; values of 0 are clamped to 1 (a single-entry cache is at
    /// least correct, even if useless: avoids a panic from `NonZeroUsize`
    /// in misconfigured callers).
    pub fn with_options(inner: P, capacity: usize, ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity is at least 1");
        Self {
            inner,
            cache: ClockTtlCache::new(cap, ttl, clock.clone()),
            capacity,
            ttl,
            clock,
            generations: Generations::new(),
        }
    }

    /// Fluent: set max capacity. Replaces the underlying cache (so call
    /// before any traffic; capacity changes mid-flight clear the cache).
    pub fn with_capacity(self, capacity: usize) -> Self {
        Self::with_options(self.inner, capacity, self.ttl, self.clock)
    }

    /// Fluent: set TTL. Replaces the underlying cache.
    pub fn with_ttl(self, ttl: Duration) -> Self {
        Self::with_options(self.inner, self.capacity, ttl, self.clock)
    }

    /// Fluent: inject a [`Clock`] for deterministic-simulation testing.
    /// Replaces the underlying cache.
    pub fn with_clock(self, clock: Arc<dyn Clock>) -> Self {
        Self::with_options(self.inner, self.capacity, self.ttl, clock)
    }

    /// Invalidate cached entries for `(principal, tenant, resource, action)`,
    /// whatever their cache discriminator.
    ///
    /// Call from any code path that mutates the principal's roles, the
    /// resource's attributes, or anything else the inner provider would
    /// load differently next time. Pass `tenant=None` for guest sessions;
    /// otherwise pass the same tenant_id the session would report.
    ///
    /// Because a load already in flight must not repopulate the entry, this
    /// also drops every other cached entry of `principal`; they are rebuilt
    /// on their next use.
    pub fn invalidate(
        &self,
        principal: &EntityUid,
        tenant: Option<&str>,
        resource: &EntityUid,
        action: &EntityUid,
    ) {
        let _ = (tenant, resource, action);
        self.generations.bump_principal(principal);
        self.cache.invalidate_by(|k| &k.principal == principal);
    }

    /// Drop every entry from the cache.
    ///
    /// Use as a last-resort invalidation when you can't enumerate the
    /// affected keys (e.g. global Cedar policy reload).
    pub fn invalidate_all(&self) {
        self.generations.bump_all();
        self.cache.invalidate_all();
    }

    /// Drop every entry whose `principal` matches.
    ///
    /// Returns the number of entries dropped. Call from role-change,
    /// account-suspension, and token-revoke paths so the next
    /// request sees the new authorization state without waiting for
    /// the TTL.
    pub fn invalidate_principal(&self, principal: &EntityUid) -> usize {
        self.generations.bump_principal(principal);
        self.cache.invalidate_by(|k| &k.principal == principal)
    }

    /// Drop every entry whose `tenant` matches.
    ///
    /// Returns the number of entries dropped. Entries with
    /// `tenant = None` (guest sessions) are not matched; use
    /// [`invalidate_all`](Self::invalidate_all) to drop guest entries
    /// alongside tenant ones.
    pub fn invalidate_tenant(&self, tenant: &str) -> usize {
        self.generations.bump_tenant(tenant);
        self.cache
            .invalidate_by(|k| k.tenant.as_deref() == Some(tenant))
    }

    /// Drop every entry built for `resource`, for every principal.
    ///
    /// Returns the number of entries dropped. Call from code that changes a
    /// resource's authorization-relevant attributes (owner, classification,
    /// sharing) when you cannot enumerate the principals that read it.
    pub fn invalidate_resource(&self, resource: &EntityUid) -> usize {
        self.generations.bump_resource(resource);
        self.cache.invalidate_by(|k| &k.resource == resource)
    }

    /// Borrow the inner provider for read access.
    pub fn inner(&self) -> &P {
        &self.inner
    }

    /// Snapshot the cache hit/miss/eviction/invalidation counters.
    ///
    /// Counters are cumulative since construction (or the last
    /// [`reset_stats`](Self::reset_stats)). Pair with
    /// [`flush_metrics`](Self::flush_metrics) to forward deltas into
    /// an [`AuthnMetrics`](crate::metrics::AuthnMetrics) sink on a
    /// schedule.
    pub fn stats(&self) -> axess_cache::CacheStats {
        self.cache.stats()
    }

    /// Reset all cache counters to zero.
    ///
    /// Useful after [`flush_metrics`](Self::flush_metrics) when the
    /// adopter prefers fresh-from-zero counters per reporting window
    /// rather than delta-tracking against a previous snapshot.
    pub fn reset_stats(&self) {
        self.cache.reset_stats();
    }

    /// Forward the cumulative cache counters as `delta_*` events to an
    /// [`AuthnMetrics`](crate::metrics::AuthnMetrics) sink, then reset
    /// the internal counters to zero so the next call reports only
    /// events accumulated since this one.
    ///
    /// Call this periodically (e.g. every 10 s from a background task)
    /// so the metrics backend sees up-to-date hit/miss rates without
    /// the EntityCache holding a long-lived reference to the metrics
    /// trait object. Adopters who prefer Prometheus-style "expose
    /// cumulative counters via `/metrics` scrape" can ignore this
    /// helper and read [`stats`](Self::stats) directly in their
    /// scrape handler.
    ///
    /// ```rust,ignore
    /// let cache = Arc::new(EntityCache::new(provider));
    /// let metrics_clone = metrics.clone();
    /// let cache_clone = Arc::clone(&cache);
    /// tokio::spawn(async move {
    ///     let mut tick = tokio::time::interval(Duration::from_secs(10));
    ///     loop {
    ///         tick.tick().await;
    ///         cache_clone.flush_metrics(&*metrics_clone);
    ///     }
    /// });
    /// ```
    pub fn flush_metrics(&self, metrics: &dyn crate::metrics::AuthnMetrics) {
        let snapshot = self.stats();
        // One call per counter, carrying the window's total: a busy cache
        // accumulates millions of hits between flushes, and one virtual call
        // per hit would make the flush itself a cost.
        metrics.authz_cache_hits(snapshot.hits);
        metrics.authz_cache_misses(snapshot.misses);
        metrics.authz_cache_evictions(snapshot.capacity_evictions);
        metrics.authz_cache_invalidations(snapshot.invalidations);
        self.reset_stats();
    }
}

impl<P> super::invalidator::CacheInvalidator for EntityCache<P>
where
    P: RequestEntityProvider + 'static,
{
    type Error = std::convert::Infallible;

    async fn invalidate_principal(&self, principal: &EntityUid) -> Result<(), Self::Error> {
        let _ = EntityCache::invalidate_principal(self, principal);
        Ok(())
    }

    async fn invalidate_tenant(&self, tenant: &str) -> Result<(), Self::Error> {
        let _ = EntityCache::invalidate_tenant(self, tenant);
        Ok(())
    }

    async fn invalidate_all(&self) -> Result<(), Self::Error> {
        EntityCache::invalidate_all(self);
        Ok(())
    }

    async fn invalidate_resource(&self, resource: &EntityUid) -> Result<(), Self::Error> {
        let _ = EntityCache::invalidate_resource(self, resource);
        Ok(())
    }
}

impl<P> RequestEntityProvider for EntityCache<P>
where
    P: RequestEntityProvider,
{
    fn cache_discriminator<'a>(
        &'a self,
        session: &'a AuthSession,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + 'a>> {
        self.inner.cache_discriminator(session)
    }

    fn entities_for<'a>(
        &'a self,
        session: &'a AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let shared = self
                .shared_entities_for(session, principal, resource, action)
                .await?;
            Ok((*shared).clone())
        })
    }

    fn shared_entities_for<'a>(
        &'a self,
        session: &'a AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<Entities>, AuthzError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let tenant = session.tenant_id().await.map(|t| t.to_string().to_string());
            let discriminator = self.inner.cache_discriminator(session).await;
            // Taken before the provider is read: an invalidation that runs
            // during the load changes the key the result is stored under.
            let generation = self
                .generations
                .snapshot(principal, tenant.as_deref(), resource);
            let key = EntityCacheKey {
                principal: principal.clone(),
                tenant,
                resource: resource.clone(),
                action: action.clone(),
                discriminator,
                generation,
            };

            // Single-flight: concurrent cold misses for the same key share
            // one inner-provider call instead of N parallel DB hits.
            // `get_or_try_insert_with` also handles the cache-hit fast path
            // and the "promote to cache on success" step.
            self.cache
                .get_or_try_insert_with(key, || async {
                    let entities = self
                        .inner
                        .entities_for(session, principal, resource, action)
                        .await?;
                    Ok::<Arc<Entities>, AuthzError>(Arc::new(entities))
                })
                .await
        })
    }
}

#[cfg(test)]
mod tests;
