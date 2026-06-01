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

use crate::authz::error::AuthzError;
use crate::authz::provider::RequestEntityProvider;
use crate::session::AuthSession;

/// Default capacity if the caller doesn't override it.
const DEFAULT_CAPACITY: usize = 10_000;
/// Default TTL if the caller doesn't override it.
const DEFAULT_TTL_SECS: u64 = 60;

/// Cache key for the (principal, tenant, resource, action) tuple.
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
/// [`SystemClock`]). Pass [`MockClock`](axess_clock::testing::MockClock)
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
/// # Invalidation
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
            cache: ClockTtlCache::new(cap, ttl, clock),
        }
    }

    /// Fluent: set max capacity. Replaces the underlying cache (so call
    /// before any traffic; capacity changes mid-flight clear the cache).
    pub fn with_capacity(self, capacity: usize) -> Self {
        let ttl = Duration::from_secs(DEFAULT_TTL_SECS);
        Self::with_options(self.inner, capacity, ttl, Arc::new(SystemClock))
    }

    /// Fluent: set TTL. Replaces the underlying cache.
    pub fn with_ttl(self, ttl: Duration) -> Self {
        Self::with_options(self.inner, DEFAULT_CAPACITY, ttl, Arc::new(SystemClock))
    }

    /// Fluent: inject a [`Clock`] for deterministic-simulation testing.
    /// Replaces the underlying cache.
    pub fn with_clock(self, clock: Arc<dyn Clock>) -> Self {
        Self::with_options(
            self.inner,
            DEFAULT_CAPACITY,
            Duration::from_secs(DEFAULT_TTL_SECS),
            clock,
        )
    }

    /// Invalidate cached entries for `(principal, tenant, resource, action)`.
    ///
    /// Call from any code path that mutates the principal's roles, the
    /// resource's attributes, or anything else the inner provider would
    /// load differently next time. Pass `tenant=None` for guest sessions;
    /// otherwise pass the same tenant_id the session would report.
    pub fn invalidate(
        &self,
        principal: &EntityUid,
        tenant: Option<&str>,
        resource: &EntityUid,
        action: &EntityUid,
    ) {
        let key = EntityCacheKey {
            principal: principal.clone(),
            tenant: tenant.map(str::to_string),
            resource: resource.clone(),
            action: action.clone(),
        };
        self.cache.invalidate(&key);
    }

    /// Drop every entry from the cache.
    ///
    /// Use as a last-resort invalidation when you can't enumerate the
    /// affected keys (e.g. global Cedar policy reload).
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Drop every entry whose `principal` matches.
    ///
    /// Returns the number of entries dropped. Call from role-change,
    /// account-suspension, and token-revoke paths so the next
    /// request sees the new authorization state without waiting for
    /// the TTL.
    pub fn invalidate_principal(&self, principal: &EntityUid) -> usize {
        self.cache.invalidate_by(|k| &k.principal == principal)
    }

    /// Drop every entry whose `tenant` matches.
    ///
    /// Returns the number of entries dropped. Entries with
    /// `tenant = None` (guest sessions) are not matched; use
    /// [`invalidate_all`](Self::invalidate_all) to drop guest entries
    /// alongside tenant ones.
    pub fn invalidate_tenant(&self, tenant: &str) -> usize {
        self.cache
            .invalidate_by(|k| k.tenant.as_deref() == Some(tenant))
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
        // One event per unit because the trait surface mirrors the
        // existing per-event method shape (`auth_attempt`,
        // `session_created`, …). Adopters wiring batched counter
        // backends can implement the trait method as a single counter
        // increment per call; no per-event allocation if the impl is
        // a `fetch_add`.
        for _ in 0..snapshot.hits {
            metrics.authz_cache_hit();
        }
        for _ in 0..snapshot.misses {
            metrics.authz_cache_miss();
        }
        for _ in 0..snapshot.capacity_evictions {
            metrics.authz_cache_eviction();
        }
        for _ in 0..snapshot.invalidations {
            metrics.authz_cache_invalidation();
        }
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
}

impl<P> RequestEntityProvider for EntityCache<P>
where
    P: RequestEntityProvider,
{
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
            let tenant = session.tenant_id().await.map(|t| t.to_string().to_string());
            let key = EntityCacheKey {
                principal: principal.clone(),
                tenant,
                resource: resource.clone(),
                action: action.clone(),
            };

            // Single-flight: concurrent cold misses for the same key share
            // one inner-provider call instead of N parallel DB hits.
            // `get_or_try_insert_with` also handles the cache-hit fast path
            // and the "promote to cache on success" step.
            let arc = self
                .cache
                .get_or_try_insert_with(key, || async {
                    let entities = self
                        .inner
                        .entities_for(session, principal, resource, action)
                        .await?;
                    Ok::<Arc<Entities>, AuthzError>(Arc::new(entities))
                })
                .await?;
            Ok((*arc).clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_clock::testing::MockClock;
    use std::collections::HashSet;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts inner-provider calls so the test can verify cache hits/misses.
    struct CountingProvider {
        calls: Arc<AtomicUsize>,
    }

    impl RequestEntityProvider for CountingProvider {
        fn entities_for<'a>(
            &'a self,
            session: &'a AuthSession,
            principal: &'a EntityUid,
            resource: &'a EntityUid,
            action: &'a EntityUid,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
        > {
            // Synthetic counting fixture; doesn't need session/action; explicit
            // acknowledgment per the axess no-`_`-prefix convention.
            let _ = (session, action);
            let calls = self.calls.clone();
            let principal = principal.clone();
            let resource = resource.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let p = cedar_policy::Entity::new(
                    principal,
                    std::collections::HashMap::new(),
                    HashSet::new(),
                )
                .unwrap();
                let r = cedar_policy::Entity::new(
                    resource,
                    std::collections::HashMap::new(),
                    HashSet::new(),
                )
                .unwrap();
                Ok(Entities::from_entities(vec![p, r], None).unwrap())
            })
        }
    }

    /// Construct a guest (unauthenticated) `AuthSession` for unit tests.
    /// Reaches into `pub(crate)` `SessionInner` / `SessionHandle`: usable
    /// only from inside axess-core; mirrors the pattern in
    /// `session::extractor::tests::make_session`.
    fn guest_session() -> AuthSession {
        use crate::session::SessionData;
        use crate::session::id::SessionId;
        use crate::session::layer::{SessionHandle, SessionInner};
        use tokio::sync::RwLock;

        let inner = SessionInner {
            id: SessionId::new(&axess_rng::SystemRng),
            data: SessionData::default(),
            modified: false,
            regenerate: false,
            pre_cycle_id: None,
            pending_fingerprint: None,
            max_custom_bytes: 64 * 1024,
        };
        AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
    }

    fn principal() -> EntityUid {
        EntityUid::from_str("App::User::\"alice\"").unwrap()
    }
    fn action() -> EntityUid {
        EntityUid::from_str("App::Action::\"View\"").unwrap()
    }
    fn doc(id: &str) -> EntityUid {
        EntityUid::from_str(&format!("App::Doc::\"{id}\"")).unwrap()
    }

    #[tokio::test]
    async fn first_call_misses_then_caches() {
        let calls = Arc::new(AtomicUsize::new(0));
        let cached = EntityCache::new(CountingProvider {
            calls: calls.clone(),
        });
        let s = guest_session();
        let p = principal();
        let a = action();
        let r1 = doc("doc-1");

        let _ = cached.entities_for(&s, &p, &r1, &a).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let _ = cached.entities_for(&s, &p, &r1, &a).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "cache hit should not invoke inner"
        );

        let r2 = doc("doc-2");
        let _ = cached.entities_for(&s, &p, &r2, &a).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidate_evicts_cached_entry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let cached = EntityCache::new(CountingProvider {
            calls: calls.clone(),
        });
        let s = guest_session();
        let p = principal();
        let a = action();
        let r = doc("doc-1");

        let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
        let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Guest session has no tenant_id, so invalidation key uses tenant=None.
        cached.invalidate(&p, None, &r, &a);

        let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "after invalidate, next call should re-invoke inner"
        );
    }

    /// Pin the single-flight property at the entity-cache layer:
    /// concurrent cold-miss callers for the same key share one inner
    /// provider call rather than fan out to N parallel DB hits. This
    /// is what `ClockTtlCache::get_or_try_insert_with` enables: the
    /// previous (moka-backed, no single-flight) implementation would
    /// have called the inner provider N times.
    #[tokio::test]
    async fn concurrent_cold_misses_share_one_inner_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let cached = Arc::new(EntityCache::new(CountingProvider {
            calls: calls.clone(),
        }));
        let p = principal();
        let a = action();
        let r = doc("doc-1");

        const N: usize = 8;
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let cached = cached.clone();
            let p = p.clone();
            let a = a.clone();
            let r = r.clone();
            // Each task constructs its own session; guest_session() is
            // only callable inside the test module.
            let s = guest_session();
            handles.push(tokio::spawn(async move {
                cached.entities_for(&s, &p, &r, &a).await.map(|_| ())
            }));
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "single-flight must collapse N concurrent cold misses into 1 inner call"
        );
    }

    /// Pin the DST property: with an injected MockClock, advancing time
    /// past the TTL must cause the next call to re-invoke the inner
    /// provider. This is the test that would have failed under the
    /// previous moka-backed implementation (moka uses wall-clock time
    /// internally; advancing `MockClock` had no effect on its eviction).
    #[tokio::test]
    async fn entries_expire_under_injected_clock() {
        let clock = Arc::new(MockClock::now());
        let calls = Arc::new(AtomicUsize::new(0));
        let cached = EntityCache::with_options(
            CountingProvider {
                calls: calls.clone(),
            },
            DEFAULT_CAPACITY,
            Duration::from_secs(60),
            clock.clone() as Arc<dyn Clock>,
        );

        let s = guest_session();
        let p = principal();
        let a = action();
        let r = doc("doc-1");

        let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Inside TTL; cache hit.
        clock.advance_secs(30);
        let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "still inside TTL");

        // Past TTL; cache miss, inner re-invoked.
        clock.advance_secs(31);
        let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "TTL expired under MockClock; must re-fetch from inner"
        );
    }
}
