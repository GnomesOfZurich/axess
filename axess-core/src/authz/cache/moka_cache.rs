//! In-process LRU+TTL cache decorator for [`RequestEntityProvider`].
//!
//! Wraps any [`RequestEntityProvider`] in a [`moka::future::Cache`] so that
//! repeat authorization checks for the same principal × resource × action
//! triple skip the inner provider's entity-build work.

use std::sync::Arc;
use std::time::Duration;

use cedar_policy::{Entities, EntityUid};
use moka::future::Cache;

use crate::authz::error::AuthzError;
use crate::authz::provider::RequestEntityProvider;
use crate::session::AuthSession;

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
/// In-process LRU+TTL via [`moka`]. Sub-microsecond lookup, per-pod scope.
/// Use as the L1 tier; combine with the cluster-tier
/// [`super::ValkeyEntityCache`] (behind the `valkey-cache` feature) if
/// you need cross-pod sharing.
///
/// # Construction
///
/// ```rust,ignore
/// use axess_core::authz::cache::MokaEntityCache;
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// let provider = MyEntityProvider::new(db);
/// let cached = MokaEntityCache::new(provider)
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
pub struct MokaEntityCache<P>
where
    P: RequestEntityProvider,
{
    inner: P,
    cache: Cache<EntityCacheKey, Arc<Entities>>,
}

impl<P> MokaEntityCache<P>
where
    P: RequestEntityProvider,
{
    /// Wrap `inner` in a cache with default capacity 10,000 entries and
    /// 60-second TTL. Override via [`with_capacity`](Self::with_capacity)
    /// and [`with_ttl`](Self::with_ttl).
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(60))
                .build(),
        }
    }

    /// Construct with explicit capacity and TTL.
    pub fn with_options(inner: P, capacity: u64, ttl: Duration) -> Self {
        Self {
            inner,
            cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// Fluent: set max capacity. Replaces the underlying cache (so call
    /// before any traffic; capacity changes mid-flight clear the cache).
    pub fn with_capacity(self, capacity: u64) -> Self {
        let ttl = Duration::from_secs(60);
        Self::with_options(self.inner, capacity, ttl)
    }

    /// Fluent: set TTL. Replaces the underlying cache.
    pub fn with_ttl(self, ttl: Duration) -> Self {
        let capacity = 10_000;
        Self::with_options(self.inner, capacity, ttl)
    }

    /// Invalidate cached entries for `(principal, tenant, resource, action)`.
    ///
    /// Call from any code path that mutates the principal's roles, the
    /// resource's attributes, or anything else the inner provider would
    /// load differently next time. Pass `tenant=None` for guest sessions;
    /// otherwise pass the same tenant_id the session would report.
    pub async fn invalidate(
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
        self.cache.invalidate(&key).await;
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
    /// Eviction is **deferred**: moka's `invalidate_entries_if`
    /// registers the predicate and matching entries are removed on
    /// the next maintenance tick (typically sub-second) or the next
    /// read of a matching key. The next authorization request for
    /// this principal will still see the cached entry if it lands
    /// before the tick; call `cache.run_pending_tasks().await` if
    /// you need hard-sync semantics.
    ///
    /// Call from role-change, account-suspension, and token-revoke
    /// paths so the new authorization state takes effect promptly
    /// without waiting for the TTL.
    pub fn invalidate_principal(&self, principal: &EntityUid) -> Result<(), moka::PredicateError> {
        let principal = principal.clone();
        self.cache
            .invalidate_entries_if(move |k, _v| k.principal == principal)?;
        Ok(())
    }

    /// Drop every entry whose `tenant` matches.
    ///
    /// Eviction is **deferred** (see
    /// [`invalidate_principal`](Self::invalidate_principal) for the
    /// timing model). Entries with `tenant = None` (guest sessions)
    /// are not matched; use [`invalidate_all`](Self::invalidate_all)
    /// to drop guest entries alongside tenant ones.
    pub fn invalidate_tenant(&self, tenant: &str) -> Result<(), moka::PredicateError> {
        let tenant = tenant.to_string();
        self.cache
            .invalidate_entries_if(move |k, _v| k.tenant.as_deref() == Some(tenant.as_str()))?;
        Ok(())
    }

    /// Borrow the inner provider for read access.
    pub fn inner(&self) -> &P {
        &self.inner
    }
}

impl<P> super::invalidator::CacheInvalidator for MokaEntityCache<P>
where
    P: RequestEntityProvider + 'static,
{
    type Error = moka::PredicateError;

    async fn invalidate_principal(&self, principal: &EntityUid) -> Result<(), Self::Error> {
        MokaEntityCache::invalidate_principal(self, principal)
    }

    async fn invalidate_tenant(&self, tenant: &str) -> Result<(), Self::Error> {
        MokaEntityCache::invalidate_tenant(self, tenant)
    }

    async fn invalidate_all(&self) -> Result<(), Self::Error> {
        MokaEntityCache::invalidate_all(self);
        Ok(())
    }
}

impl<P> RequestEntityProvider for MokaEntityCache<P>
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

            if let Some(cached) = self.cache.get(&key).await {
                return Ok((*cached).clone());
            }

            let entities = self
                .inner
                .entities_for(session, principal, resource, action)
                .await?;
            self.cache.insert(key, Arc::new(entities.clone())).await;
            Ok(entities)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let cached = MokaEntityCache::new(CountingProvider {
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
        let cached = MokaEntityCache::new(CountingProvider {
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
        cached.invalidate(&p, None, &r, &a).await;

        let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "after invalidate, next call should re-invoke inner"
        );
    }

    #[tokio::test]
    async fn invalidate_all_evicts_every_entry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let cached = MokaEntityCache::new(CountingProvider {
            calls: calls.clone(),
        });
        let s = guest_session();
        let p = principal();
        let a = action();
        let r1 = doc("doc-1");
        let r2 = doc("doc-2");

        let _ = cached.entities_for(&s, &p, &r1, &a).await.unwrap();
        let _ = cached.entities_for(&s, &p, &r2, &a).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let _ = cached.entities_for(&s, &p, &r1, &a).await.unwrap();
        let _ = cached.entities_for(&s, &p, &r2, &a).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "warmed entries must hit cache"
        );

        cached.invalidate_all();
        // moka's `invalidate_all` is best-effort/lazy; pending invalidations
        // are flushed by `run_pending_tasks` so the assertion is deterministic.
        cached.cache.run_pending_tasks().await;

        let _ = cached.entities_for(&s, &p, &r1, &a).await.unwrap();
        let _ = cached.entities_for(&s, &p, &r2, &a).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "after invalidate_all, every entry must re-invoke inner; \
             killing the `()` no-op mutation on invalidate_all"
        );
    }
}
