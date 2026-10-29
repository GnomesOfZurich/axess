//! In-process LRU+TTL cache decorator for [`RequestEntityProvider`].
//!
//! Wraps any [`RequestEntityProvider`] in a [`moka::future::Cache`] so that
//! repeat authorization checks for the same principal × resource × action
//! triple skip the inner provider's entity-build work.

use std::sync::Arc;
use std::time::Duration;

use cedar_policy::{Entities, EntityUid};
use moka::future::Cache;

use super::generation::{Generation, Generations};
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
    discriminator: Option<String>,
    generation: Generation,
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
/// An invalidation takes effect at once for later lookups, and also
/// discards a load that was in flight when it ran: that load's result is
/// returned to its caller but never served to anyone else.
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
    generations: Generations,
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
                // Without this, `invalidate_entries_if` returns
                // `InvalidationClosuresDisabled` and a revoked role keeps
                // authorizing until the TTL expires.
                .support_invalidation_closures()
                .build(),
            generations: Generations::new(),
        }
    }

    /// Construct with explicit capacity and TTL.
    pub fn with_options(inner: P, capacity: u64, ttl: Duration) -> Self {
        Self {
            inner,
            cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .support_invalidation_closures()
                .build(),
            generations: Generations::new(),
        }
    }

    /// Fluent: set max capacity. Replaces the underlying cache (so call
    /// before any traffic; capacity changes mid-flight clear the cache).
    /// The TTL already set is kept, so `.with_ttl(5s).with_capacity(100)`
    /// means what it says.
    pub fn with_capacity(self, capacity: u64) -> Self {
        let ttl = self
            .cache
            .policy()
            .time_to_live()
            .unwrap_or(Duration::from_secs(60));
        Self::with_options(self.inner, capacity, ttl)
    }

    /// Fluent: set TTL. Replaces the underlying cache; the capacity already
    /// set is kept.
    pub fn with_ttl(self, ttl: Duration) -> Self {
        let capacity = self.cache.policy().max_capacity().unwrap_or(10_000);
        Self::with_options(self.inner, capacity, ttl)
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
    pub async fn invalidate(
        &self,
        principal: &EntityUid,
        tenant: Option<&str>,
        resource: &EntityUid,
        action: &EntityUid,
    ) {
        let _ = (tenant, resource, action);
        self.generations.bump_principal(principal);
        let principal = principal.clone();
        // Lookups already miss (the generation is part of the key); this
        // frees the memory. A predicate error only delays that.
        let _ = self
            .cache
            .invalidate_entries_if(move |k, _v| k.principal == principal);
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
    /// Lookups miss from the moment this returns, because the invalidation
    /// generation is part of every key. Freeing the memory is **deferred**:
    /// moka's `invalidate_entries_if` registers the predicate and matching
    /// entries are removed on the next maintenance tick.
    ///
    /// Call from role-change, account-suspension, and token-revoke
    /// paths so the new authorization state takes effect promptly
    /// without waiting for the TTL.
    pub fn invalidate_principal(&self, principal: &EntityUid) -> Result<(), moka::PredicateError> {
        self.generations.bump_principal(principal);
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
        self.generations.bump_tenant(tenant);
        let tenant = tenant.to_string();
        self.cache
            .invalidate_entries_if(move |k, _v| k.tenant.as_deref() == Some(tenant.as_str()))?;
        Ok(())
    }

    /// Drop every entry built for `resource`, for every principal.
    ///
    /// Lookups miss from the moment this returns (see
    /// [`invalidate_principal`](Self::invalidate_principal) for the timing
    /// of freeing the memory). Call from code that changes a resource's
    /// authorization-relevant attributes when you cannot enumerate the
    /// principals that read it.
    pub fn invalidate_resource(&self, resource: &EntityUid) -> Result<(), moka::PredicateError> {
        self.generations.bump_resource(resource);
        let resource = resource.clone();
        self.cache
            .invalidate_entries_if(move |k, _v| k.resource == resource)?;
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

    async fn invalidate_resource(&self, resource: &EntityUid) -> Result<(), Self::Error> {
        MokaEntityCache::invalidate_resource(self, resource)
    }
}

impl<P> RequestEntityProvider for MokaEntityCache<P>
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

    /// Concurrent misses for one key share a single inner-provider call
    /// (moka's `try_get_with`); a hit returns the cached set without
    /// copying it.
    ///
    /// When the shared load fails, the caller that ran it gets the
    /// provider's own error. Callers that joined that load get an
    /// [`AuthzError::EntityBuild`] carrying its message, because the error
    /// value is shared and `AuthzError` is not `Clone`.
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

            self.cache
                .try_get_with(key, async {
                    self.inner
                        .entities_for(session, principal, resource, action)
                        .await
                        .map(Arc::new)
                })
                .await
                .map_err(|shared| {
                    Arc::try_unwrap(shared)
                        .unwrap_or_else(|shared| AuthzError::EntityBuild(shared.to_string()))
                })
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod setter_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    struct Never;
    impl RequestEntityProvider for Never {
        fn entities_for<'a>(
            &'a self,
            _session: &'a crate::session::AuthSession,
            _principal: &'a EntityUid,
            _resource: &'a EntityUid,
            _action: &'a EntityUid,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<cedar_policy::Entities, AuthzError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(cedar_policy::Entities::empty()) })
        }
    }

    /// `.with_ttl(5s).with_capacity(100)` keeps the TTL; the old setter reset
    /// it to 60 s, so revoked roles stayed cached twelve times longer than set.
    #[test]
    fn fluent_setters_keep_each_others_settings() {
        let _unused = AtomicUsize::new(0);
        let cached = MokaEntityCache::new(Never)
            .with_ttl(Duration::from_secs(5))
            .with_capacity(100);
        assert_eq!(
            cached.cache.policy().time_to_live(),
            Some(Duration::from_secs(5))
        );
        assert_eq!(cached.cache.policy().max_capacity(), Some(100));
        let _ = Arc::new(());
    }
}
