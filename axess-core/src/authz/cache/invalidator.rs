//! Scope-aware cache invalidation contract.
//!
//! Policy updates, role changes, and tenant suspensions need to reach
//! the authz hot-path cache so the new state takes effect at the next
//! request, not the next TTL expiry. TTL-only invalidation means
//! the cache may serve stale decisions for up to the configured TTL
//! window, which audit findings frequently flag as a control gap.
//!
//! This trait unifies "drop entries matching this scope" across the
//! in-process [`EntityCache`](super::EntityCache), the Moka decorator
//! ([`MokaEntityCache`](super::MokaEntityCache), if compiled in), and
//! the Valkey decorator
//! ([`ValkeyEntityCache`](super::ValkeyEntityCache), if compiled in).
//! Adopters can dispatch through `dyn CacheInvalidator` from policy-
//! update handlers without naming the concrete cache layer.
//!
//! # Scope semantics
//!
//! - [`invalidate_principal`](CacheInvalidator::invalidate_principal):
//!   drop every entry whose `principal` field matches. Use when a
//!   user's roles change, a token is revoked, or an account is
//!   terminated.
//! - [`invalidate_tenant`](CacheInvalidator::invalidate_tenant):
//!   drop every entry whose `tenant` field matches. Use when a
//!   tenant's policy bundle is reloaded, membership shifts, or the
//!   tenant is suspended.
//! - [`invalidate_all`](CacheInvalidator::invalidate_all): drop
//!   every entry. Use for global policy reloads only: a multi-tenant
//!   deployment paying this hammer on every change negates the cache.
//!
//! Implementations MAY treat scope invalidation as a no-op when the
//! cache backend cannot enumerate keys cheaply (e.g. a write-through
//! cache with no scan support). Adopters who need guaranteed scope
//! invalidation should pick a cache that supports it (the in-process
//! [`EntityCache`](super::EntityCache) does via
//! [`axess_cache::ClockTtlCache::invalidate_by`]).

use cedar_policy::EntityUid;
use std::future::Future;

/// Scope-aware invalidation for an authz entity-resolution cache.
///
/// All methods are async because the Valkey decorator round-trips to
/// the cluster; in-process impls just return `Ok(())` synchronously.
pub trait CacheInvalidator: Send + Sync + 'static {
    /// Backend-specific error type. In-process caches typically use
    /// [`std::convert::Infallible`]; network caches surface their
    /// driver error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Drop every cache entry whose `principal` matches.
    ///
    /// Call from role-change, account-suspension, and token-revoke
    /// paths so the next request sees the new authorization state
    /// without waiting for the TTL.
    fn invalidate_principal(
        &self,
        principal: &EntityUid,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Drop every cache entry whose `tenant` matches.
    ///
    /// Call from policy-bundle reload, tenant-suspension, and
    /// membership-change paths. The cache key carries an optional
    /// tenant; entries with `tenant = None` (guest sessions) are not
    /// matched by this method; use
    /// [`invalidate_all`](Self::invalidate_all) to drop guest entries
    /// alongside tenant ones.
    fn invalidate_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Drop every cache entry. Last-resort for global policy reloads
    /// or cache-corruption recovery.
    fn invalidate_all(&self) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
