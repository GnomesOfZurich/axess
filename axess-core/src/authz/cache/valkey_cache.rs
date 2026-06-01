//! Cluster-tier (Valkey/Redis) cache decorator for [`RequestEntityProvider`].
//!
//! Wraps any [`RequestEntityProvider`] in a network-shared cache so that
//! repeat authorization checks across pods reuse the same entity build.
//! Typically composed under [`super::MokaEntityCache`] as the L2 tier.

use std::sync::Arc;
use std::time::Duration;

use cedar_policy::{Entities, EntityUid};
use fred::prelude::*;
use tracing::warn;

use crate::authz::error::AuthzError;
use crate::authz::provider::RequestEntityProvider;
use crate::health::{HealthCheck, HealthStatus};
use crate::session::AuthSession;

const DEFAULT_PREFIX: &str = "axess";
const DEFAULT_TTL_SECS: u64 = 60;

/// Cluster-tier cache decorator over a [`RequestEntityProvider`].
///
/// # Tier
///
/// Network-shared cache via [`fred`] (Valkey/Redis). Sub-millisecond
/// lookup, cluster-wide scope. Use as the L2 tier; combine under an
/// in-process [`super::MokaEntityCache`] L1 for sub-microsecond hot-path
/// hits.
///
/// # Construction
///
/// ```rust,ignore
/// use axess_core::authz::cache::{MokaEntityCache, ValkeyEntityCache};
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// let provider = MyEntityProvider::new(db);
/// let provider = ValkeyEntityCache::new(provider, valkey_client)
///     .with_ttl(Duration::from_secs(60));
/// let provider = MokaEntityCache::new(provider).with_ttl(Duration::from_secs(5));
/// let provider: Arc<dyn axess_core::authz::RequestEntityProvider> = Arc::new(provider);
/// ```
///
/// # Wire format
///
/// Cedar `Entities` are serialised as JSON via
/// `Entities::to_json_value` / `Entities::from_json_value` and stored as
/// UTF-8 bytes in Valkey. JSON is the only stable serialization format
/// `cedar_policy::Entities` exposes today; round-trip preserves entity
/// attributes, parents, and types.
///
/// # Cache key
///
/// `{prefix}:authz-entities:{principal}|{resource}|{action}`: the three
/// `EntityUid` `Display` representations joined with `|`. Cedar UIDs are
/// already serialisable text and unique enough that no extra hashing is
/// needed.
///
/// # Cross-pod invalidation
///
/// Apps that need cross-pod invalidation publish on the channel
/// `{prefix}:authz-entities-invalidated:{principal}` and have each pod
/// subscribe at startup. Because the cache key includes the principal
/// UID first, listeners can match by prefix or wildcard. axess does not
/// auto-subscribe; invalidation policy is application-specific (which
/// data mutations require which scope of cache eviction). See the design
/// doc for the recommended pattern.
///
/// # Errors
///
/// Errors from the inner provider are NOT cached. Errors from Valkey
/// (network, serialization) degrade silently to "cache miss + no
/// populate": the inner provider still answers correctly; the next
/// request retries. axess emits `tracing::warn!` on cache I/O failure
/// so operators can detect Valkey outages without authorization breaking.
pub struct ValkeyEntityCache<P>
where
    P: RequestEntityProvider,
{
    inner: P,
    client: Client,
    prefix: Arc<str>,
    ttl: Duration,
}

impl<P> ValkeyEntityCache<P>
where
    P: RequestEntityProvider,
{
    /// Wrap `inner` with a Valkey cache using the default prefix
    /// (`axess`) and 60-second TTL.
    pub fn new(inner: P, client: Client) -> Self {
        Self {
            inner,
            client,
            prefix: DEFAULT_PREFIX.into(),
            ttl: Duration::from_secs(DEFAULT_TTL_SECS),
        }
    }

    /// Construct with explicit prefix and TTL.
    pub fn with_options(
        inner: P,
        client: Client,
        prefix: impl Into<Arc<str>>,
        ttl: Duration,
    ) -> Self {
        Self {
            inner,
            client,
            prefix: prefix.into(),
            ttl,
        }
    }

    /// Fluent: set TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Fluent: set key prefix.
    pub fn with_prefix(mut self, prefix: impl Into<Arc<str>>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Build the cache key for `(principal, tenant, resource, action)`.
    /// Tenant from session disambiguates entries for the same user
    /// acting in different tenants (membership model).
    fn cache_key(
        &self,
        principal: &EntityUid,
        tenant: Option<&str>,
        resource: &EntityUid,
        action: &EntityUid,
    ) -> String {
        format!(
            "{}:authz-entities:{principal}|{t}|{resource}|{action}",
            self.prefix,
            t = tenant.unwrap_or(""),
        )
    }

    /// Invalidate the cache entry for `(principal, tenant, resource, action)`.
    ///
    /// Operates on the local Valkey state only; for cross-pod propagation,
    /// publish on `{prefix}:authz-entities-invalidated:{principal}` and
    /// have each pod subscribe.
    pub async fn invalidate(
        &self,
        principal: &EntityUid,
        tenant: Option<&str>,
        resource: &EntityUid,
        action: &EntityUid,
    ) {
        let key = self.cache_key(principal, tenant, resource, action);
        let _: Result<(), _> = self.client.del(&key).await;
    }

    /// Borrow the inner provider for read access.
    pub fn inner(&self) -> &P {
        &self.inner
    }

    /// Glob-pattern prefix matching every cache key this decorator
    /// writes. Used by the scope-invalidation helpers to scope SCAN
    /// to this decorator's keys instead of the whole Valkey instance.
    fn key_prefix_pattern(&self) -> String {
        format!("{}:authz-entities:*", self.prefix)
    }

    /// SCAN + DEL every key matching `pattern`. Iterates with a small
    /// COUNT hint so a populated cache doesn't block the Valkey
    /// connection on a single round-trip.
    ///
    /// Uses cursor-based iteration directly (no `Stream` adapter) to
    /// avoid pulling `futures-util` into axess-core's transitive
    /// surface for one call site.
    async fn scan_and_delete(&self, pattern: &str) -> Result<(), fred::error::Error> {
        let mut cursor: String = "0".to_string();
        loop {
            let (next_cursor, batch): (String, Vec<String>) = self
                .client
                .scan_page(cursor.clone(), pattern, Some(256), None)
                .await?;
            if !batch.is_empty() {
                let _: () = self.client.del(batch).await?;
            }
            if next_cursor == "0" {
                break;
            }
            cursor = next_cursor;
        }
        Ok(())
    }

    /// Drop every entry under this decorator's prefix.
    ///
    /// Runs a SCAN over `{prefix}:authz-entities:*` and DELs the
    /// matching keys in batches. Cheap for small caches, O(N) over
    /// the live key set otherwise.
    pub async fn invalidate_all(&self) -> Result<(), fred::error::Error> {
        let pattern = self.key_prefix_pattern();
        self.scan_and_delete(&pattern).await
    }

    /// Drop every cache entry whose `principal` segment matches.
    ///
    /// Uses Valkey's `SCAN MATCH` with the per-key encoding
    /// `{prefix}:authz-entities:{principal}|{tenant}|{resource}|{action}`,
    /// so the glob pattern `{prefix}:authz-entities:{principal}|*`
    /// touches only matching entries; no whole-keyspace scan.
    pub async fn invalidate_principal(
        &self,
        principal: &EntityUid,
    ) -> Result<(), fred::error::Error> {
        let pattern = format!("{}:authz-entities:{principal}|*", self.prefix);
        self.scan_and_delete(&pattern).await
    }

    /// Drop every cache entry whose `tenant` segment matches.
    ///
    /// Implementation note: the cache key encodes principal **before**
    /// tenant, so a glob like `*|{tenant}|*` would match across the
    /// whole `*` (principal) range, which Valkey supports but
    /// requires care if the principal stringification can contain
    /// `|`. Cedar EntityUid strings do not contain `|` in practice,
    /// so the pattern is safe; if you adopt a custom EntityUid format
    /// that does, prefer a per-tenant key prefix instead.
    pub async fn invalidate_tenant(&self, tenant: &str) -> Result<(), fred::error::Error> {
        let pattern = format!("{}:authz-entities:*|{tenant}|*", self.prefix);
        self.scan_and_delete(&pattern).await
    }
}

impl<P> super::invalidator::CacheInvalidator for ValkeyEntityCache<P>
where
    P: RequestEntityProvider + 'static,
{
    type Error = fred::error::Error;

    async fn invalidate_principal(&self, principal: &EntityUid) -> Result<(), Self::Error> {
        ValkeyEntityCache::invalidate_principal(self, principal).await
    }

    async fn invalidate_tenant(&self, tenant: &str) -> Result<(), Self::Error> {
        ValkeyEntityCache::invalidate_tenant(self, tenant).await
    }

    async fn invalidate_all(&self) -> Result<(), Self::Error> {
        ValkeyEntityCache::invalidate_all(self).await
    }
}

impl<P> RequestEntityProvider for ValkeyEntityCache<P>
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
            let tenant = session.tenant_id().await;
            let tenant_str = tenant.as_ref().map(|t| t.to_string());
            let key = self.cache_key(principal, tenant_str.as_deref(), resource, action);

            // Cache lookup. Failures (network, deser) degrade to miss
            // with a warn; never break authorization for a cache fault.
            match self.client.get::<Option<String>, _>(&key).await {
                Ok(Some(json_str)) => match serde_json::from_str::<serde_json::Value>(&json_str) {
                    Ok(json) => match Entities::from_json_value(json, None) {
                        Ok(entities) => return Ok(entities),
                        Err(e) => {
                            warn!(?e, key = %key, "valkey cache: Entities::from_json_value failed; treating as miss");
                        }
                    },
                    Err(e) => {
                        warn!(?e, key = %key, "valkey cache: serde_json parse failed; treating as miss");
                    }
                },
                Ok(None) => {} // miss; fall through
                Err(e) => {
                    warn!(?e, key = %key, "valkey cache: GET failed; treating as miss");
                }
            }

            // Build via inner provider.
            let entities = self
                .inner
                .entities_for(session, principal, resource, action)
                .await?;

            // Best-effort populate. Failure to write is a warn, not a hard
            // error; the request already has its answer.
            match entities.to_json_value() {
                Ok(json) => match serde_json::to_string(&json) {
                    Ok(s) => {
                        let ttl_secs = self.ttl.as_secs().min(i64::MAX as u64) as i64;
                        let res: Result<(), _> = self
                            .client
                            .set(&key, s, Some(Expiration::EX(ttl_secs)), None, false)
                            .await;
                        if let Err(e) = res {
                            warn!(?e, key = %key, "valkey cache: SET failed");
                        }
                    }
                    Err(e) => warn!(?e, key = %key, "valkey cache: serde_json serialize failed"),
                },
                Err(e) => warn!(?e, key = %key, "valkey cache: Entities::to_json_value failed"),
            }

            Ok(entities)
        })
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────────────

/// Bounded health check: round-trips `PING` to Valkey with a 2-second
/// ceiling. The cache itself is fail-soft (errors degrade to
/// cache-miss + warn-log, not a denied authorization), so an
/// unhealthy result here is operational information rather than a
/// circuit-breaker trigger; adopters running readiness probes can
/// surface "Valkey down → no shared L2 cache, falling back to direct
/// provider" as a degraded-but-serving state.
impl<P> HealthCheck for ValkeyEntityCache<P>
where
    P: RequestEntityProvider + Send + Sync,
{
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async {
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                self.client.ping::<()>(None),
            )
            .await
            {
                Ok(Ok(_)) => HealthStatus::Healthy,
                Ok(Err(e)) => HealthStatus::Unhealthy(format!("valkey cache PING failed: {e}")),
                Err(_) => HealthStatus::Unhealthy("valkey cache PING timeout (2s)".into()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::Entities;
    use std::str::FromStr;

    struct StubProvider;
    impl RequestEntityProvider for StubProvider {
        fn entities_for<'a>(
            &'a self,
            _session: &'a AuthSession,
            _principal: &'a EntityUid,
            _resource: &'a EntityUid,
            _action: &'a EntityUid,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(Entities::empty()) })
        }
    }

    fn uid(s: &str) -> EntityUid {
        EntityUid::from_str(s).expect("valid EntityUid literal")
    }

    fn cache() -> ValkeyEntityCache<StubProvider> {
        ValkeyEntityCache::new(StubProvider, Client::default())
    }

    #[test]
    fn cache_key_distinguishes_inputs_and_carries_components() {
        let c = cache();
        let p = uid("App::User::\"alice\"");
        let r1 = uid("App::Doc::\"doc-1\"");
        let r2 = uid("App::Doc::\"doc-2\"");
        let a = uid("App::Action::\"View\"");

        let k1 = c.cache_key(&p, Some("t1"), &r1, &a);
        let k2 = c.cache_key(&p, Some("t1"), &r2, &a);
        let k3 = c.cache_key(&p, Some("t2"), &r1, &a);
        let k_none = c.cache_key(&p, None, &r1, &a);

        assert!(
            k1.contains("alice") && k1.contains("doc-1") && k1.contains("View"),
            "key must carry principal/resource/action: {k1}"
        );
        assert!(
            k1.starts_with(&format!("{DEFAULT_PREFIX}:authz-entities:")),
            "key must carry prefix namespace: {k1}"
        );
        assert_ne!(k1, k2, "different resources must yield different keys");
        assert_ne!(k1, k3, "different tenants must yield different keys");
        assert_ne!(
            k1, k_none,
            "Some(tenant) and None must yield different keys"
        );
        assert!(
            !k1.is_empty() && k1 != "xyzzy",
            "kills `String::new()` and `xyzzy` mutations"
        );
    }
}
