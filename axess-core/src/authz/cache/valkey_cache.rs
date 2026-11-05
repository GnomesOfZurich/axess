//! Cluster-tier (Valkey/Redis) cache decorator for [`RequestEntityProvider`].
//!
//! Wraps any [`RequestEntityProvider`] in a network-shared cache so that
//! repeat authorization checks across pods reuse the same entity build.
//! Typically composed under [`super::EntityCache`] as the L2 tier.

use std::sync::Arc;
use std::time::Duration;

use cedar_policy::{Entities, EntityUid};
use fred::prelude::*;
use tracing::warn;

use super::generation::Generations;
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
/// in-process [`super::EntityCache`] L1 for sub-microsecond hot-path
/// hits.
///
/// # Construction
///
/// ```rust,ignore
/// use axess_core::authz::cache::{EntityCache, ValkeyEntityCache};
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// let provider = MyEntityProvider::new(db);
/// let provider = ValkeyEntityCache::new(provider, valkey_client)
///     .with_ttl(Duration::from_secs(60));
/// let provider = EntityCache::new(provider).with_ttl(Duration::from_secs(5));
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
/// `{prefix}:authz-entities:{principal}|{tenant}|{resource}|{action}|{discriminator}`:
/// the three `EntityUid` `Display` representations and the tenant joined
/// with `|`, then the SHA-256 (hex) of the inner provider's
/// [`cache_discriminator`](RequestEntityProvider::cache_discriminator), or
/// nothing when it has none. Cedar UIDs are already serialisable text and
/// unique enough that no extra hashing is needed.
///
/// # Entity index
///
/// Beside each entry the cache writes, for every entity UID in the entity
/// set and for the resource, a Valkey SET `{prefix}:authz-entities-uid:{uid}`
/// holding the entry's key, with the same TTL as the entry.
/// [`invalidate_resource`](Self::invalidate_resource) reads that SET and
/// deletes the entries it names, so it also drops the entries built under a
/// parent (a folder, group or role) whose UID is in their entity sets. An
/// entry whose index could not be written is not stored.
///
/// # Caching contract
///
/// An entry is shared by every session of the same user and tenant that
/// asks for the same resource and action, for the whole TTL, on every pod.
/// Entities that depend on other session state (MFA status, step-up
/// recency, impersonation) must not be cached unless the provider names
/// that state in its discriminator. The supported shape is to keep the
/// entities to durable facts and put per-session facts in the Cedar
/// context, which is never cached.
///
/// # Invalidation contract (load-bearing for security)
///
/// The cached value is the entity graph Cedar sees for
/// `(principal, resource, action)`. Role parents, tenant attributes,
/// ownership fields, and any ABAC attribute the provider set are all
/// baked into that graph. A cache hit RE-USES that graph unchanged
/// until TTL expiry.
///
/// This means every application-side mutation that changes the
/// **authorization-relevant state of a principal**: role assignment,
/// role removal, group membership change, account suspension, tenant
/// switch: MUST be paired with a call to
/// [`invalidate_principal`](Self::invalidate_principal) (or
/// [`invalidate_tenant`](Self::invalidate_tenant) for tenant-scoped
/// changes) on the mutating pod. Forgetting this leaves the affected
/// user acting under their old rights for up to [`ttl`](Self::with_ttl)
/// seconds, a real vulnerability for revocation.
///
/// TTL is a safety net, not a substitute. Short TTLs (60s default)
/// bound the worst-case exposure; explicit invalidation on mutation is
/// the correctness path.
///
/// # Cross-pod invalidation
///
/// [`invalidate_principal`](Self::invalidate_principal) evicts on the
/// caller pod only. For multi-pod deployments, invalidation must
/// propagate: publish on the channel
/// `{prefix}:authz-entities-invalidated:{principal}` after any local
/// eviction and have each pod subscribe at startup, calling its own
/// invalidator on receipt. Because the cache key includes the
/// principal UID first, listeners can match by prefix or wildcard.
/// axess does not auto-subscribe; invalidation policy is
/// application-specific (which data mutations require which scope of
/// cache eviction). See the design doc for the recommended pattern.
///
/// # Invalidation racing a load
///
/// An invalidation on this pod bumps a local generation before it deletes.
/// A load that started before and finishes after does not write its result,
/// and deletes it if the write was already issued, so a stale build cannot
/// outlive the invalidation that should have removed it. The guard is local
/// to the pod: an invalidation that runs on another pod reaches this one
/// only through the application's own cross-pod propagation.
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
    generations: Generations,
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
            generations: Generations::new(),
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
            generations: Generations::new(),
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
        discriminator: Option<&str>,
    ) -> String {
        format!(
            "{}:authz-entities:{principal}|{t}|{resource}|{action}|{d}",
            self.prefix,
            t = tenant.unwrap_or(""),
            d = discriminator.map(hash_discriminator).unwrap_or_default(),
        )
    }

    /// Invalidate the cache entries for `(principal, tenant, resource,
    /// action)`, whatever their cache discriminator.
    ///
    /// Operates on the local Valkey state only; for cross-pod propagation,
    /// publish on `{prefix}:authz-entities-invalidated:{principal}` and
    /// have each pod subscribe.
    ///
    /// Because a load already in flight on this pod must not repopulate the
    /// entry, a local generation of the principal is bumped as well, so
    /// loads of that principal that started before this call do not write.
    pub async fn invalidate(
        &self,
        principal: &EntityUid,
        tenant: Option<&str>,
        resource: &EntityUid,
        action: &EntityUid,
    ) -> Result<(), fred::error::Error> {
        self.generations.bump_principal(principal);
        let pattern = format!(
            "{}:authz-entities:{}|{}|{}|{}|*",
            self.prefix,
            glob_escape(&principal.to_string()),
            glob_escape(tenant.unwrap_or("")),
            glob_escape(&resource.to_string()),
            glob_escape(&action.to_string()),
        );
        self.scan_and_delete(&pattern).await
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
        self.generations.bump_all();
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
        self.generations.bump_principal(principal);
        let pattern = format!(
            "{}:authz-entities:{}|*",
            self.prefix,
            glob_escape(&principal.to_string())
        );
        self.scan_and_delete(&pattern).await
    }

    /// Drop every cache entry built for `resource`, for every principal, and
    /// every entry whose entity set holds `resource` as an entity of its own.
    ///
    /// The second part is what makes this the call for a parent entity: a
    /// folder, group or role is not the resource of the entries built under
    /// it, but it is in their entity sets, so changing it drops those entries
    /// too. The entries are found through the entity index (see the struct
    /// docs); the glob `{prefix}:authz-entities:*|{resource}|*` is run as
    /// well, for entries written before the index existed. Loads of that
    /// resource that started on this pod before the call do not write their
    /// result; a load for a child that started before the call may still be
    /// stored with the old parent until the TTL.
    pub async fn invalidate_resource(
        &self,
        resource: &EntityUid,
    ) -> Result<(), fred::error::Error> {
        self.generations.bump_resource(resource);
        let index = self.index_key(resource);
        let members: Vec<String> = self.client.smembers(&index).await?;
        for chunk in members.chunks(256) {
            let _: () = self.client.del(chunk.to_vec()).await?;
        }
        let _: () = self.client.del(&index).await?;
        let pattern = format!(
            "{}:authz-entities:*|{}|*",
            self.prefix,
            glob_escape(&resource.to_string())
        );
        self.scan_and_delete(&pattern).await
    }

    /// The key of the SET naming the entries whose entity set holds `uid`.
    fn index_key(&self, uid: &EntityUid) -> String {
        format!("{}:authz-entities-uid:{uid}", self.prefix)
    }

    /// Record `entry_key` in the index SET of every entity in `entities` and
    /// of `resource`, each expiring with the entry. Written before the entry
    /// so an entry is never stored unindexed.
    async fn write_index(
        &self,
        entry_key: &str,
        resource: &EntityUid,
        entities: &Entities,
    ) -> Result<(), fred::error::Error> {
        let mut uids: Vec<EntityUid> = entities.iter().map(|e| e.uid()).collect();
        if !uids.contains(resource) {
            uids.push(resource.clone());
        }
        let ttl_ms = self.ttl.as_millis().clamp(1, i64::MAX as u128) as i64;
        let pipeline = self.client.pipeline();
        for uid in uids {
            let index = self.index_key(&uid);
            let _: () = pipeline.sadd(&index, entry_key).await?;
            let _: () = pipeline.pexpire(&index, ttl_ms, None).await?;
        }
        let _: Vec<Value> = pipeline.all().await?;
        Ok(())
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
        self.generations.bump_tenant(tenant);
        let pattern = format!("{}:authz-entities:*|{}|*", self.prefix, glob_escape(tenant));
        self.scan_and_delete(&pattern).await
    }
}

/// The key segment for a cache discriminator: its SHA-256 as lower-case
/// hex, so an arbitrary string cannot carry the `|` separator or a glob
/// character into the key.
fn hash_discriminator(discriminator: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(discriminator.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Escape the characters SCAN MATCH reads as a glob (`*`, `?`, `[`, `]`,
/// `\`), so a principal such as `App::User::"a[1]"` matches its own key and
/// a tenant string of `*` cannot name every tenant's entries.
fn glob_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
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

    async fn invalidate_resource(&self, resource: &EntityUid) -> Result<(), Self::Error> {
        ValkeyEntityCache::invalidate_resource(self, resource).await
    }
}

impl<P> RequestEntityProvider for ValkeyEntityCache<P>
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
            let tenant = session.tenant_id().await;
            let tenant_str = tenant.as_ref().map(|t| t.to_string());
            let discriminator = self.inner.cache_discriminator(session).await;
            let key = self.cache_key(
                principal,
                tenant_str.as_deref(),
                resource,
                action,
                discriminator.as_deref(),
            );
            // Taken before the provider is read; see the struct docs on an
            // invalidation racing a load.
            let generation = self
                .generations
                .snapshot(principal, tenant_str.as_deref(), resource);

            // Cache lookup. Failures (network, deser) degrade to miss
            // with a warn; never break authorization for a cache fault.
            //
            // `Entities::from_json_value` is called with `None` (no schema
            // re-validation) as a deliberate hot-path optimisation. The
            // stored value was produced on our own miss path (below) by
            // the inner provider, which is validated once at startup via
            // `AuthzEntityProvider::validate_schema`. Re-validating every
            // cache read costs O(entities × attributes) on the critical
            // path with no correctness gain against our own writer. It
            // does NOT defend against Valkey being written to by anything
            // other than axess: that's a distinct trust boundary
            // (network segmentation, Valkey ACLs) and MUST NOT be relied
            // on cache-side. One exception is held by the evaluator rather
            // than here: `PolicyStore` checks every action-typed entity it
            // is handed against the schema and denies on a difference, so a
            // cached action entity stripped of its groups cannot take an
            // action out of a `forbid`. Note also the mutation-invalidation contract
            // documented on the struct: semantic staleness (a revoked
            // role still cached) is invisible to schema validation
            // regardless.
            match self.client.get::<Option<String>, _>(&key).await {
                Ok(Some(json_str)) => match Entities::from_json_str(&json_str, None) {
                    Ok(entities) => return Ok(entities),
                    Err(e) => {
                        warn!(?e, key = %key, "valkey cache: Entities::from_json_str failed; treating as miss");
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

            // An invalidation ran while the provider was being read: the
            // result may be the state it removed, so it is not stored.
            if !self
                .generations
                .is_current(generation, principal, tenant_str.as_deref(), resource)
            {
                return Ok(entities);
            }

            // Best-effort populate. Failure to write is a warn, not a hard
            // error; the request already has its answer.
            let mut buf = Vec::new();
            match entities.write_to_json(&mut buf) {
                Ok(()) => match String::from_utf8(buf) {
                    Ok(s) => {
                        if let Err(e) = self.write_index(&key, resource, &entities).await {
                            warn!(?e, key = %key, "valkey cache: index write failed; not storing");
                            return Ok(entities);
                        }
                        let res: Result<(), _> = self
                            .client
                            .set(&key, s, Some(expiration_for(self.ttl)), None, false)
                            .await;
                        if let Err(e) = res {
                            warn!(?e, key = %key, "valkey cache: SET failed");
                        } else if !self.generations.is_current(
                            generation,
                            principal,
                            tenant_str.as_deref(),
                            resource,
                        ) {
                            // An invalidation slipped in between the check
                            // and the write: take the write back.
                            let _: Result<(), _> = self.client.del(&key).await;
                        }
                    }
                    Err(e) => {
                        warn!(?e, key = %key, "valkey cache: serialized entities are not UTF-8")
                    }
                },
                Err(e) => warn!(?e, key = %key, "valkey cache: Entities::write_to_json failed"),
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

/// The `SET` expiry for a cache TTL. Written in milliseconds so a TTL under a
/// second is not rounded to zero (which Valkey refuses, silently disabling the
/// cache); never less than 1 ms.
fn expiration_for(ttl: Duration) -> Expiration {
    Expiration::PX(ttl.as_millis().clamp(1, i64::MAX as u128) as i64)
}

#[cfg(test)]
mod tests {
    /// A sub-second TTL must still be a positive expiry.
    #[test]
    fn a_sub_second_ttl_is_a_positive_expiry() {
        for ttl in [Duration::from_millis(500), Duration::ZERO] {
            match super::expiration_for(ttl) {
                Expiration::EX(n) | Expiration::PX(n) => assert!(n >= 1, "{ttl:?} gave {n}"),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(matches!(
            super::expiration_for(Duration::from_secs(60)),
            Expiration::PX(60_000)
        ));
    }

    /// The glob characters a principal or tenant may carry are escaped, so a
    /// principal `a[1]` matches its own key and a tenant `*` matches only
    /// the tenant spelled `*`.
    #[test]
    fn glob_escape_neutralises_pattern_characters() {
        assert_eq!(
            super::glob_escape(r#"App::User::"a[1]""#),
            r#"App::User::"a\[1\]""#
        );
        assert_eq!(super::glob_escape("*"), r"\*");
        assert_eq!(super::glob_escape("plain-tenant"), "plain-tenant");
        assert_eq!(super::glob_escape(r"a\b?"), r"a\\b\?");
    }

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

        let k1 = c.cache_key(&p, Some("t1"), &r1, &a, None);
        let k2 = c.cache_key(&p, Some("t1"), &r2, &a, None);
        let k3 = c.cache_key(&p, Some("t2"), &r1, &a, None);
        let k_none = c.cache_key(&p, None, &r1, &a, None);

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

    /// A session-state discriminator separates entries of one user and
    /// tenant, and reaches the key only as a hash.
    #[test]
    fn cache_key_separates_sessions_by_discriminator_without_leaking_it() {
        let c = cache();
        let p = uid("App::User::\"alice\"");
        let r = uid("App::Doc::\"doc-1\"");
        let a = uid("App::Action::\"View\"");

        let plain = c.cache_key(&p, Some("t1"), &r, &a, None);
        let mfa = c.cache_key(&p, Some("t1"), &r, &a, Some("mfa=1"));
        let no_mfa = c.cache_key(&p, Some("t1"), &r, &a, Some("mfa=0"));
        assert_ne!(mfa, no_mfa);
        assert_ne!(plain, mfa);
        assert!(!mfa.contains("mfa=1"), "the discriminator is hashed: {mfa}");
        assert_eq!(mfa, c.cache_key(&p, Some("t1"), &r, &a, Some("mfa=1")));
        assert_eq!(hash_discriminator("mfa=1").len(), 64);
    }
}

// ── live-server tests (ignored by default) ──────────────────────────────

#[cfg(test)]
mod live_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A provider whose resource sits in a folder: the folder is part of
    /// every entity set it builds, as the resource's parent.
    struct FolderedProvider {
        calls: Arc<AtomicUsize>,
        folder: EntityUid,
    }

    impl RequestEntityProvider for FolderedProvider {
        fn entities_for<'a>(
            &'a self,
            session: &'a AuthSession,
            principal: &'a EntityUid,
            resource: &'a EntityUid,
            action: &'a EntityUid,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
        > {
            let _ = (session, action);
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let entity = |uid: &EntityUid, parents: HashSet<EntityUid>| {
                    cedar_policy::Entity::new(uid.clone(), HashMap::new(), parents).unwrap()
                };
                Ok(Entities::from_entities(
                    vec![
                        entity(principal, HashSet::new()),
                        entity(&self.folder, HashSet::new()),
                        entity(resource, HashSet::from([self.folder.clone()])),
                    ],
                    None,
                )
                .unwrap())
            })
        }
    }

    fn guest_session() -> AuthSession {
        use crate::session::SessionData;
        use crate::session::id::SessionId;
        use crate::session::layer::{SessionHandle, SessionInner};
        use tokio::sync::RwLock;

        let inner = SessionInner {
            id: SessionId::new(&axess_rng::SystemRng),
            data: SessionData::default(),
            modified: false,
            needs_persist: false,
            regenerate: false,
            pre_cycle_id: None,
            rng: Arc::new(axess_rng::SystemRng),
            pending_fingerprint: None,
            max_custom_bytes: 64 * 1024,
            consume: None,
        };
        AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
    }

    async fn live_client() -> Client {
        let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let client = Client::new(Config::from_url(&url).expect("url"), None, None, None);
        client.init().await.expect("connect");
        client
    }

    /// Invalidating a folder drops the entries of the documents in it, on
    /// the shared tier as on the in-process one: the folder is in their
    /// entity sets, not in their keys.
    #[tokio::test]
    #[ignore = "requires a running Valkey (VALKEY_URL)"]
    async fn invalidating_a_folder_drops_the_entries_of_the_documents_in_it() {
        let calls = Arc::new(AtomicUsize::new(0));
        let folder = EntityUid::from_str("App::Folder::\"f1\"").unwrap();
        let cached = ValkeyEntityCache::with_options(
            FolderedProvider {
                calls: calls.clone(),
                folder: folder.clone(),
            },
            live_client().await,
            "axt_folder",
            Duration::from_secs(60),
        );
        let s = guest_session();
        let p = EntityUid::from_str("App::User::\"alice\"").unwrap();
        let a = EntityUid::from_str("App::Action::\"View\"").unwrap();
        let docs = [
            EntityUid::from_str("App::Doc::\"d1\"").unwrap(),
            EntityUid::from_str("App::Doc::\"d2\"").unwrap(),
        ];
        cached.invalidate_all().await.unwrap();
        for res in &docs {
            cached.entities_for(&s, &p, res, &a).await.unwrap();
        }
        cached.invalidate_resource(&folder).await.unwrap();
        for res in &docs {
            cached.entities_for(&s, &p, res, &a).await.unwrap();
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "both documents are rebuilt after their folder changed"
        );
    }
}
