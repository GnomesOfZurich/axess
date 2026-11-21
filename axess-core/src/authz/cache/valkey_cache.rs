//! Cluster-tier (Valkey/Redis) cache decorator for [`RequestEntityProvider`].
//!
//! Wraps any [`RequestEntityProvider`] in a network-shared cache so that
//! repeat authorization checks across pods reuse the same entity build.
//! Typically composed under [`super::EntityCache`] as the L2 tier.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Duration;

use cedar_policy::{Entities, EntityUid};
use fred::prelude::*;
use tracing::warn;

use self::index_ops::{drain_index, store_indexed, ttl_millis};
use super::generation::Generations;
use crate::authz::error::AuthzError;
use crate::authz::provider::RequestEntityProvider;
use crate::health::{HealthCheck, HealthStatus};
use crate::session::AuthSession;

pub(crate) mod index_ops;

#[cfg(test)]
mod index_tests;
#[cfg(test)]
mod key_tests;
#[cfg(test)]
mod live_scope_tests;
#[cfg(test)]
mod live_tests;
#[cfg(test)]
mod untagged_cluster_tests;

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
/// nothing when it has none. Each part has its `%` and `|` percent-escaped
/// (`%25`, `%7C`), so a part cannot produce the separator and two different
/// inputs cannot produce one key; the tenant segment is `t:{tenant}` for a
/// session with a tenant and empty for one without, so no tenant and an
/// empty tenant are different keys. The tenant has its `:` escaped as well
/// (`%3A`), so its segment holds one `:`, after the `t`, and an entity UID
/// (whose text always holds `::`) cannot spell it. Cedar UIDs are already
/// serialisable text and unique enough that no extra hashing is needed.
///
/// # Entity index
///
/// Beside each entry the cache writes, for every entity UID in the entity
/// set and for the resource, a Valkey SET `{prefix}:authz-entities-uid:{uid}`
/// holding the entry's key, with the same TTL as the entry.
/// [`invalidate_resource`](Self::invalidate_resource) takes the members out
/// of that SET and deletes the entries they name, so it also drops the
/// entries built under a parent (a folder, group or role) whose UID is in
/// their entity sets. A member another pod adds while it runs stays in the
/// SET until a later read takes it. The index is written before the entry
/// and again after it, so an entry whose index could not be written is not
/// stored, and an entry whose member an invalidation on another pod took
/// between its index write and its entry write is indexed again for the
/// next invalidation.
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
/// # On a Valkey cluster
///
/// Give the prefix a hash tag (`with_prefix("{axess}")`): every entry and
/// index key then hashes to one slot, so the SCAN of an invalidation reaches
/// every entry and its DEL is one slot's. Without a hash tag the entries
/// would spread over the nodes, where the SCAN of an invalidation reaches
/// one node and its DEL is refused across slots, so an entry could outlive
/// the invalidation meant to drop it. On a clustered client whose prefix has
/// no hash tag the cache therefore stores nothing: every call reads the
/// inner provider, the first says why at `warn`, and an invalidation has
/// nothing to drop.
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
    /// Set once the cache has said it stores nothing on this cluster.
    untagged_warned: AtomicBool,
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
            untagged_warned: AtomicBool::new(false),
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
            untagged_warned: AtomicBool::new(false),
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

    /// Whether entries may be stored: on a single node always, on a cluster
    /// only under a hash-tag prefix (see the struct docs). Read on each call,
    /// since [`with_prefix`](Self::with_prefix) may change the prefix.
    fn stores_entries(&self) -> bool {
        !self.client.is_clustered() || has_hash_tag(&self.prefix)
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
            "{}:authz-entities:{p}|{t}|{r}|{a}|{d}",
            self.prefix,
            p = key_part(&principal.to_string()),
            t = tenant_part(tenant),
            r = key_part(&resource.to_string()),
            a = key_part(&action.to_string()),
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
            glob_escape(&key_part(&principal.to_string())),
            glob_escape(&tenant_part(tenant)),
            glob_escape(&key_part(&resource.to_string())),
            glob_escape(&key_part(&action.to_string())),
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
        if !self.stores_entries() {
            // Nothing was stored, so there is nothing to find.
            return Ok(());
        }
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
            glob_escape(&key_part(&principal.to_string()))
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
        if self.stores_entries() {
            let index = self.index_key(resource);
            drain_index(&self.client, &index).await?;
        }
        let pattern = format!(
            "{}:authz-entities:*|{}|*",
            self.prefix,
            glob_escape(&key_part(&resource.to_string()))
        );
        self.scan_and_delete(&pattern).await
    }

    /// The key of the SET naming the entries whose entity set holds `uid`.
    fn index_key(&self, uid: &EntityUid) -> String {
        format!("{}:authz-entities-uid:{uid}", self.prefix)
    }

    /// The index SETs an entry built for `resource` from `entities` is named
    /// in: one per entity in the set, and the resource's own.
    fn index_keys(&self, resource: &EntityUid, entities: &Entities) -> Vec<String> {
        let mut uids: Vec<EntityUid> = entities.iter().map(|e| e.uid()).collect();
        if !uids.contains(resource) {
            uids.push(resource.clone());
        }
        uids.iter().map(|uid| self.index_key(uid)).collect()
    }

    /// Drop every cache entry whose `tenant` segment matches.
    ///
    /// Implementation note: the cache key encodes principal **before**
    /// tenant, so the glob `*|t:{tenant}|*` matches across the whole `*`
    /// (principal) range, and any segment of a key could be the one it
    /// matches. The principal, tenant, resource and action of a key have
    /// their `|` and `%` percent-escaped, the tenant its `:` as well, and
    /// the discriminator is a hex digest. So the tenant segment holds one
    /// `:`, the principal, resource and action segments are entity UIDs
    /// whose text always holds `::` (a resource of type `t` included), and
    /// none of them can produce the `|t:{tenant}|` segment of a tenant; a
    /// tenant carrying `|` or `:` matches only its own entries.
    pub async fn invalidate_tenant(&self, tenant: &str) -> Result<(), fred::error::Error> {
        self.generations.bump_tenant(tenant);
        let pattern = self.tenant_pattern(tenant);
        self.scan_and_delete(&pattern).await
    }

    /// The SCAN pattern matching every entry of `tenant`.
    fn tenant_pattern(&self, tenant: &str) -> String {
        format!(
            "{}:authz-entities:*|{}|*",
            self.prefix,
            glob_escape(&tenant_part(Some(tenant)))
        )
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

/// A part of a cache key: `%` and the separator `|` percent-escaped, so a
/// part cannot produce the separator, two different inputs cannot produce
/// one key, and a part cannot produce the segment of another part's value.
fn key_part(s: &str) -> String {
    s.replace('%', "%25").replace('|', "%7C")
}

/// The tenant segment of a cache key: empty for a session without a tenant,
/// `t:` and the escaped tenant for one with, so no tenant and an empty
/// tenant are different keys. The tenant's `:` is escaped too (`%3A`, after
/// `%`, so the escape stays one to one), which leaves the segment one `:`
/// and keeps an entity UID, whose text always holds `::`, from spelling it.
fn tenant_part(tenant: Option<&str>) -> String {
    match tenant {
        None => String::new(),
        Some(t) => format!("t:{}", key_part(t).replace(':', "%3A")),
    }
}

/// Whether keys under `prefix` hash by a tag of the prefix: the key's first
/// `{` is in the prefix, and the first `}` after it is too, with something
/// between them. Every key under such a prefix is in one cluster slot.
fn has_hash_tag(prefix: &str) -> bool {
    prefix
        .find('{')
        .and_then(|open| prefix[open + 1..].find('}'))
        .is_some_and(|len| len > 0)
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
            if !self.stores_entries() {
                if !self.untagged_warned.swap(true, AtomicOrdering::Relaxed) {
                    warn!(
                        prefix = %self.prefix,
                        "valkey cache: the client is clustered and the prefix has no hash tag, so nothing is cached (give it one, such as {{axess}}); said once"
                    );
                }
                return self
                    .inner
                    .entities_for(session, principal, resource, action)
                    .await;
            }
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
            // error; the request already has its answer. The index is
            // written around the entry (see `store_indexed`), so a failure
            // leaves the entry unstored or indexed, never unindexed.
            let mut buf = Vec::new();
            match entities.write_to_json(&mut buf) {
                Ok(()) => match String::from_utf8(buf) {
                    Ok(s) => {
                        let indexes = self.index_keys(resource, &entities);
                        let stored =
                            store_indexed(&self.client, &indexes, &key, &s, ttl_millis(self.ttl))
                                .await;
                        if let Err(e) = &stored {
                            warn!(?e, key = %key, "valkey cache: storing the entry failed");
                        }
                        // Whether or not the store reported an error (the
                        // entry may have been written before it): an
                        // invalidation slipped in between the check and the
                        // write, so take the write back.
                        if !self.generations.is_current(
                            generation,
                            principal,
                            tenant_str.as_deref(),
                            resource,
                        ) {
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
