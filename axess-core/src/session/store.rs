//! Session storage and registry traits, plus in-memory implementations.

#[cfg(any(test, feature = "memory"))]
use crate::health::{HealthCheck, HealthStatus};
use crate::session::{data::SessionData, id::SessionId};
#[cfg(any(test, feature = "memory"))]
use crate::store::{MemoryStore, Store};
#[cfg(any(test, feature = "memory"))]
use dashmap::DashMap;
use std::future::Future;
use std::pin::Pin;
#[cfg(any(test, feature = "memory"))]
use std::sync::Arc;
#[cfg(any(test, feature = "memory"))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// ── SessionStore ──────────────────────────────────────────────────────────────

/// Typed, async session storage backend.
///
/// Implementors: [`MemorySessionStore`], `SqliteSessionStore`, `ValkeySessionStore`.
///
/// All methods accept `&self`; implementations are expected to use
/// interior mutability (`Arc<DashMap<...>>` for memory, connection
/// pool for SQL/Valkey).
pub trait SessionStore: Send + Sync + Clone + 'static {
    /// The error type returned by storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load the session data for the given ID. Returns `None` if the session
    /// does not exist or has expired.
    fn load(
        &self,
        id: &SessionId,
    ) -> impl std::future::Future<Output = Result<Option<SessionData>, Self::Error>> + Send;

    /// Persist session data with a time-to-live.
    fn save(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Delete the session. Idempotent; does not error if the session is absent.
    fn delete(
        &self,
        id: &SessionId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Atomically delete the old session row and store the data under the
    /// caller-supplied new id.
    ///
    /// Used for session fixation prevention. The new id is supplied by the
    /// caller (rather than minted by the store) so that handler-side code
    /// can register the *post-rotation* id with `SessionRegistry` *before*
    /// the layer persists the rotation; without this ordering, every
    /// authenticated request fails its next `is_valid` check because the
    /// registry holds the pre-cycle id while the cookie carries the
    /// post-cycle one. See the internal `SessionInner::rotate_id` helper.
    ///
    /// Implementations MUST perform the delete and insert atomically (single
    /// transaction) so a crash mid-cycle never leaves the user with both
    /// rows or neither.
    ///
    /// # Orphan window
    ///
    /// There is a narrow race where `cycle` commits successfully but the
    /// task is cancelled (or the connection drops) before the new id is
    /// returned to the client. The new row exists but no client knows
    /// about it. The row is bounded by the session TTL (it dies on its
    /// own); applications that want to reclaim the storage faster
    /// should call [`prune_expired`](Self::prune_expired) on startup
    /// and on a schedule.
    fn cycle(
        &self,
        old_id: &SessionId,
        new_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Bulk-delete every session row whose TTL has elapsed.
    /// Returns the number of rows reclaimed.
    ///
    /// Provides a cheap recovery path for orphans created by a cancelled
    /// [`cycle`](Self::cycle) (the row exists in the store but no client
    /// holds the id); those rows naturally die at TTL, and this method
    /// is what an operator runs to evict them sooner. Recommended cadence:
    /// once on application startup, then every TTL window.
    ///
    /// # Required
    ///
    /// Every `SessionStore` MUST implement this; there is no safe
    /// default. A silent `Ok(0)` would let a misconfigured deployment
    /// believe eviction is running while sessions accumulate forever.
    /// Backends that rely on the underlying datastore for TTL eviction
    /// (Valkey/Redis) implement this as a documented no-op returning
    /// `Ok(0)`. Backends with their own row table (SQLite, Postgres,
    /// in-memory) actually delete.
    fn prune_expired(&self) -> impl std::future::Future<Output = Result<u64, Self::Error>> + Send;

    /// Return active (non-expired) sessions for the given user, newest first.
    ///
    /// `limit` caps how many entries are returned; pass a small value
    /// (e.g. 100) for breach-response UIs and admin "view active devices"
    /// pages, since a malicious or curious caller could otherwise scan
    /// every session for a high-cardinality user.
    ///
    /// # When to override
    ///
    /// Override on backends that can answer the query efficiently, typically
    /// by indexing a denormalised `user_id` column extracted from
    /// [`SessionData::auth_state`] at write time. Without an index this is
    /// an O(N) scan over the entire session table, which is why the
    /// default returns an empty `Vec` instead of doing the scan implicitly.
    ///
    /// # Use cases
    ///
    /// - **Breach response**: list every active session for an account
    ///   so an admin can revoke them via [`delete`](Self::delete).
    /// - **"Devices" UI**: let a user see their own active sessions
    ///   (mobile / desktop / tablet) and selectively log out.
    /// - **Concurrent-session enforcement**: count active sessions
    ///   before allowing a new login to exceed a per-user cap.
    ///
    /// # Default
    ///
    /// Returns `Ok(Vec::new())`. **Deliberately informational, not
    /// security-bearing.** Enumeration is hard for backends that store
    /// sessions as encrypted blobs keyed by `SessionId` (every in-tree
    /// SQL/Valkey backend), since the `user_id` lives inside the
    /// ciphertext and a naive scan would need to decrypt every row.
    /// Backends that don't support cheap enumeration return empty and
    /// the admin UI shows "no sessions"; operationally fine because the
    /// caller has no recovery path for "unsupported" that differs from
    /// "no sessions found."
    ///
    /// The security-relevant enumeration is
    /// [`SessionRegistry::active_sessions`], which IS required and
    /// drives concurrent-session-limit enforcement.
    fn find_sessions_for_user(
        &self,
        user_id: &crate::authn::ids::UserId,
        limit: usize,
    ) -> impl std::future::Future<Output = Result<Vec<(SessionId, SessionData)>, Self::Error>> + Send
    {
        let _ = (user_id, limit);
        std::future::ready(Ok(Vec::new()))
    }
}

// ── SessionRegistry ───────────────────────────────────────────────────────────

/// Tracks which sessions are valid for each user, enabling forced logout.
///
/// Implementors: [`MemorySessionRegistry`], `ValkeySessionRegistry`.
///
/// All methods accept the typed [`UserId`](crate::authn::ids::UserId) so the
/// trait surface cannot accidentally degrade to `&str` at the storage
/// boundary; implementations that need the underlying string can call
/// `.as_str()`.
pub trait SessionRegistry: Send + Sync + Clone + 'static {
    /// The error type returned by registry operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Register a session ID as belonging to a user.
    fn register(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Return `true` if the given session ID is still valid for the user.
    fn is_valid(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send;

    /// Invalidate all sessions for a user (e.g. global logout, credential rotation).
    fn invalidate_user(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Invalidate a single session for a user.
    fn invalidate_session(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Return all active session IDs for a user, ordered oldest first.
    ///
    /// Used by the concurrent-session-limit enforcement on
    /// [`AuthnService::with_max_sessions_per_user`](crate::authn::AuthnService::with_max_sessions_per_user)
    /// to FIFO-evict the oldest session when a new login would cross the
    /// cap. **This method is required**: a silent empty result here
    /// disables the limit without any warning, which is a security
    /// regression on every deployment using the cap. Backends that
    /// genuinely cannot enumerate (rare) should panic with
    /// `unimplemented!` so misconfiguration surfaces loudly, not
    /// silently.
    fn active_sessions(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> impl std::future::Future<Output = Result<Vec<SessionId>, Self::Error>> + Send;

    /// Resolve when the named session is invalidated (on this or another
    /// node), otherwise stay pending. Lets long-lived connections
    /// (WebSocket, SSE) react proactively to revocation rather than
    /// discovering it on the next message attempt. The future never
    /// resolves except on actual revocation, so `select!` callers don't
    /// need to guard against spurious wakeups.
    ///
    /// The default impl returns `std::future::pending()`; backends
    /// without push support (memory, SQLite without LISTEN/NOTIFY) thus
    /// compile but won't surface revocations. `ValkeySessionRegistry`
    /// overrides via Redis pub/sub.
    fn watch_revocation(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = ()> + Send {
        let _ = (user_id, session_id);
        std::future::pending()
    }
}

// Dyn-safe adapters over `SessionRegistry`. The trait uses RPITIT + an
// associated `Error` so it is not dyn-safe; `SessionRevoker` narrows to
// the logout surface (`invalidate_*`) and `SessionRegistryHandle` adds
// the full registry surface used by `AuthnService`. Error handling is
// baked in: `is_valid` fails closed, `invalidate_*` log-and-swallow,
// `register` returns `bool`, `active_sessions` fails open with `vec![]`
// so registry outages don't lock users out.

/// Dyn-safe narrow handle for session revocation. Implemented by
/// [`SessionRegistryAdapter`]; consumers (logout handlers) take
/// `Arc<dyn SessionRevoker>` so they can't accidentally call broader
/// registry operations.
pub trait SessionRevoker: Send + Sync + 'static {
    /// Invalidate every session belonging to the user.
    fn invalidate_user<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    /// Invalidate a single session for the user.
    fn invalidate_session<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Dyn-safe full handle for the session registry. Adds session
/// registration + validity-check + active-session listing on top of
/// [`SessionRevoker`].
pub trait SessionRegistryHandle: SessionRevoker {
    /// Return `true` if the named session is still valid for the user.
    /// Fails closed on registry error.
    fn is_valid<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

    /// Register a session under the user. Returns `true` on success,
    /// `false` on registry error. Callers that *require* the registry
    /// to track the session (signup, factor completion) should react to
    /// `false` by clearing the session and refusing authentication.
    fn register<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

    /// Return all active session IDs for the user, oldest first.
    /// Fails open with an empty vec on registry error so the
    /// concurrent-session limit doesn't lock users out during outage.
    fn active_sessions<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Vec<SessionId>> + Send + 'a>>;
}

/// Type-erasing adapter that turns any concrete [`SessionRegistry`] into
/// `dyn SessionRevoker` *and* `dyn SessionRegistryHandle`. One wrapper
/// for both shapes; pick the trait that matches the call site's needs.
pub struct SessionRegistryAdapter<T: SessionRegistry>(pub T);

impl<T: SessionRegistry + 'static> SessionRevoker for SessionRegistryAdapter<T> {
    fn invalidate_user<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if let Err(e) = self.0.invalidate_user(user_id).await {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "session registry invalidate_user failed; user sessions may remain active"
                );
            }
        })
    }

    fn invalidate_session<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if let Err(e) = self.0.invalidate_session(user_id, session_id).await {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "session registry invalidate_session failed"
                );
            }
        })
    }
}

impl<T: SessionRegistry + 'static> SessionRegistryHandle for SessionRegistryAdapter<T> {
    fn is_valid<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self.0.is_valid(user_id, session_id).await {
                Ok(valid) => valid,
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "session registry is_valid check failed; failing closed"
                    );
                    false
                }
            }
        })
    }

    fn register<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self.0.register(user_id, session_id).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "session registry register failed; caller must clear the session \
                         to avoid an Authenticated-but-untracked outcome"
                    );
                    false
                }
            }
        })
    }

    fn active_sessions<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Vec<SessionId>> + Send + 'a>> {
        Box::pin(async move {
            match self.0.active_sessions(user_id).await {
                Ok(sessions) => sessions,
                Err(e) => {
                    tracing::error!(
                        user_id = %user_id,
                        error = %e,
                        "session registry active_sessions failed; concurrent session limit disabled for this request"
                    );
                    Vec::new()
                }
            }
        })
    }
}

// ── MemorySessionStore ────────────────────────────────────────────────────────
//
// The in-memory store + registry below are gated behind
// `#[cfg(any(test, feature = "memory"))]` so production builds that don't
// opt in cannot accidentally ship `MemorySessionStore` / `MemorySessionRegistry`
//; both are dev/test-only (data lost on restart, no cross-node coordination).
// `cfg(test)` keeps them available for the in-crate test suite without
// requiring `--features memory` on every `cargo test` invocation.

/// In-memory session store backed by [`DashMap`].
///
/// **For testing and single-node development only.** Not suitable for production:
/// - Data is lost on process restart.
/// - No encryption at rest.
///
/// Expired sessions are automatically purged every 1024 write operations.
/// Call [`MemorySessionStore::purge_expired`] for on-demand cleanup.
///
/// # Time injection
///
/// Stores `created_at` as `chrono::DateTime<Utc>` against the injected
/// [`Clock`](axess_clock::Clock) (default
/// [`SystemClock`](axess_clock::SystemClock)). DST tests can
/// drive expiry deterministically by constructing the store with
/// [`with_clock`](Self::with_clock) and a `MockClock`.
/// In-memory session store. Suitable for tests and single-process
/// examples; not durable across restarts and not shared across nodes.
///
/// Thin newtype around [`MemoryStore<SessionId, SessionData>`] (the
/// shared [`Store<K, V>`] backend from
/// [`axess_core::store`](crate::store)). The session-domain
/// `SessionStore::cycle` lives on this wrapper because `Store<K, V>`
/// has no equivalent (cycle is a session-domain rename primitive, not
/// a kv primitive); everything else delegates to the inner backend.
#[cfg(any(test, feature = "memory"))]
#[derive(Clone)]
pub struct MemorySessionStore {
    inner: MemoryStore<SessionId, SessionData>,
    /// Write counter for lazy auto-purge scheduling. Sits outside the
    /// shared backend because auto-purge is a session-specific
    /// ergonomic; backends like `MemoryStore` leave eviction to the
    /// caller.
    write_count: Arc<AtomicU64>,
}

#[cfg(any(test, feature = "memory"))]
impl Default for MemorySessionStore {
    fn default() -> Self {
        Self {
            inner: MemoryStore::new(),
            write_count: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[cfg(any(test, feature = "memory"))]
impl MemorySessionStore {
    /// Create an empty in-memory session store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject a [`Clock`](axess_clock::Clock) for deterministic
    /// simulation testing. In production, leave at the default
    /// [`SystemClock`](axess_clock::SystemClock). Flows through to
    /// the underlying [`MemoryStore`] so TTL bookkeeping uses the
    /// same time source.
    pub fn with_clock(mut self, clock: Arc<dyn axess_clock::Clock>) -> Self {
        self.inner = self.inner.with_clock(clock);
        self
    }

    /// Remove all expired sessions. Call from a background task or let
    /// the auto-purge handle it (runs every 1024 writes).
    pub fn purge_expired(&self) {
        self.inner.prune_expired_sync();
    }

    /// Conditionally run auto-purge every 1024 writes.
    fn maybe_auto_purge(&self) {
        let count = self.write_count.fetch_add(1, Ordering::Relaxed);
        if count.is_multiple_of(1024) && !self.inner.is_empty() {
            self.purge_expired();
        }
    }
}

/// Infallible error for the in-memory store. The previous
/// `Serialization(serde_json::Error)` variant has been removed since
/// `MemoryStore<K, V>` holds values by-clone, never serialises, so the
/// variant was unreachable in practice. Adopters who matched on it
/// can drop the arm.
#[cfg(any(test, feature = "memory"))]
pub type MemoryStoreError = std::convert::Infallible;

#[cfg(any(test, feature = "memory"))]
impl SessionStore for MemorySessionStore {
    type Error = MemoryStoreError;

    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        self.inner.get(id).await
    }

    async fn save(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.inner.put(id, data, ttl).await?;
        self.maybe_auto_purge();
        Ok(())
    }

    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.delete(id).await
    }

    async fn cycle(
        &self,
        old_id: &SessionId,
        new_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        // `Store<K, V>` has no atomic-rename primitive; cycle is a
        // session-domain operation (rotate the id, preserve the data).
        // Two operations on the same DashMap-backed backend are
        // effectively atomic from the perspective of a single-process
        // session store; multi-node backends override `SessionStore::cycle`
        // with whatever native atomic the backend exposes.
        self.inner.delete(old_id).await?;
        self.inner.put(new_id, data, ttl).await?;
        self.maybe_auto_purge();
        Ok(())
    }

    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        self.inner.prune_expired().await
    }
}

#[cfg(any(test, feature = "memory"))]
impl HealthCheck for MemorySessionStore {
    fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async { HealthStatus::Healthy })
    }
}

// ── MemorySessionRegistry ─────────────────────────────────────────────────────

/// In-memory session registry backed by [`DashMap`].
///
/// Maps `user_id -> Vec<SessionId>` (insertion-ordered). **For testing
/// and single-node development only.**
///
/// Uses a `Vec<SessionId>` whose push order tracks insertion order so
/// [`Self::active_sessions`] returns sessions oldest-first, satisfying
/// the [`SessionRegistry::active_sessions`] "ordered oldest first"
/// contract (load-bearing for the
/// [`max_sessions_per_user`](crate::authn::service::AuthnService::with_max_sessions_per_user)
/// FIFO eviction in `complete_factor_step`). The cost is O(N) lookup
/// for `is_valid` and `invalidate_session`, but N is bounded by the
/// concurrent-session limit (typically ≤10) and the Memory registry
/// is testing-only.
#[cfg(any(test, feature = "memory"))]
#[derive(Clone, Default)]
pub struct MemorySessionRegistry {
    valid: Arc<DashMap<Arc<str>, Vec<SessionId>>>,
}

#[cfg(any(test, feature = "memory"))]
impl MemorySessionRegistry {
    /// Create an empty in-memory session registry.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Infallible error for the in-memory registry. The in-memory backend
/// cannot fail at the storage boundary, so callers can prove statically
/// that no error case is possible. Aliased to `std::convert::Infallible`
/// rather than carrying an empty enum so `?`-propagation and exhaustive
/// matches behave the canonical way.
#[cfg(any(test, feature = "memory"))]
pub type MemoryRegistryError = std::convert::Infallible;

#[cfg(any(test, feature = "memory"))]
impl SessionRegistry for MemorySessionRegistry {
    type Error = MemoryRegistryError;

    async fn register(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        // Dedup-on-insert preserves FIFO semantics; a re-
        // register of an existing id is a no-op (keeps the original
        // position) rather than appending a duplicate.
        let mut entry = self
            .valid
            .entry(Arc::from(user_id.to_string()))
            .or_default();
        if !entry.contains(session_id) {
            entry.push(*session_id);
        }
        Ok(())
    }

    async fn is_valid(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .valid
            .get(user_id.to_string().as_str())
            .is_some_and(|sessions| sessions.contains(session_id)))
    }

    async fn invalidate_user(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), Self::Error> {
        self.valid.remove(user_id.to_string().as_str());
        Ok(())
    }

    async fn invalidate_session(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        if let Some(mut sessions) = self.valid.get_mut(user_id.to_string().as_str()) {
            sessions.retain(|s| s != session_id);
        }
        Ok(())
    }

    async fn active_sessions(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<Vec<SessionId>, Self::Error> {
        Ok(self
            .valid
            .get(user_id.to_string().as_str())
            .map(|sessions| sessions.clone())
            .unwrap_or_default())
    }
}

#[cfg(any(test, feature = "memory"))]
impl HealthCheck for MemorySessionRegistry {
    fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async { HealthStatus::Healthy })
    }
}

#[cfg(test)]
mod memory_store_clock_tests;

#[cfg(test)]
mod memory_registry_tests;
