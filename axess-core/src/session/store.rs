//! Session storage and registry traits, plus in-memory implementations.

#[cfg(any(test, feature = "memory"))]
use crate::health::{HealthCheck, HealthStatus};
#[cfg(any(test, feature = "memory"))]
use crate::locked::lock;
use crate::session::{data::SessionData, id::SessionId};
#[cfg(any(test, feature = "memory"))]
use crate::store::{MemoryStore, Store};
#[cfg(any(test, feature = "memory"))]
use std::collections::HashMap;
#[cfg(any(test, feature = "memory"))]
use std::future::Future;
#[cfg(any(test, feature = "memory"))]
use std::pin::Pin;
#[cfg(any(test, feature = "memory"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(test, feature = "memory"))]
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ── SessionStore ──────────────────────────────────────────────────────────────

/// What [`SessionStore::cycle`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum CycleOutcome {
    /// The data is stored under the new id and the old row is gone.
    Rotated,
    /// The old row was required but was not live (deleted or expired since
    /// the caller loaded it). Nothing was written.
    SessionGone,
}

/// What [`SessionStore::update_if_revision`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ConditionalUpdate {
    /// The stored data carried the expected revision and was replaced.
    Written,
    /// A live row exists but holds another revision: a concurrent request
    /// wrote it since the caller loaded. Nothing was written.
    Conflict,
    /// No live row: the session was deleted or expired. Nothing was written.
    Gone,
}

/// Typed, async session storage backend.
///
/// Implementors: [`MemorySessionStore`], `SqliteSessionStore`, `ValkeySessionStore`.
///
/// All methods accept `&self`; implementations are expected to use
/// interior mutability (`Arc<RwLock<HashMap<...>>>` for memory, connection
/// pool for SQL/Valkey).
///
/// # Zero TTL
///
/// A zero `ttl` means the data is already expired, and no shipped store
/// keeps anything for it: [`save`](Self::save) removes the row under the id,
/// [`update`](Self::update) removes it and reports `false`,
/// [`update_if_revision`](Self::update_if_revision) removes the row whose
/// revision matched and reports [`ConditionalUpdate::Gone`] (another
/// revision is still a [`ConditionalUpdate::Conflict`], and removes
/// nothing), and [`cycle`](Self::cycle) removes both rows and reports
/// [`CycleOutcome::SessionGone`], whether or not the old row was required.
/// An adopter's store should do the same: a session the layer meant to end
/// at once must not stay loadable until an older, longer expiry runs out.
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

    /// Replace the data of a session that is still stored.
    ///
    /// Returns `Ok(true)` when a live (stored, unexpired) row under `id` was
    /// replaced, and `Ok(false)` when there is none: the session was deleted
    /// (logout, administrator revocation, front-channel logout) or expired
    /// since the caller loaded it. In the `false` case nothing is written, so
    /// a request that was in flight while its session was ended cannot bring
    /// the session back. [`save`](Self::save) stays the way to create a row.
    ///
    /// The check and the write are one atomic step in every shipped backend
    /// (an `UPDATE ... WHERE`, a `SET ... XX`, a guarded map entry).
    fn update(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send;

    /// Replace the data of a live session only while the stored data still
    /// carries `expected_revision` ([`SessionData::revision`]).
    ///
    /// The compare-and-swap behind single-use session state: two requests
    /// that loaded the same revision cannot both write, so only one of them
    /// consumes a one-shot value. The loser gets
    /// [`ConditionalUpdate::Conflict`] and nothing is written; a row that no
    /// longer exists is [`ConditionalUpdate::Gone`].
    ///
    /// The comparison and the write are one atomic step in every shipped
    /// backend: the SQL stores replace the row only while it still holds the
    /// bytes that were compared, Valkey runs a script (so a deployment
    /// without scripting gets an error, never a weaker compare), and the
    /// memory store holds the entry's lock. The revision is what decides: a
    /// concurrent load's re-seal of the row changes its bytes and keeps its
    /// revision, so a write that found other bytes reads the row again and
    /// is retried while the revision still matches.
    fn update_if_revision(
        &self,
        id: &SessionId,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> impl std::future::Future<Output = Result<ConditionalUpdate, Self::Error>> + Send;

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
    /// `require_old` says whether the old row must still be live. The layer
    /// passes `true` when the request ran under a stored session, so a
    /// rotation that races a logout does not carry the authenticated data
    /// over to the new id: the delete of the old row decides, and when it
    /// removed nothing the call returns [`CycleOutcome::SessionGone`] and
    /// writes nothing. With `require_old == false` (a login on a fresh
    /// guest whose id was never stored) the old row may be absent and the
    /// new row is always written.
    ///
    /// A failed write MUST leave the caller able to fail closed: the layer
    /// deletes the old id after any error, so a backend that cannot keep the
    /// old row on failure (the Valkey fallback without scripting) does not
    /// weaken the guarantee. Transactional backends (SQL) do the delete and
    /// the write in one transaction; Valkey runs one script. Writing the new
    /// id must be idempotent: a retry of the same rotation succeeds.
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
        require_old: bool,
    ) -> impl std::future::Future<Output = Result<CycleOutcome, Self::Error>> + Send;

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
    /// [`AuthnServiceBuilder::with_max_sessions_per_user`](crate::authn::service::AuthnServiceBuilder::with_max_sessions_per_user)
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

#[cfg(any(
    test,
    feature = "memory",
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
pub(crate) mod cas;
mod handles;
pub(crate) use handles::note_revocation;
pub use handles::{
    RevocationError, SessionLiveness, SessionRegistryAdapter, SessionRegistryHandle, SessionRevoker,
};

// ── MemorySessionStore ────────────────────────────────────────────────────────
//
// The in-memory store + registry below are gated behind
// `#[cfg(any(test, feature = "memory"))]` so production builds that don't
// opt in cannot accidentally ship `MemorySessionStore` / `MemorySessionRegistry`
//; both are dev/test-only (data lost on restart, no cross-node coordination).
// `cfg(test)` keeps them available for the in-crate test suite without
// requiring `--features memory` on every `cargo test` invocation.

/// In-memory session store backed by one `RwLock<HashMap>`.
///
/// # Lock granularity
///
/// One lock covers the whole table: reads (`load`, `snapshot`) share it,
/// every write takes it alone, and the purge that runs every 1024 writes
/// holds it for a full scan. That is the right trade at test and
/// single-node sizes and the wrong one for a contended server, which is
/// not what this store is for.
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
        if ttl.is_zero() {
            // Already expired: nothing may be stored, and a previous entry
            // under this id must not outlive the expiry it was just given.
            return self.inner.delete(id).await;
        }
        self.inner.put(id, data, ttl).await?;
        self.maybe_auto_purge();
        Ok(())
    }

    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.delete(id).await
    }

    async fn update(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        if ttl.is_zero() {
            // Already expired: nothing may stay stored under this id.
            self.inner.remove_live(id);
            return Ok(false);
        }
        let replaced = self.inner.replace_live(id, data, ttl);
        if replaced {
            self.maybe_auto_purge();
        }
        Ok(replaced)
    }

    async fn update_if_revision(
        &self,
        id: &SessionId,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        cas::cas_by_revision(self, id, expected_revision, data, ttl).await
    }

    async fn cycle(
        &self,
        old_id: &SessionId,
        new_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        if ttl.is_zero() {
            // Already expired: the rotated session is stored nowhere, so both
            // entries go and the session is reported gone, never as rotated.
            self.inner.remove_live(old_id);
            self.inner.remove_live(new_id);
            return Ok(CycleOutcome::SessionGone);
        }
        // The removal of the old row decides: `remove_live` takes the entry
        // out of the map in one step, so of two racing rotations (or a
        // rotation and a logout) exactly one sees a live row. Same id: the
        // row is replaced in place, never removed.
        if old_id == new_id {
            if require_old {
                return Ok(if self.inner.replace_live(new_id, data, ttl) {
                    CycleOutcome::Rotated
                } else {
                    CycleOutcome::SessionGone
                });
            }
        } else {
            let was_live = self.inner.remove_live(old_id);
            if require_old && !was_live {
                return Ok(CycleOutcome::SessionGone);
            }
        }
        self.inner.put(new_id, data, ttl).await?;
        self.maybe_auto_purge();
        Ok(CycleOutcome::Rotated)
    }

    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        self.inner.prune_expired().await
    }
}

/// The in-memory store compares the stored revision: its entries are values,
/// replaced in one step under the map's shard lock.
#[cfg(any(test, feature = "memory"))]
impl cas::CasRow for MemorySessionStore {
    type Seen = u64;
    type Error = MemoryStoreError;

    async fn read(&self, id: &SessionId) -> Result<Option<(u64, u64)>, Self::Error> {
        Ok(self.inner.get(id).await?.map(|d| (d.revision, d.revision)))
    }

    async fn delete_if(&self, id: &SessionId, seen: &u64) -> Result<cas::CasWrite, Self::Error> {
        Ok(cas_outcome(
            self.inner.remove_live_if(id, |d| d.revision == *seen),
        ))
    }

    async fn replace_if(
        &self,
        id: &SessionId,
        seen: &u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<cas::CasWrite, Self::Error> {
        let written = cas_outcome(
            self.inner
                .replace_live_if(id, data, ttl, |d| d.revision == *seen),
        );
        if matches!(written, cas::CasWrite::Done) {
            self.maybe_auto_purge();
        }
        Ok(written)
    }
}

/// A conditional step of the in-memory store: `None` for no live entry,
/// otherwise whether the entry matched and the step ran.
#[cfg(any(test, feature = "memory"))]
fn cas_outcome(step: Option<bool>) -> cas::CasWrite {
    match step {
        None => cas::CasWrite::Gone,
        Some(true) => cas::CasWrite::Done,
        Some(false) => cas::CasWrite::Missed,
    }
}

#[cfg(any(test, feature = "memory"))]
impl HealthCheck for MemorySessionStore {
    fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async { HealthStatus::Healthy })
    }
}

// ── MemorySessionRegistry ─────────────────────────────────────────────────────

/// In-memory session registry backed by one `Mutex<HashMap>`.
///
/// Maps `user_id -> Vec<SessionId>` (insertion-ordered). **For testing
/// and single-node development only.**
///
/// Uses a `Vec<SessionId>` whose push order tracks insertion order so
/// [`Self::active_sessions`] returns sessions oldest-first, satisfying
/// the [`SessionRegistry::active_sessions`] "ordered oldest first"
/// contract (load-bearing for the
/// [`max_sessions_per_user`](crate::authn::service::AuthnServiceBuilder::with_max_sessions_per_user)
/// FIFO eviction in `complete_factor_step`). The cost is O(N) lookup
/// for `is_valid` and `invalidate_session`, but N is bounded by the
/// concurrent-session limit (typically ≤10) and the Memory registry
/// is testing-only.
///
/// # Lifetime
///
/// Each entry carries the time it was registered or last used, and is
/// forgotten once it is older than the registry's TTL (24 hours by default,
/// as in `ValkeySessionRegistry`; see [`with_ttl`](Self::with_ttl)). A
/// session that is used keeps its entry: `is_valid` moves the stamp forward
/// once half the TTL has gone. The clock is injectable with
/// [`with_clock`](Self::with_clock).
#[cfg(any(test, feature = "memory"))]
#[derive(Clone)]
pub struct MemorySessionRegistry {
    valid: Arc<Mutex<HashMap<Arc<str>, Vec<RegisteredSession>>>>,
    ttl: Duration,
    clock: Arc<dyn axess_clock::Clock>,
}

/// A session id and when it was registered or last used.
#[cfg(any(test, feature = "memory"))]
type RegisteredSession = (SessionId, chrono::DateTime<chrono::Utc>);

#[cfg(any(test, feature = "memory"))]
impl Default for MemorySessionRegistry {
    fn default() -> Self {
        Self {
            valid: Arc::default(),
            ttl: Duration::from_secs(24 * 60 * 60),
            clock: Arc::new(axess_clock::SystemClock),
        }
    }
}

#[cfg(any(test, feature = "memory"))]
impl MemorySessionRegistry {
    /// Create an empty in-memory session registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set how long an entry lives without being used. Defaults to 24 hours.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Inject a [`Clock`](axess_clock::Clock) for deterministic simulation
    /// testing. Defaults to [`SystemClock`](axess_clock::SystemClock).
    pub fn with_clock(mut self, clock: Arc<dyn axess_clock::Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The oldest stamp that is still live at `now`.
    fn cutoff(&self, now: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
        chrono::Duration::from_std(self.ttl)
            .ok()
            .and_then(|ttl| now.checked_sub_signed(ttl))
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC)
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
        // Dedup-on-insert preserves FIFO semantics; a re-register of an
        // existing id keeps the original position (it renews the stamp)
        // rather than appending a duplicate. Entries past the TTL go.
        let now = self.clock.now();
        let cutoff = self.cutoff(now);
        let mut valid = lock(&self.valid);
        let entry = valid.entry(Arc::from(user_id.to_string())).or_default();
        entry.retain(|(_, at)| *at > cutoff);
        match entry.iter_mut().find(|(s, _)| s == session_id) {
            Some((_, at)) => *at = now,
            None => entry.push((*session_id, now)),
        }
        Ok(())
    }

    async fn is_valid(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<bool, Self::Error> {
        let now = self.clock.now();
        let cutoff = self.cutoff(now);
        let mut valid = lock(&self.valid);
        let Some(sessions) = valid.get_mut(user_id.to_string().as_str()) else {
            return Ok(false);
        };
        let half = chrono::Duration::from_std(self.ttl / 2).unwrap_or(chrono::Duration::MAX);
        Ok(sessions
            .iter_mut()
            .find(|(s, _)| s == session_id)
            .is_some_and(|(_, at)| {
                let live = *at > cutoff;
                // A session that is used keeps its entry, as in the Valkey
                // registry: the stamp moves forward once half the TTL has gone.
                if live && now - *at >= half {
                    *at = now;
                }
                live
            }))
    }

    async fn invalidate_user(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), Self::Error> {
        lock(&self.valid).remove(user_id.to_string().as_str());
        Ok(())
    }

    async fn invalidate_session(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        let key = user_id.to_string();
        let mut valid = lock(&self.valid);
        if let Some(sessions) = valid.get_mut(key.as_str()) {
            sessions.retain(|(s, _)| s != session_id);
        }
        // A user with no session left keeps no entry.
        valid.retain(|k, v| &**k != key.as_str() || !v.is_empty());
        Ok(())
    }

    async fn active_sessions(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<Vec<SessionId>, Self::Error> {
        let cutoff = self.cutoff(self.clock.now());
        Ok(lock(&self.valid)
            .get(user_id.to_string().as_str())
            .map(|sessions| {
                sessions
                    .iter()
                    .filter(|(_, at)| *at > cutoff)
                    .map(|(s, _)| *s)
                    .collect()
            })
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

#[cfg(test)]
pub(crate) mod revival_tests;
