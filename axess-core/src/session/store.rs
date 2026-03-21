//! Session storage and registry traits, plus in-memory implementations.

use crate::session::{data::SessionData, id::SessionId};
use crate::utils::random::SecureRng;
use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── SessionStore ──────────────────────────────────────────────────────────────

/// Typed, async session storage backend.
///
/// Implementors: [`MemorySessionStore`], `SqliteSessionStore`, `ValkeySessionStore`.
///
/// All methods accept `&self` — implementations are expected to use interior mutability
/// (`Arc<DashMap<…>>` for memory, connection pool for SQL/Valkey).
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

    /// Delete the session. Idempotent — does not error if the session is absent.
    fn delete(
        &self,
        id: &SessionId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Atomically delete the old session and create a new one with the same data.
    ///
    /// Used for session fixation prevention: after a successful login the existing
    /// pre-auth session ID must be replaced with a fresh one.
    fn cycle(
        &self,
        old_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
        rng: &mut impl SecureRng,
    ) -> impl std::future::Future<Output = Result<SessionId, Self::Error>> + Send;
}

// ── SessionRegistry ───────────────────────────────────────────────────────────

/// Tracks which sessions are valid for each user, enabling forced logout.
///
/// Implementors: [`MemorySessionRegistry`], `ValkeySessionRegistry`.
pub trait SessionRegistry: Send + Sync + Clone + 'static {
    /// The error type returned by registry operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Register a session ID as belonging to a user.
    fn register(
        &self,
        user_id: &str,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Return `true` if the given session ID is still valid for the user.
    fn is_valid(
        &self,
        user_id: &str,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send;

    /// Invalidate all sessions for a user (e.g. global logout, credential rotation).
    fn invalidate_user(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Invalidate a single session for a user.
    fn invalidate_session(
        &self,
        user_id: &str,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}

// ── MemorySessionStore ────────────────────────────────────────────────────────

/// In-memory session store backed by [`DashMap`].
///
/// Suitable for tests and single-node development. Data is lost on restart.
/// Call [`MemorySessionStore::purge_expired`] periodically to reclaim memory.
#[derive(Clone, Default)]
pub struct MemorySessionStore {
    sessions: Arc<DashMap<SessionId, (SessionData, Instant, Duration)>>,
}

impl MemorySessionStore {
    /// Create an empty in-memory session store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove all expired sessions. Call from a background task.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        self.sessions
            .retain(|_, (_, created_at, ttl)| now.duration_since(*created_at) < *ttl);
    }
}

/// Infallible error for the in-memory store.
#[derive(Debug, thiserror::Error)]
pub enum MemoryStoreError {
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl SessionStore for MemorySessionStore {
    type Error = MemoryStoreError;

    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        let now = Instant::now();
        if let Some(entry) = self.sessions.get(id) {
            let (data, created_at, ttl) = entry.value();
            if now.duration_since(*created_at) < *ttl {
                return Ok(Some(data.clone()));
            }
            // expired — drop the reference before removing
            drop(entry);
            self.sessions.remove(id);
        }
        Ok(None)
    }

    async fn save(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.sessions.insert(*id, (data.clone(), Instant::now(), ttl));
        Ok(())
    }

    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.sessions.remove(id);
        Ok(())
    }

    async fn cycle(
        &self,
        old_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
        rng: &mut impl SecureRng,
    ) -> Result<SessionId, Self::Error> {
        self.sessions.remove(old_id);
        let new_id = SessionId::new(rng);
        self.sessions.insert(new_id, (data.clone(), Instant::now(), ttl));
        Ok(new_id)
    }
}

// ── MemorySessionRegistry ─────────────────────────────────────────────────────

/// In-memory session registry backed by [`DashMap`].
///
/// Maps `user_id -> Set<SessionId>`. Suitable for tests and single-node dev.
#[derive(Clone, Default)]
pub struct MemorySessionRegistry {
    valid: Arc<DashMap<String, HashSet<SessionId>>>,
}

impl MemorySessionRegistry {
    /// Create an empty in-memory session registry.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Infallible error for the in-memory registry.
#[derive(Debug, thiserror::Error)]
pub enum MemoryRegistryError {}

impl SessionRegistry for MemorySessionRegistry {
    type Error = MemoryRegistryError;

    async fn register(&self, user_id: &str, session_id: &SessionId) -> Result<(), Self::Error> {
        self.valid
            .entry(user_id.to_string())
            .or_default()
            .insert(*session_id);
        Ok(())
    }

    async fn is_valid(&self, user_id: &str, session_id: &SessionId) -> Result<bool, Self::Error> {
        Ok(self
            .valid
            .get(user_id)
            .is_some_and(|set| set.contains(session_id)))
    }

    async fn invalidate_user(&self, user_id: &str) -> Result<(), Self::Error> {
        self.valid.remove(user_id);
        Ok(())
    }

    async fn invalidate_session(
        &self,
        user_id: &str,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        if let Some(mut set) = self.valid.get_mut(user_id) {
            set.remove(session_id);
        }
        Ok(())
    }
}
