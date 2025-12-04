//! Session registry abstractions and the default in-memory store.
//!
//! This module exposes [`SessionRegistry`] for tracking authenticated sessions
//! plus [`SessionRegistryStore`], a tower-sessions based implementation used by
//! Axess to register, validate, and invalidate user/tenant sessions.

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{from_value, to_value};
use std::{
    collections::HashMap,
    fmt::Display,
    hash::{Hash, Hasher},
};
use time;
use time::Duration;
use tower_sessions::{session::Id as SessionId, session_store::SessionStore};
use tracing::{debug, error};

use crate::authn::errors::SessionRegistryError;

// TODO: turn both these consts into application configuration parameters!
const SESSION_REGISTRY_KEY: &str = "axess_session_registry";
const SESSION_EXPIRY_DURATION: Duration = Duration::seconds(3600);
struct FnvHasher(u128);

impl Hasher for FnvHasher {
    fn finish(&self) -> u64 {
        (self.0 & 0xFFFFFFFFFFFFFFFF) as u64
    }
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u128::from(byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
}

/// Metadata describing a registered authentication session.
///
/// `SessionMetadata` tracks the essential details for each session managed by the registry,
/// including its unique ID, associated user and tenant (if any), cryptographic session hash,
/// and timestamps for creation and last activity. This struct enables efficient lookup,
/// validation, and audit of sessions across users and tenants.
///
/// # Fields
/// - `session_id`: Unique identifier for the session (as a string; typically a UUID or numeric ID).
/// - `user_id`: Optional user ID associated with the session.
/// - `tenant_id`: Optional tenant ID associated with the session.
/// - `session_hash`: Cryptographically secure hash binding the session to its authentication state.
/// - `created_at`: Timestamp when the session was registered.
/// - `last_activity`: Timestamp of the most recent activity for this session.
///
/// # Usage
/// Used internally by [`SessionRegistry`] and [`SessionRegistryStore`] to track, validate,
/// and invalidate sessions for users and tenants. Enables audit logging and session lifecycle management.
///
/// # Example
/// ```rust
/// use axess_core::authn::session::registry::SessionMetadata;
///
/// let metadata = SessionMetadata {
///     session_id: "abc123".to_string(),
///     user_id: Some("user42".to_string()),
///     tenant_id: Some("tenantA".to_string()),
///     session_hash: "crabmeat".to_string(),
///     created_at: chrono::Utc::now(),
///     last_activity: chrono::Utc::now(),
/// };
/// assert_eq!(metadata.user_id.as_deref(), Some("user42"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Unique identifier for the session (as a string; typically a UUID or numeric ID).
    pub session_id: String, // TODO: Consider changing to tower_sessions::session::Id
    /// Optional user ID associated with the session.
    pub user_id: Option<String>,
    /// Optional tenant ID associated with the session.
    pub tenant_id: Option<String>,
    /// Cryptographically secure hash binding the session to its authentication state.
    pub session_hash: String,
    /// Timestamp when the session was registered.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Timestamp of the most recent activity for this session.
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

/// Trait for tracking and managing authentication sessions across users and tenants.
///
/// `SessionRegistry` provides an abstraction for registering, validating, and invalidating
/// sessions in a distributed or in-memory store. It supports multi-user and multi-tenant
/// scenarios, enabling secure session lifecycle management, audit logging, and administrative
/// operations such as forced logout.
///
/// Implementations (such as [`SessionRegistryStore`]) must ensure that session operations
/// are atomic and consistent, and should support efficient lookup by user, tenant, or session ID.
///
/// # Usage
/// - Register a session when a user authenticates.
/// - Validate a session's hash to ensure it matches the expected authentication state.
/// - Invalidate sessions for a user, tenant, or globally for administrative actions.
/// - Update last activity timestamps for session tracking and expiry.
///
/// # Example
/// ```rust,ignore
/// use axess_core::authn::session::registry::{SessionRegistry, SessionRegistryStore};
/// use tower_sessions::MemoryStore;
///
/// let store = MemoryStore::default();
/// let registry = SessionRegistryStore::new(store, 0, None, None);
///
/// // Register a session
/// registry.register_session(
///     "session_id",
///     Some(&"user_id"),
///     Some(&"tenant_id"),
///     "session_hash".to_string(),
/// ).await?;
///
/// // Validate session
/// let valid = registry.validate_session("session_id", "session_hash").await?;
/// assert!(valid);
///
/// // Invalidate all sessions for a user
/// let count = registry.invalidate_user_sessions(&"user_id").await?;
/// assert!(count > 0);
/// ```
#[async_trait]
pub trait SessionRegistry: Send + Sync + Clone + 'static {
    /// Register a session for a user and tenant.
    ///
    /// Stores the session metadata and associates it with the given user and tenant IDs.
    /// The `session_hash` should be a cryptographically secure value binding the session
    /// to its authentication state.
    async fn register_session<UId, TId>(
        &self,
        session_id: &str,
        user_id: Option<&UId>,
        tenant_id: Option<&TId>,
        session_hash: String,
    ) -> Result<(), SessionRegistryError>
    where
        UId: Display + Send + Sync,
        TId: Display + Send + Sync;

    /// Get all session IDs for a user.
    ///
    /// Returns a list of session IDs currently registered for the specified user.
    async fn get_user_sessions<UId>(
        &self,
        user_id: &UId,
    ) -> Result<Vec<String>, SessionRegistryError>
    where
        UId: Display + Send + Sync;

    /// Get all session IDs for a tenant.
    ///
    /// Returns a list of session IDs currently registered for the specified tenant.
    async fn get_tenant_sessions<TId>(
        &self,
        tenant_id: &TId,
    ) -> Result<Vec<String>, SessionRegistryError>
    where
        TId: Display + Send + Sync;

    /// Validate that a session is registered with the correct hash.
    ///
    /// Returns `true` if the session exists and its hash matches the expected value.
    async fn validate_session(
        &self,
        session_id: &str,
        expected_hash: &str,
    ) -> Result<bool, SessionRegistryError>;

    /// Update last activity timestamp for a session.
    ///
    /// This is used for session expiry and activity tracking.
    async fn touch_session(&self, session_id: &str) -> Result<(), SessionRegistryError>;

    /// Invalidate (delete) a specific session by ID.
    ///
    /// Removes the session from the registry and underlying store.
    async fn invalidate_session(&self, session_id: &str) -> Result<(), SessionRegistryError>;

    /// Invalidate all sessions for a user.
    ///
    /// Removes all sessions associated with the specified user.
    /// Returns the number of sessions invalidated.
    async fn invalidate_user_sessions<UId>(
        &self,
        user_id: &UId,
    ) -> Result<u64, SessionRegistryError>
    where
        UId: Display + Send + Sync;

    /// Invalidate all sessions for a tenant.
    ///
    /// Removes all sessions associated with the specified tenant.
    /// Returns the number of sessions invalidated.
    async fn invalidate_tenant_sessions<TId>(
        &self,
        tenant_id: &TId,
    ) -> Result<u64, SessionRegistryError>
    where
        TId: Display + Send + Sync;

    /// Invalidate all sessions globally.
    ///
    /// Removes all sessions from the registry and underlying store.
    /// Returns the number of sessions invalidated.
    async fn invalidate_all_sessions(&self) -> Result<u64, SessionRegistryError>;
}

/// Distributed session registry implementation backed by a tower-sessions compatible store.
///
/// `SessionRegistryStore` manages the lifecycle of authenticated sessions for users and tenants,
/// storing session metadata in a pluggable session store (e.g., in-memory, Redis/Valkey).
/// It supports multi-instance deployments by generating a deterministic registry ID from a seed,
/// allowing administrators to invalidate sessions across all application instances sharing the same registry.
///
/// # Features
/// - Tracks session metadata (ID, user, tenant, hash, timestamps) for audit and validation.
/// - Supports efficient lookup and invalidation by user, tenant, or globally.
/// - Pluggable store: works with any [`SessionStore`] (in-memory, Redis, Valkey, etc.).
/// - Deterministic registry ID generation for distributed setups.
/// - Configurable session expiry and registry key.
///
/// # Usage
/// - Create with [`SessionRegistryStore::new`] using a store, seed, optional expiry, and key.
/// - Use via the [`SessionRegistry`] trait for registration, validation, and invalidation.
/// - Share the same registry seed/key across instances to enable global session invalidation.
///
/// # Example
/// ```rust,ignore
/// use axess_core::authn::session::registry::{SessionRegistry, SessionRegistryStore};
/// use tower_sessions::{session, MemoryStore};
///
/// # tokio_test::block_on(async {
/// let store = MemoryStore::default();
/// let registry = SessionRegistryStore::new(store, 42, None, None);
///
/// // Register a session
/// registry.register_session(
///     "session_id",
///     Some(&"user_id"),
///     Some(&"tenant_id"),
///     "session_hash".to_string(),
/// ).await.unwrap();
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct SessionRegistryStore<S: SessionStore> {
    /// Underlying session store (in-memory, Redis/Valkey, etc.).
    store: S,
    /// Maximum age for session expiry.
    session_max_age: Duration,
    /// Key used to store the registry data in the session store.
    registry_key: String,
    /// Deterministically generated registry ID for distributed setups.
    registry_id: SessionId,
}

impl<S: SessionStore> SessionRegistryStore<S> {
    pub fn new(store: S, id_seed: u128, max_age: Option<Duration>, key: Option<String>) -> Self {
        let max_age = max_age.unwrap_or(SESSION_EXPIRY_DURATION);
        let registry_key = key.unwrap_or_else(|| SESSION_REGISTRY_KEY.into());
        let registry_id = Self::generate_registry_id(id_seed, registry_key.clone());
        Self {
            store,
            session_max_age: max_age,
            registry_key,
            registry_id,
        }
    }

    fn generate_registry_id(seed: u128, registry_key: String) -> SessionId {
        let mut hasher = FnvHasher(seed);
        registry_key.hash(&mut hasher);
        let hash = hasher.0;

        SessionId(hash as i128)
    }

    fn get_registry_id(&self) -> &SessionId {
        &self.registry_id
    }

    pub fn get_registry_key(&self) -> &String {
        &self.registry_key
    }

    pub fn get_session_max_age(&self) -> Duration {
        self.session_max_age
    }

    /// Get the full session registry
    async fn get_registry(&self) -> Result<Vec<SessionMetadata>, SessionRegistryError> {
        let registry_id = self.get_registry_id();

        tracing::debug!("Loading registry with ID: {registry_id:?}");
        if let Some(record) = self.store.load(registry_id).await? {
            tracing::debug!("Loaded registry record: {record:?}");
            let registry: Vec<SessionMetadata> = record
                .data
                .get(&self.registry_key)
                .and_then(|v| from_value(v.clone()).ok())
                .unwrap_or_default();
            Ok(registry)
        } else {
            tracing::debug!("No registry record found for ID: {:?}", registry_id);
            Ok(Vec::new())
        }
    }

    /// Save the session registry
    async fn save_registry(
        &self,
        registry: Vec<SessionMetadata>,
    ) -> Result<(), SessionRegistryError> {
        let registry_id = *self.get_registry_id();

        // Create or load the registry session record
        let mut record = self.store.load(&registry_id).await?.unwrap_or_else(|| {
            tower_sessions::session::Record {
                id: registry_id,
                data: HashMap::new(),
                expiry_date: time::OffsetDateTime::now_utc() + self.get_session_max_age(),
            }
        });

        // Store the registry data
        let registry_value = to_value(registry).map_err(|e| {
            error!("Failed to serialize session registry: {e}");
            SessionRegistryError::SerializationError(e.to_string())
        })?;

        record
            .data
            .insert(self.registry_key.clone(), registry_value);

        // Save back to store
        self.store.save(&record).await?;
        Ok(())
    }

    /// Filter sessions by user ID
    fn filter_by_user<UId: Display>(registry: &[SessionMetadata], user_id: &UId) -> Vec<String> {
        let user_id_str = user_id.to_string();
        registry
            .iter()
            .filter(|metadata| metadata.user_id.as_ref() == Some(&user_id_str))
            .map(|metadata| metadata.session_id.clone())
            .collect()
    }

    /// Filter sessions by tenant ID
    fn filter_by_tenant<TId: Display>(
        registry: &[SessionMetadata],
        tenant_id: &TId,
    ) -> Vec<String> {
        let tenant_id_str = tenant_id.to_string();
        registry
            .iter()
            .filter(|metadata| metadata.tenant_id.as_ref() == Some(&tenant_id_str))
            .map(|metadata| metadata.session_id.clone())
            .collect()
    }

    /// Remove sessions from registry and invalidate them in the store
    async fn invalidate_sessions_by_ids(
        &self,
        session_ids: &[String],
    ) -> Result<u64, SessionRegistryError> {
        let mut registry = self.get_registry().await?;
        let mut invalidated_count = 0;

        // Remove from registry and invalidate in store
        for session_id in session_ids {
            // Remove from registry
            if let Some(pos) = registry
                .iter()
                .position(|metadata| metadata.session_id == *session_id)
            {
                registry.remove(pos);
                invalidated_count += 1;
                debug!("Removed session {} from registry", session_id);
            }

            // Attempt to invalidate in store - this may fail for non-existent sessions
            // which is fine as we're cleaning up the registry
            if let Ok(session_id_obj) = session_id.parse::<SessionId>() {
                tracing::debug!("Parsed session ID: {:?}", session_id_obj);
                if let Err(e) = self.store.delete(&session_id_obj).await {
                    debug!("Failed to delete session {} from store: {}", session_id, e);
                } else {
                    debug!("Deleted session {} from store", session_id);
                }
            } else {
                tracing::error!("Failed to parse session ID: {}", session_id);
            }
        }

        // Save updated registry
        self.save_registry(registry).await?;
        Ok(invalidated_count)
    }
}

#[async_trait]
impl<S: SessionStore + Send + Sync + Clone> SessionRegistry for SessionRegistryStore<S> {
    async fn register_session<UId, TId>(
        &self,
        session_id: &str,
        user_id: Option<&UId>,
        tenant_id: Option<&TId>,
        session_hash: String,
    ) -> Result<(), SessionRegistryError>
    where
        UId: Display + Send + Sync,
        TId: Display + Send + Sync,
    {
        if user_id.is_none() {
            tracing::debug!("Registering guest session: {}", session_id);
        }
        if tenant_id.is_none() {
            tracing::debug!("Registering guest session: {}", session_id);
        }

        // Defensive: Only allow valid session IDs
        if session_id.parse::<SessionId>().is_err() {
            error!("Attempted to register invalid session ID: {session_id}");
            // return Err(SessionRegistryError::SerializationError(format!(
            //     "Invalid session ID format: {session_id}"
            // )));

            // Do NOT register, but do NOT treat this as a fatal error for the caller.
            return Ok(());
        }

        let mut registry = self.get_registry().await?;

        // Check if session already exists - update if so
        if let Some(existing) = registry.iter_mut().find(|m| m.session_id == session_id) {
            existing.session_hash = session_hash;
            existing.last_activity = chrono::Utc::now();
            debug!("Updated existing session {} registration", session_id);
        } else {
            // Add new session
            let metadata = SessionMetadata {
                session_id: session_id.to_string(),
                user_id: user_id.map(|id| id.to_string()),
                tenant_id: tenant_id.map(|id| id.to_string()),
                session_hash,
                created_at: chrono::Utc::now(),
                last_activity: chrono::Utc::now(),
            };
            registry.push(metadata);
            debug!("Registered new session {}", session_id);
        }

        self.save_registry(registry).await?;
        Ok(())
    }

    async fn get_user_sessions<UId>(
        &self,
        user_id: &UId,
    ) -> Result<Vec<String>, SessionRegistryError>
    where
        UId: Display + Send + Sync,
    {
        let registry = self.get_registry().await?;
        Ok(Self::filter_by_user(&registry, user_id))
    }

    async fn get_tenant_sessions<TId>(
        &self,
        tenant_id: &TId,
    ) -> Result<Vec<String>, SessionRegistryError>
    where
        TId: Display + Send + Sync,
    {
        let registry = self.get_registry().await?;
        Ok(Self::filter_by_tenant(&registry, tenant_id))
    }

    async fn validate_session(
        &self,
        session_id: &str,
        expected_hash: &str,
    ) -> Result<bool, SessionRegistryError> {
        let registry = self.get_registry().await?;

        Ok(registry
            .iter()
            .find(|m| m.session_id == session_id)
            .map(|m| m.session_hash == expected_hash)
            .unwrap_or(false))
    }

    async fn touch_session(&self, session_id: &str) -> Result<(), SessionRegistryError> {
        let mut registry = self.get_registry().await?;

        if let Some(metadata) = registry.iter_mut().find(|m| m.session_id == session_id) {
            metadata.last_activity = Utc::now();
            self.save_registry(registry).await?;
        }

        Ok(())
    }

    async fn invalidate_session(&self, session_id: &str) -> Result<(), SessionRegistryError> {
        self.invalidate_sessions_by_ids(&[session_id.to_string()])
            .await?;
        debug!("Invalidated session: {}", session_id);
        Ok(())
    }

    async fn invalidate_user_sessions<UId>(
        &self,
        user_id: &UId,
    ) -> Result<u64, SessionRegistryError>
    where
        UId: Display + Send + Sync,
    {
        let registry = self.get_registry().await?;
        let session_ids = Self::filter_by_user(&registry, user_id);
        let count = self.invalidate_sessions_by_ids(&session_ids).await?;

        debug!("Invalidated {} sessions for user: {}", count, user_id);
        Ok(count)
    }

    async fn invalidate_tenant_sessions<TId>(
        &self,
        tenant_id: &TId,
    ) -> Result<u64, SessionRegistryError>
    where
        TId: Display + Send + Sync,
    {
        let registry = self.get_registry().await?;
        let session_ids = Self::filter_by_tenant(&registry, tenant_id);
        let count = self.invalidate_sessions_by_ids(&session_ids).await?;

        debug!("Invalidated {} sessions for tenant: {}", count, tenant_id);
        Ok(count)
    }

    async fn invalidate_all_sessions(&self) -> Result<u64, SessionRegistryError> {
        let registry = self.get_registry().await?;
        let session_ids: Vec<String> = registry
            .iter()
            .map(|metadata| metadata.session_id.clone())
            .collect();

        let count = self.invalidate_sessions_by_ids(&session_ids).await?;
        debug!("Invalidated {} sessions globally", count);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::mock_tracing::init_tracing;
    use tower_sessions::MemoryStore;

    #[tokio::test]
    /// Verifies basic session registration, lookup, and invalidation for a single user and tenant.
    async fn test_session_registry_basic_operations() -> Result<(), SessionRegistryError> {
        init_tracing();

        let store = MemoryStore::default();
        let registry = SessionRegistryStore::new(store, 0, None, None);

        let session_id = SessionId(42).to_string();

        tracing::info!("Registry ID: {:?}", registry.get_registry_id());

        // Register a session
        registry
            .register_session(
                &session_id,
                Some(&"user1"),
                Some(&"tenant1"),
                "test_hash".to_string(),
            )
            .await?;

        let user_sessions = registry.get_user_sessions(&"user1").await?;
        tracing::info!("User sessions after registration: {:?}", user_sessions);

        let tenant_sessions = registry.get_tenant_sessions(&"tenant1").await?;
        tracing::info!("Tenant sessions after registration: {:?}", tenant_sessions);

        let count = registry.invalidate_user_sessions(&"user1").await?;
        tracing::info!("Invalidated user sessions count: {}", count);

        let user_sessions_after = registry.get_user_sessions(&"user1").await?;
        tracing::info!(
            "User sessions after invalidation: {:?}",
            user_sessions_after
        );

        assert_eq!(user_sessions, vec![session_id.clone()]);
        assert_eq!(tenant_sessions, vec![session_id.clone()]);
        assert_eq!(count, 1);
        assert!(user_sessions_after.is_empty());

        Ok(())
    }

    #[tokio::test]
    /// Checks session registration and invalidation for multiple users and tenants.
    async fn test_session_registry_multiple_users() -> Result<(), SessionRegistryError> {
        init_tracing();

        let store = MemoryStore::default();
        let registry = SessionRegistryStore::new(store, 0, None, None);

        // Use deterministic, valid session IDs
        let session_id1 = SessionId(1).to_string();
        let session_id2 = SessionId(2).to_string();
        let session_id3 = SessionId(3).to_string();

        registry
            .register_session(
                &session_id1,
                Some(&"user1"),
                Some(&"tenant1"),
                "hash1".to_string(),
            )
            .await?;
        registry
            .register_session(
                &session_id2,
                Some(&"user2"),
                Some(&"tenant1"),
                "hash2".to_string(),
            )
            .await?;
        registry
            .register_session(
                &session_id3,
                Some(&"user1"),
                Some(&"tenant2"),
                "hash3".to_string(),
            )
            .await?;

        let user1_sessions = registry.get_user_sessions(&"user1").await?;
        assert_eq!(user1_sessions.len(), 2);
        assert!(user1_sessions.contains(&session_id1));
        assert!(user1_sessions.contains(&session_id3));

        let tenant1_sessions = registry.get_tenant_sessions(&"tenant1").await?;
        assert_eq!(tenant1_sessions.len(), 2);
        assert!(tenant1_sessions.contains(&session_id1));
        assert!(tenant1_sessions.contains(&session_id2));

        let count = registry.invalidate_tenant_sessions(&"tenant1").await?;
        assert_eq!(count, 2);

        let user1_sessions_after = registry.get_user_sessions(&"user1").await?;
        assert_eq!(user1_sessions_after, vec![session_id3]);

        Ok(())
    }

    #[tokio::test]
    /// Ensures duplicate registration updates session hash and does not create duplicates.
    async fn test_session_registry_duplicate_registration() -> Result<(), SessionRegistryError> {
        init_tracing();

        let store = MemoryStore::default();
        let registry = SessionRegistryStore::new(store, 0, None, None);

        let session_id = SessionId(10).to_string();

        registry
            .register_session(
                &session_id,
                Some(&"user1"),
                Some(&"tenant1"),
                "hash".to_string(),
            )
            .await?;
        registry
            .register_session(
                &session_id,
                Some(&"user1"),
                Some(&"tenant1"),
                "hash_updated".to_string(),
            )
            .await?;

        let user_sessions = registry.get_user_sessions(&"user1").await?;
        assert_eq!(user_sessions.len(), 1);
        assert_eq!(user_sessions, vec![session_id]);

        Ok(())
    }

    #[tokio::test]
    /// Validates cleanup operations: session invalidation by ID, tenant, and global.
    async fn test_session_registry_cleanup_operations() -> Result<(), SessionRegistryError> {
        init_tracing();

        let store = MemoryStore::default();
        let registry = SessionRegistryStore::new(store, 0, None, None);

        let session_id1 = SessionId(11).to_string();
        let session_id2 = SessionId(12).to_string();
        let session_id3 = SessionId(13).to_string();

        registry
            .register_session(
                &session_id1,
                Some(&"user1"),
                Some(&"tenant1"),
                "hash1".to_string(),
            )
            .await?;
        registry
            .register_session(
                &session_id2,
                Some(&"user2"),
                Some(&"tenant1"),
                "hash2".to_string(),
            )
            .await?;
        registry
            .register_session(
                &session_id3,
                Some(&"user1"),
                None::<&String>,
                "hash3".to_string(),
            )
            .await?;

        registry.invalidate_session(&session_id2).await?;
        let tenant1_sessions = registry.get_tenant_sessions(&"tenant1").await?;
        assert_eq!(tenant1_sessions.len(), 1);
        assert!(tenant1_sessions.contains(&session_id1));

        let count = registry.invalidate_all_sessions().await?;
        assert_eq!(count, 2); // session_id1 and session_id3 should be invalidated

        let user1_sessions = registry.get_user_sessions(&"user1").await?;
        assert!(user1_sessions.is_empty());

        Ok(())
    }

    #[tokio::test]
    /// Confirms registry persistence across multiple instances using the same store.
    async fn test_session_registry_persistence_across_instances() -> Result<(), SessionRegistryError>
    {
        let store = MemoryStore::default();

        let session_id = SessionId(21).to_string();

        // First registry instance
        {
            let registry = SessionRegistryStore::new(store.clone(), 0, None, None);
            registry
                .register_session(
                    &session_id,
                    Some(&"user1"),
                    Some(&"tenant1"),
                    "hash".to_string(),
                )
                .await?;
        }

        // Second registry instance using same store
        {
            let registry = SessionRegistryStore::new(store, 0, None, None);
            let user_sessions = registry.get_user_sessions(&"user1").await?;
            assert_eq!(user_sessions, vec![session_id]);
        }

        Ok(())
    }

    #[tokio::test]
    /// Tests edge cases: guest session registration, invalid session lookup, and global invalidation.
    async fn test_session_registry_edge_cases() -> Result<(), SessionRegistryError> {
        init_tracing();

        let store = MemoryStore::default();
        let registry = SessionRegistryStore::new(store, 0, None, None);

        let session_id = SessionId(99).to_string();

        registry
            .register_session(
                &session_id,
                None::<&String>,
                None::<&String>,
                "hash".to_string(),
            )
            .await?;

        let non_existent_sessions = registry.get_user_sessions(&"non_existent").await?;
        assert!(non_existent_sessions.is_empty());

        registry.invalidate_session("non_existent").await?;

        let all_sessions_count = registry.invalidate_all_sessions().await?;
        assert_eq!(all_sessions_count, 1);

        Ok(())
    }

    #[tokio::test]
    /// Verifies deterministic registry ID generation for distributed setups.
    async fn test_session_registry_deterministic_id_generation() {
        let key = SESSION_REGISTRY_KEY.to_string();
        let id1 = SessionRegistryStore::<MemoryStore>::generate_registry_id(0, key.clone());
        let id2 = SessionRegistryStore::<MemoryStore>::generate_registry_id(0, key);
        assert_eq!(id1, id2, "Registry ID generation should be deterministic");
    }
}

// #[derive(Debug, Clone)]
// pub struct SessionContext<B>
// where
//     B: AuthnBackend,
// {
//     pub state: SessionState<B>,

//     /// The user associated by the backend or a guest user.
//     pub user: B::User,

//     /// The underlying session.
//     pub session: Session,

//     data: SessionData<B>,
//     data_key: &'static str,
// }

// #[derive(thiserror::Error, Debug)]
// pub enum SessionTrackerError {
//     #[error("Session store error: {0}")]
//     StoreError(String),
//     // ...other variants...
// }

// pub trait SessionTracker: Send + Sync + 'static {
//     /// Register a session, returning a registration token that can be stored in the session
//     async fn register_session<TId, UId>(
//         &self,
//         session_id: &str,
//         user_id: Option<&UId>,
//         tenant_id: Option<&TId>
//     ) -> Result<String, SessionTrackerError>
//     where
//         TId: Display + Send + Sync,
//         UId: Display + Send + Sync;

//     // /// Validate a session registration token
//     // async fn validate_session(
//     //     &self,
//     //     session_id: &str,
//     //     token: &str
//     // ) -> Result<bool, SessionTrackerError>;

//     /// Get all session IDs for a user.
//     async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<String>, SessionTrackerError>;

//     /// Get all session IDs for a tenant.
//     async fn get_tenant_sessions(&self, tenant_id: &str) -> Result<Vec<String>, SessionTrackerError>;

//     /// Invalidate (delete) a session by ID.
//     async fn invalidate_session(&self, session_id: &str) -> Result<(), SessionTrackerError>;

//     /// Invalidate all sessions for a user.
//     async fn invalidate_user_sessions<UId>(
//         &self,
//         user_id: &UId
//     ) -> Result<u64, SessionTrackerError>
//     where
//         UId: Display + Send + Sync;

//     /// Invalidate all sessions for a tenant.
//     async fn invalidate_tenant_sessions<TId>(&self, tenant_id: &str) -> Result<(), SessionTrackerError>
//     where
//         TId: Display + Send + Sync;

//     /// Invalidate all sessions globally.
//     async fn invalidate_all_sessions(&self) -> Result<(), SessionTrackerError>;
// }
