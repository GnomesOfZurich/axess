use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display};
use thiserror::Error;
use time;
use tower_sessions::session_store::SessionStore;
use tracing::{debug, error};

// TODO: turn both these consts into application configuration parameters!
//    the registry key can be a constant as the hashing of this can use different seeds
//    for different applications, i.e. allowing for split per tenant or per application
//
const SESSION_REGISTRY_KEY: &str = "_axess_session_registry";
const SESSION_EXPIRY_DURATION: time::Duration = time::Duration::days(365);

#[derive(Debug, Error)]
pub enum SessionRegistryError {
    #[error("Session store error: {0}")]
    StoreError(#[from] tower_sessions::session_store::Error),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Metadata about a registered session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub session_id: String, // Consider changing to tower_sessions::session::Id
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub session_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

/// Registry for tracking and managing sessions across users and tenants
#[async_trait]
pub trait SessionRegistry: Send + Sync + 'static {
    /// Register a session for a user and tenant
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

    /// Get all session IDs for a user
    async fn get_user_sessions<UId>(
        &self,
        user_id: &UId,
    ) -> Result<Vec<String>, SessionRegistryError>
    where
        UId: Display + Send + Sync;

    /// Get all session IDs for a tenant
    async fn get_tenant_sessions<TId>(
        &self,
        tenant_id: &TId,
    ) -> Result<Vec<String>, SessionRegistryError>
    where
        TId: Display + Send + Sync;

    /// Validate that a session is registered with the correct hash
    async fn validate_session(
        &self,
        session_id: &str,
        expected_hash: &str,
    ) -> Result<bool, SessionRegistryError>;

    /// Update last activity timestamp
    async fn touch_session(&self, session_id: &str) -> Result<(), SessionRegistryError>;

    /// Invalidate a specific session
    async fn invalidate_session(&self, session_id: &str) -> Result<(), SessionRegistryError>;

    /// Invalidate all sessions for a user
    async fn invalidate_user_sessions<UId>(
        &self,
        user_id: &UId,
    ) -> Result<u64, SessionRegistryError>
    where
        UId: Display + Send + Sync;

    /// Invalidate all sessions for a tenant
    async fn invalidate_tenant_sessions<TId>(
        &self,
        tenant_id: &TId,
    ) -> Result<u64, SessionRegistryError>
    where
        TId: Display + Send + Sync;

    /// Invalidate all sessions globally
    async fn invalidate_all_sessions(&self) -> Result<u64, SessionRegistryError>;
}

/// Session registry implementation that uses a single registry with session metadata
#[derive(Debug, Clone)]
pub struct StoreSessionRegistry<S: SessionStore> {
    store: S,
    registry_id: tower_sessions::session::Id,
    // registry_id_seed is only used at construction, not stored or logged
}

impl<S: SessionStore> StoreSessionRegistry<S> {
    // TODO: make this into an application configuration parameter
    const REGISTRY_KEY: &'static str = SESSION_REGISTRY_KEY;

    pub fn new(store: S, registry_id_seed: u128) -> Self {
        let registry_id = Self::generate_registry_id(registry_id_seed);
        Self { store, registry_id }
    }

    fn generate_registry_id(seed: u128) -> tower_sessions::session::Id {
        use std::hash::{Hash, Hasher};

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

        let mut hasher = FnvHasher(seed);
        SESSION_REGISTRY_KEY.hash(&mut hasher);
        let hash = hasher.0;

        tower_sessions::session::Id(hash as i128)
    }

    fn get_registry_id(&self) -> &tower_sessions::session::Id {
        &self.registry_id
    }

    /// Get the full session registry
    async fn get_registry(&self) -> Result<Vec<SessionMetadata>, SessionRegistryError> {
        let registry_id = self.get_registry_id();

        tracing::debug!("Loading registry with ID: {registry_id:?}");
        if let Some(record) = self.store.load(registry_id).await? {
            tracing::debug!("Loaded registry record: {record:?}");
            let registry: Vec<SessionMetadata> = record
                .data
                .get(Self::REGISTRY_KEY)
                .and_then(|v| serde_json::from_value(v.clone()).ok())
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
                expiry_date: time::OffsetDateTime::now_utc() + SESSION_EXPIRY_DURATION,
            }
        });

        // Store the registry data
        let registry_value = serde_json::to_value(registry).map_err(|e| {
            error!("Failed to serialize session registry: {e}");
            SessionRegistryError::SerializationError(e.to_string())
        })?;

        record
            .data
            .insert(Self::REGISTRY_KEY.to_string(), registry_value);

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
            if let Ok(session_id_obj) = session_id.parse::<tower_sessions::session::Id>() {
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
impl<S: SessionStore + Send + Sync> SessionRegistry for StoreSessionRegistry<S> {
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
        // Defensive: Only allow valid session IDs
        if session_id.parse::<tower_sessions::session::Id>().is_err() {
            error!("Attempted to register invalid session ID: {session_id}");
            return Err(SessionRegistryError::SerializationError(format!(
                "Invalid session ID format: {session_id}"
            )));
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

    use std::sync::Once;
    use tower_sessions::MemoryStore;
    use tracing_subscriber;

    static INIT: Once = Once::new();

    fn init_tracing() {
        INIT.call_once(|| {
            // Use tracing-subscriber for test output
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .with_test_writer()
                .try_init();
        });
    }

    #[tokio::test]
    async fn test_session_registry_basic_operations() {
        init_tracing();

        let store = MemoryStore::default();
        let registry = StoreSessionRegistry::new(store, 0);

        let session_id = tower_sessions::session::Id(42).to_string();

        tracing::info!("Registry ID: {:?}", registry.get_registry_id());

        // Register a session
        registry
            .register_session(
                &session_id,
                Some(&"user1"),
                Some(&"tenant1"),
                "test_hash".to_string(),
            )
            .await
            .unwrap();

        let user_sessions = registry.get_user_sessions(&"user1").await.unwrap();
        tracing::info!("User sessions after registration: {:?}", user_sessions);

        let tenant_sessions = registry.get_tenant_sessions(&"tenant1").await.unwrap();
        tracing::info!("Tenant sessions after registration: {:?}", tenant_sessions);

        let count = registry.invalidate_user_sessions(&"user1").await.unwrap();
        tracing::info!("Invalidated user sessions count: {}", count);

        let user_sessions_after = registry.get_user_sessions(&"user1").await.unwrap();
        tracing::info!(
            "User sessions after invalidation: {:?}",
            user_sessions_after
        );

        assert_eq!(user_sessions, vec![session_id.clone()]);
        assert_eq!(tenant_sessions, vec![session_id.clone()]);
        assert_eq!(count, 1);
        assert!(user_sessions_after.is_empty());
    }

    #[tokio::test]
    async fn test_session_registry_multiple_users() {
        init_tracing();

        let store = MemoryStore::default();
        let registry = StoreSessionRegistry::new(store, 0);

        // Use deterministic, valid session IDs
        let session_id1 = tower_sessions::session::Id(1).to_string();
        let session_id2 = tower_sessions::session::Id(2).to_string();
        let session_id3 = tower_sessions::session::Id(3).to_string();

        registry
            .register_session(
                &session_id1,
                Some(&"user1"),
                Some(&"tenant1"),
                "hash1".to_string(),
            )
            .await
            .unwrap();
        registry
            .register_session(
                &session_id2,
                Some(&"user2"),
                Some(&"tenant1"),
                "hash2".to_string(),
            )
            .await
            .unwrap();
        registry
            .register_session(
                &session_id3,
                Some(&"user1"),
                Some(&"tenant2"),
                "hash3".to_string(),
            )
            .await
            .unwrap();

        let user1_sessions = registry.get_user_sessions(&"user1").await.unwrap();
        assert_eq!(user1_sessions.len(), 2);
        assert!(user1_sessions.contains(&session_id1));
        assert!(user1_sessions.contains(&session_id3));

        let tenant1_sessions = registry.get_tenant_sessions(&"tenant1").await.unwrap();
        assert_eq!(tenant1_sessions.len(), 2);
        assert!(tenant1_sessions.contains(&session_id1));
        assert!(tenant1_sessions.contains(&session_id2));

        let count = registry
            .invalidate_tenant_sessions(&"tenant1")
            .await
            .unwrap();
        assert_eq!(count, 2);

        let user1_sessions_after = registry.get_user_sessions(&"user1").await.unwrap();
        assert_eq!(user1_sessions_after, vec![session_id3]);
    }

    #[tokio::test]
    async fn test_session_registry_duplicate_registration() {
        init_tracing();

        let store = MemoryStore::default();
        let registry = StoreSessionRegistry::new(store, 0);

        let session_id = tower_sessions::session::Id(10).to_string();

        registry
            .register_session(
                &session_id,
                Some(&"user1"),
                Some(&"tenant1"),
                "hash".to_string(),
            )
            .await
            .unwrap();
        registry
            .register_session(
                &session_id,
                Some(&"user1"),
                Some(&"tenant1"),
                "hash_updated".to_string(),
            )
            .await
            .unwrap();

        let user_sessions = registry.get_user_sessions(&"user1").await.unwrap();
        assert_eq!(user_sessions.len(), 1);
        assert_eq!(user_sessions, vec![session_id]);
    }

    #[tokio::test]
    async fn test_session_registry_cleanup_operations() {
        init_tracing();

        let store = MemoryStore::default();
        let registry = StoreSessionRegistry::new(store, 0);

        let session_id1 = tower_sessions::session::Id(11).to_string();
        let session_id2 = tower_sessions::session::Id(12).to_string();
        let session_id3 = tower_sessions::session::Id(13).to_string();

        registry
            .register_session(
                &session_id1,
                Some(&"user1"),
                Some(&"tenant1"),
                "hash1".to_string(),
            )
            .await
            .unwrap();
        registry
            .register_session(
                &session_id2,
                Some(&"user2"),
                Some(&"tenant1"),
                "hash2".to_string(),
            )
            .await
            .unwrap();
        registry
            .register_session(
                &session_id3,
                Some(&"user1"),
                None::<&String>,
                "hash3".to_string(),
            )
            .await
            .unwrap();

        registry.invalidate_session(&session_id2).await.unwrap();
        let tenant1_sessions = registry.get_tenant_sessions(&"tenant1").await.unwrap();
        assert_eq!(tenant1_sessions.len(), 1);
        assert!(tenant1_sessions.contains(&session_id1));

        let count = registry.invalidate_all_sessions().await.unwrap();
        assert_eq!(count, 2); // session_id1 and session_id3 should be invalidated

        let user1_sessions = registry.get_user_sessions(&"user1").await.unwrap();
        assert!(user1_sessions.is_empty());
    }

    #[tokio::test]
    async fn test_session_registry_persistence_across_instances() {
        let store = MemoryStore::default();

        let session_id = tower_sessions::session::Id(21).to_string();

        // First registry instance
        {
            let registry = StoreSessionRegistry::new(store.clone(), 0);
            registry
                .register_session(
                    &session_id,
                    Some(&"user1"),
                    Some(&"tenant1"),
                    "hash".to_string(),
                )
                .await
                .unwrap();
        }

        // Second registry instance using same store
        {
            let registry = StoreSessionRegistry::new(store, 0);
            let user_sessions = registry.get_user_sessions(&"user1").await.unwrap();
            assert_eq!(user_sessions, vec![session_id]);
        }
    }

    #[tokio::test]
    async fn test_session_registry_edge_cases() {
        init_tracing();

        let store = MemoryStore::default();
        let registry = StoreSessionRegistry::new(store, 0);

        let session_id = tower_sessions::session::Id(99).to_string();

        registry
            .register_session(
                &session_id,
                None::<&String>,
                None::<&String>,
                "hash".to_string(),
            )
            .await
            .unwrap();

        let non_existent_sessions = registry.get_user_sessions(&"non_existent").await.unwrap();
        assert!(non_existent_sessions.is_empty());

        registry.invalidate_session("non_existent").await.unwrap();

        let all_sessions_count = registry.invalidate_all_sessions().await.unwrap();
        assert_eq!(all_sessions_count, 1);
    }

    #[tokio::test]
    async fn test_session_registry_deterministic_id_generation() {
        let id1 = StoreSessionRegistry::<MemoryStore>::generate_registry_id(0);
        let id2 = StoreSessionRegistry::<MemoryStore>::generate_registry_id(0);
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
