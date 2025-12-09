//! Mock authentication helpers for Axess unit and integration tests.
//!
//! This module provides convenient utilities for constructing mock authentication methods,
//! factors, sessions, and session registries for testing Axess flows. It is designed to
//! facilitate deterministic simulation testing (DST), backend contract validation, and
//! realistic session initialization without requiring a real database or external dependencies.
//!
//! # Features
//! - [`mock_method`]: Quickly create a password-only mock authentication method.
//! - [`create_initialized_session`]: Initialize a session in a memory store for session-based tests.
//! - [`create_test_session`]: Create a fully initialized [`AuthSession`] and registry for backend/session tests.
//! - [`create_test_session_with_custom_rng`]: Same as above, but allows specifying a custom RNG for DST.
//!
//! # Usage
//! ```rust
//! use axess_core::utils::testing::mock_authn::{create_test_session, mock_method};
//!
//! #[tokio::test]
//! async fn test_auth_session_initialization() {
//!     let (session, registry) = create_test_session().await.unwrap();
//!     assert!(session.get_user_id().is_none());
//!     // Use session and registry for further authentication flow tests...
//! }
//! ```
//!
//! See also: [`mock_backend`](mock_backend.rs), [`mock_entities`](mock_entities.rs), [`mock_form`](mock_form.rs)

use crate::{
    authn::{
        backend::admin::AuthnAdminBackend,
        errors::AuthError,
        methods::{
            MethodBuilder,
            factor::{FactorInstance, Kind},
        },
        session::{AuthSession, registry::SessionRegistryStore},
        types::{AuthFactor, AuthFactorState, AuthMethod, AuthMethodState},
    },
    utils::testing::{mock_backend::MockBackend, mock_entities::TestUserId, mock_random::MockRng},
};
use std::sync::Arc;
use tower_sessions::{
    MemoryStore, Session, SessionStore,
    session::{Id, Record},
};

pub type MockAuthFactor = AuthFactor<MockBackend>;
pub type MockAuthFactorState = AuthFactorState<MockBackend>;
pub type MockAuthMethod = AuthMethod<MockBackend>;
pub type MockAuthMethodState = AuthMethodState<MockBackend>;

pub fn mock_method() -> AuthMethod<MockBackend> {
    let creator = TestUserId("method_creator".into());

    let password_factor = FactorInstance::new(
        "password-factor".to_string(),
        Kind::Password,
        "Password",
        "Mock password factor",
        creator.clone(),
    );

    MethodBuilder::new(
        "password-method".to_string(),
        "Password Only",
        "Password based authentication",
        creator,
    )
    .add_factor(password_factor)
    .build()
}

/// Helper to create a session that's properly initialized in the store
pub async fn create_initialized_session(store: MemoryStore) -> Session {
    // Bring the SessionStore trait into scope so its async methods are available.

    // Generate a new session ID
    let session_id = Id::default();

    // Create a record with the ID and empty data (mutable because create expects &mut Record)
    let mut record = Record {
        id: session_id.clone(),
        data: Default::default(),
        expiry_date: time::OffsetDateTime::now_utc() + time::Duration::hours(24),
    };

    // Save the record to the store (pass a mutable reference)
    store
        .create(&mut record)
        .await
        .expect("Failed to create session record in store");

    // Create Session with this ID - it will be able to load from store
    Session::new(Some(session_id), std::sync::Arc::new(store), None)
}

pub async fn create_test_session() -> Result<
    (
        AuthSession<MockBackend, SessionRegistryStore<MemoryStore>, MockRng>,
        Arc<SessionRegistryStore<MemoryStore>>,
    ),
    AuthError<MockBackend>,
> {
    let backend = Arc::new(MockBackend::default());
    let store = MemoryStore::default();

    // Create and initialize session (pass a cloned MemoryStore value)
    let session = create_initialized_session(store.clone()).await;

    let registry = Arc::new(SessionRegistryStore::new(store, 0, None, None));

    // Configure backend with test method
    let method = mock_method();
    backend
        .upsert_auth_method(method.clone(), TestUserId("method_creator".into()))
        .await
        .map_err(AuthError::BackendError)?;

    let rng = MockRng::new(42);
    let auth_session = AuthSession::from_session_with_rng(
        session,
        backend.clone(),
        "test.data",
        Some(registry.clone()),
        rng,
    )
    .await?;

    Ok((auth_session, registry))
}

/// Helper to create a test session with a custom RNG
pub async fn create_test_session_with_custom_rng(
    rng: MockRng,
) -> Result<
    (
        AuthSession<MockBackend, SessionRegistryStore<MemoryStore>, MockRng>,
        Arc<SessionRegistryStore<MemoryStore>>,
    ),
    AuthError<MockBackend>,
> {
    let backend = Arc::new(MockBackend::default());
    let store = MemoryStore::default();

    // Create and initialize session (pass a cloned MemoryStore value)
    let session = create_initialized_session(store.clone()).await;

    let registry = Arc::new(SessionRegistryStore::new(store, 0, None, None));

    // Configure backend with test method
    let method = mock_method();
    backend
        .upsert_auth_method(method.clone(), TestUserId("method_creator".into()))
        .await
        .map_err(AuthError::BackendError)?;

    let auth_session = AuthSession::from_session_with_rng(
        session,
        backend.clone(),
        "test.data",
        Some(registry.clone()),
        rng,
    )
    .await?;

    Ok((auth_session, registry))
}
