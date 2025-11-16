use crate::{
    authn::{
        backend::admin::AuthnAdminBackend,
        errors::AuthError,
        methods::{
            MethodBuilder,
            factor::{AuthFactorKind, FactorInstance},
        },
        session::{AuthSession, registry::SessionRegistryStore},
        types::{AuthFactor, AuthFactorState, AuthMethod, AuthMethodState},
    },
    utils::{
        // random::SystemRng,
        testing::{mock_backend::MockBackend, mock_entities::TestUserId, mock_random::MockRng},
    },
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

// pub type MockSession = AuthSession<MockBackend, SessionRegistryStore<MemoryStore>, SystemRng>;

pub fn mock_method() -> AuthMethod<MockBackend> {
    let creator = TestUserId("method_creator".into());

    let password_factor = FactorInstance::new(
        "password-factor".to_string(),
        AuthFactorKind::Password,
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
        .upsert_auth_method(method.clone())
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
        .upsert_auth_method(method.clone())
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
