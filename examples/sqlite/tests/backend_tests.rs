use axess::{
    AuthEventRecord, AuthEventStatus, AuthEventType, AuthFactorKind, AuthnAdminBackend,
    AuthnBackend, EnablementState, EntityState, FactorStateChange, MethodInstance, PermissionScope,
    StatusDetail, form::PasswordForm,
};

// Include the example crate's models into this integration test crate so we can refer to
// backend::OurBackend and entities::{OurUser, OurTenant} here.
mod models {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/models/mod.rs"));
}
use self::models::{backend::OurBackend, entities::OurUser};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

async fn create_test_pool() -> SqlitePool {
    // in-memory DB used by tests (isolated)
    let pool = SqlitePool::connect(":memory:")
        .await
        .expect("connect sqlite");
    // run migrations located at examples/sqlite/migrations (path relative to test crate)
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations"
    )))
    .await
    .expect("load migrations");
    migrator.run(&pool).await.expect("apply migrations");

    pool
}

async fn create_test_backend() -> OurBackend {
    let pool = create_test_pool().await;

    OurBackend::new(pool)
}

#[tokio::test]
async fn test_get_auth_method_returns_method()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let backend = create_test_backend().await;

    // Create a test method
    let method_id = Uuid::new_v4();
    let system_user_id = backend.get_system_user_id(None).await?;

    let method: MethodInstance<Uuid, Uuid, Uuid> = MethodInstance {
        id: method_id,
        name: "Test Password Method".to_string(),
        description: "Test method for password authentication".to_string(),
        factors: vec![],
        created_at: Utc::now(),
        created_by: system_user_id.clone(),
        updated_at: Utc::now(),
        updated_by: system_user_id,
    };

    backend
        .upsert_auth_method(method.clone().into(), system_user_id)
        .await?;

    // Test retrieval
    let retrieved = backend.get_auth_method(&method_id).await?;
    assert_eq!(retrieved.id, method_id);
    assert_eq!(retrieved.name, "Test Password Method");

    Ok(())
}
#[tokio::test]
async fn test_authenticate_with_inactive_user_returns_error()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let backend = create_test_backend().await;

    // Get default tenant
    let tenant_id = backend.get_default_tenant_id().await?;
    let system_user_id = backend.get_system_user_id(None).await?;

    // Create a suspended user
    let user_id = Uuid::new_v4();
    let suspended_user = OurUser {
        id: user_id,
        tenant_id,
        username: "suspended_user".to_string(),
        fullname: "Suspended User".to_string(),
        email: "suspended@example.com".to_string(),
        state: EntityState::Suspended(StatusDetail {
            reason: "Test suspension".to_string(),
            timestamp: Utc::now(),
            until: None,
            metadata: None,
        }),
        created_at: Utc::now(),
        created_by: system_user_id.clone(),
        updated_at: Utc::now(),
        updated_by: system_user_id,
    };

    backend.upsert_user(suspended_user, system_user_id).await?;

    // Verify user exists but is not active
    let fetched = backend.get_user(&user_id).await?;
    assert!(!matches!(fetched.state, EntityState::Active));

    // Try to authenticate - should fail
    let form = PasswordForm {
        username: "suspended_user".to_string(),
        password: "password123".to_string(),
        tenant: Some(tenant_id.to_string()),
        next: None,
    };

    let result = backend.authenticate(&form).await;
    assert!(result.is_err());

    Ok(())
}
#[tokio::test]
async fn test_record_and_retrieve_auth_event_roundtrip()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let backend = create_test_backend().await;

    let tenant_id = backend.get_default_tenant_id().await?;
    let system_user_id = backend.get_system_user_id(None).await?;

    // Record an auth event
    let event: AuthEventRecord<'_, OurBackend> = AuthEventRecord::<OurBackend> {
        user_id: &system_user_id,
        tenant_id: &tenant_id,
        session_id: Some("session123"),
        event_type: AuthEventType::LoginAttempt,
        event_status: AuthEventStatus::Success,
        method_id: None,
        factor_id: None,
        factor_kind: None,
        ip_address: Some("192.168.1.1"),
        user_agent: Some("Mozilla/5.0 Test Agent"),
        error_message: None,
    };

    backend.record_auth_event(event).await?;

    // Retrieve events
    let events = backend
        .get_auth_history(
            &system_user_id,
            Some(AuthEventType::LoginAttempt),
            Some(AuthEventStatus::Success),
            Some(10),
        )
        .await?;

    assert!(!events.is_empty());
    assert_eq!(events[0].event_type, AuthEventType::LoginAttempt);
    assert_eq!(events[0].event_status, AuthEventStatus::Success);
    assert_eq!(events[0].session_id, Some("session123".to_string()));
    assert_eq!(events[0].ip_address, Some("192.168.1.1".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_get_scoped_auth_factors() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let backend = create_test_backend().await;

    let tenant_id = backend.get_default_tenant_id().await?;
    let system_user_id = backend.get_system_user_id(None).await?;

    // Get global factors
    let global_factors = backend
        .get_scoped_auth_factors(PermissionScope::Global, vec![EnablementState::Active])
        .await?;

    // Should have at least the password factor from migrations
    assert!(!global_factors.is_empty());

    // Get user-specific factors
    let user_scope = PermissionScope::User(tenant_id, system_user_id);
    let user_factors = backend
        .get_scoped_auth_factors(user_scope, vec![EnablementState::Active])
        .await?;

    // User may inherit global factors or have specific ones
    assert!(!user_factors.is_empty());

    Ok(())
}
#[tokio::test]
async fn test_get_scoped_auth_factors_with_empty_state_filter()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let backend = create_test_backend().await;

    let tenant_id = backend.get_default_tenant_id().await?;
    let system_user_id = backend.get_system_user_id(None).await?;

    // Get all global factors, regardless of state
    let global_factors = backend
        .get_scoped_auth_factors(PermissionScope::Global, vec![])
        .await?;
    assert!(
        !global_factors.is_empty(),
        "Should return all global factors when state filter is empty"
    );

    // Get all user-scoped factors, regardless of state
    let user_scope = PermissionScope::User(tenant_id, system_user_id);
    let user_factors = backend.get_scoped_auth_factors(user_scope, vec![]).await?;
    assert!(
        !user_factors.is_empty(),
        "Should return all user factors when state filter is empty"
    );

    // Get all tenant-scoped factors, regardless of state
    let tenant_scope = PermissionScope::Tenant(tenant_id);
    let tenant_factors = backend
        .get_scoped_auth_factors(tenant_scope, vec![])
        .await?;
    assert!(
        !tenant_factors.is_empty(),
        "Should return all tenant factors when state filter is empty"
    );

    // Get all factors with PermissionScope::Any, regardless of state
    let any_factors = backend
        .get_scoped_auth_factors(PermissionScope::Any, vec![])
        .await?;
    assert!(
        !any_factors.is_empty(),
        "Should return all factors when state filter is empty"
    );

    Ok(())
}

#[tokio::test]
async fn test_upsert_factor_state_roundtrip() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let backend = create_test_backend().await;

    let tenant_id = backend.get_default_tenant_id().await?;
    let system_user_id = backend.get_system_user_id(None).await?;

    // Get a password factor
    let factors = backend.get_all_auth_factors().await?;
    let password_factor = factors
        .iter()
        .find(|f| matches!(f.kind, AuthFactorKind::Password))
        .ok_or_else(|| {
            Box::<dyn std::error::Error + Send + Sync>::from(
                "Should have password factor from migrations",
            )
        })?;

    // Create a factor state change
    let mut config = std::collections::HashMap::new();
    config.insert(
        "password_hash".to_string(),
        serde_json::Value::String("$argon2id$v=19$m=19456,t=2,p=1$test".to_string()),
    );

    let change = FactorStateChange {
        factor_id: password_factor.id,
        tenant_id: Some(tenant_id),
        user_id: Some(system_user_id.clone()),
        state: EnablementState::Active,
        config,
    };

    // Upsert the factor state
    let upserted = backend.upsert_factor_state(change, system_user_id).await?;

    assert_eq!(upserted.factor_id, password_factor.id);
    assert!(upserted.config.contains_key("password_hash"));

    // Retrieve it back
    let scope = PermissionScope::User(tenant_id, system_user_id.clone());
    let states = backend
        .get_factor_states(&password_factor.id, scope)
        .await?;

    assert_eq!(states.len(), 1);
    assert_eq!(states[0].factor_id, password_factor.id);

    Ok(())
}
