//! Integration tests for the signup, activation, and suspension flows.

use axess_core::{
    authn::{
        error::AuthnError,
        event::AuthEventType,
        service::{AuthnService, SignupOutcome},
        store::IdentityStore,
        types::{EntityState, StatusDetail, Tenant, User},
    },
    session::data::AuthState,
    utils::testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    },
};
use chrono::Utc;

// ── Test helpers ─────────────────────────────────────────────────────────────

fn test_tenant() -> Tenant {
    Tenant {
        id: "t1".into(),
        identifier: "default".into(),
        display_name: "Test Tenant".into(),
        status: EntityState::Active,
    }
}

fn candidate_user(id: &str, identifier: &str) -> User {
    User {
        id: id.into(),
        tenant_id: "t1".into(),
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Candidate,
        webauthn_id: None,
    }
}

fn make_service() -> AuthnService<MockIdentityStore, MockFactorStore> {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let factors = MockFactorStore::new();
    AuthnService::new(identity, factors)
}

// ── Signup flow tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn begin_signup_creates_user_and_sets_pending_workflow() {
    let service = make_service();
    let session = test_session();

    let user = candidate_user("u1", "alice@example.com");
    let outcome = service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();

    assert!(matches!(outcome, SignupOutcome::Started));

    // Session should be in PendingWorkflow(Signup).
    let state = session.auth_state().await;
    assert!(matches!(
        state,
        AuthState::PendingWorkflow { ref workflow, .. }
        if workflow.kind == axess_core::session::data::WorkflowKind::Signup
    ));

    // User ID should be set on the session.
    assert_eq!(session.user_id().await.unwrap().as_ref(), "u1");
}

#[tokio::test]
async fn begin_signup_duplicate_returns_already_exists() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(candidate_user("u1", "alice@example.com"));
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors);
    let session = test_session();

    let user = candidate_user("u2", "alice@example.com");
    let outcome = service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();

    assert!(matches!(outcome, SignupOutcome::AlreadyExists));
    // Session should still be Guest.
    assert!(session.auth_state().await.is_guest());
}

#[tokio::test]
async fn begin_signup_bad_tenant_returns_tenant_not_active() {
    // No tenants registered.
    let identity = MockIdentityStore::new();
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors);
    let session = test_session();

    let user = candidate_user("u1", "alice@example.com");
    let outcome = service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();

    assert!(matches!(outcome, SignupOutcome::TenantNotActive));
}

#[tokio::test]
async fn complete_signup_activates_user_and_authenticates() {
    let service = make_service();
    let session = test_session();

    // Begin signup.
    let user = candidate_user("u1", "alice@example.com");
    service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();

    // Complete signup — should activate user and authenticate session.
    service.complete_signup(&session).await.unwrap();

    assert!(session.is_authenticated().await);
    assert_eq!(session.user_id().await.unwrap().as_ref(), "u1");
}

#[tokio::test]
async fn complete_signup_without_pending_workflow_returns_no_flow() {
    let service = make_service();
    let session = test_session();

    // Session is Guest — no PendingWorkflow.
    let result = service.complete_signup(&session).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn signup_records_audit_events() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity.clone(), factors);
    let session = test_session();

    let user = candidate_user("u1", "alice@example.com");
    service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();
    service.complete_signup(&session).await.unwrap();

    let events = identity.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, AuthEventType::SignupStarted);
    assert_eq!(events[1].event_type, AuthEventType::SignupCompleted);
}

// ── Suspend / activate tests ─────────────────────────────────────────────────

#[tokio::test]
async fn suspend_user_changes_status() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(User {
            id: "u1".into(),
            tenant_id: "t1".into(),
            identifier: "alice".into(),
            display_name: "Alice".into(),
            status: EntityState::Active,
            webauthn_id: None,
        });
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity.clone(), factors);

    let detail = StatusDetail {
        reason: "policy violation".into(),
        since: Utc::now(),
        until: None,
    };
    service.suspend_user("u1", detail).await.unwrap();

    // User should now be suspended.
    let status = identity.account_status("u1").await.unwrap();
    assert!(status.is_locked());

    // Audit event should be recorded.
    let events = identity.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, AuthEventType::AccountSuspended);
}

#[tokio::test]
async fn activate_user_changes_status() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(User {
            id: "u1".into(),
            tenant_id: "t1".into(),
            identifier: "alice".into(),
            display_name: "Alice".into(),
            status: EntityState::Candidate,
            webauthn_id: None,
        });
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity.clone(), factors);

    service.activate_user("u1").await.unwrap();

    let status = identity.account_status("u1").await.unwrap();
    assert!(status.is_active());

    let events = identity.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, AuthEventType::AccountActivated);
}

#[tokio::test]
async fn suspend_then_reactivate() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(User {
            id: "u1".into(),
            tenant_id: "t1".into(),
            identifier: "alice".into(),
            display_name: "Alice".into(),
            status: EntityState::Active,
            webauthn_id: None,
        });
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity.clone(), factors);

    // Suspend.
    let detail = StatusDetail {
        reason: "investigation".into(),
        since: Utc::now(),
        until: None,
    };
    service.suspend_user("u1", detail).await.unwrap();
    assert!(identity.account_status("u1").await.unwrap().is_locked());

    // Reactivate.
    service.activate_user("u1").await.unwrap();
    assert!(identity.account_status("u1").await.unwrap().is_active());
}

// ── Input validation tests ───────────────────────────────────────────────────

#[tokio::test]
async fn signup_rejects_oversized_identifier() {
    let service = make_service();
    let session = test_session();

    let user = User {
        id: "u1".into(),
        tenant_id: "t1".into(),
        identifier: "a".repeat(300).into(), // > MAX_IDENTIFIER_BYTES (256)
        display_name: "Alice".into(),
        status: EntityState::Candidate,
        webauthn_id: None,
    };
    let result = service.begin_signup(user, "default", &session).await;
    assert!(matches!(result, Err(AuthnError::InvalidAssertion)));
}

#[tokio::test]
async fn signup_rejects_control_chars_in_display_name() {
    let service = make_service();
    let session = test_session();

    let user = User {
        id: "u1".into(),
        tenant_id: "t1".into(),
        identifier: "alice@example.com".into(),
        display_name: "Alice\x00Evil".into(), // null byte
        status: EntityState::Candidate,
        webauthn_id: None,
    };
    let result = service.begin_signup(user, "default", &session).await;
    assert!(matches!(result, Err(AuthnError::InvalidAssertion)));
}
