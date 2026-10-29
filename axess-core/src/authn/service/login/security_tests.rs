//! What `begin_login`, `logout` and the account-state checks reveal and
//! permit: one answer for every way a login can fail before credentials,
//! per-session logout, and suspensions that end.

use super::super::AuthnService;
use super::*;
use crate::authn::event::AuthFailureReason;
use crate::authn::ids::{TenantId, UserId};
use crate::authn::types::{EntityState, LockoutPolicy, StatusDetail, Tenant, User};
use crate::authn::{AuditContext, RequestAuthnService};
use crate::session::data::SessionData;
use crate::session::extractor::AuthSession;
use crate::session::layer::{SessionHandle, SessionInner};
use crate::session::store::{MemorySessionRegistry, SessionRegistry};
use crate::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use std::sync::Arc;
use tokio::sync::RwLock;

fn uid() -> UserId {
    axess_identity::testing::user("u-sec")
}

fn tid() -> TenantId {
    axess_identity::testing::tenant("t-sec")
}

fn session() -> AuthSession {
    let inner = SessionInner {
        id: crate::session::id::SessionId::new(&axess_rng::SystemRng),
        data: SessionData::default(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        rng: std::sync::Arc::new(axess_rng::SystemRng),
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
        consume: None,
    };
    AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
}

fn user(status: EntityState) -> User {
    let now = chrono::Utc::now();
    User {
        id: uid(),
        tenant_id: tid(),
        identifier: "alice".into(),
        display_name: "alice".into(),
        status,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn tenant(status: EntityState) -> Tenant {
    let now = chrono::Utc::now();
    Tenant {
        id: tid(),
        identifier: "acme".into(),
        display_name: "acme".into(),
        status,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn suspended(until: Option<chrono::DateTime<chrono::Utc>>) -> EntityState {
    EntityState::Suspended(StatusDetail {
        reason: "hold".into(),
        since: chrono::Utc::now() - chrono::Duration::days(2),
        until,
    })
}

fn identity(t: EntityState, u: EntityState) -> MockIdentityStore {
    MockIdentityStore::new()
        .with_tenant(tenant(t))
        .with_user(user(u))
        .with_lockout_policy(LockoutPolicy::default())
}

fn service(identity: MockIdentityStore) -> RequestAuthnService<MockIdentityStore, MockFactorStore> {
    AuthnService::builder(identity, MockFactorStore::new())
        .build()
        .with_audit_context(AuditContext::default())
}

#[tokio::test]
async fn known_user_without_methods_answers_like_an_unknown_user() {
    let known = service(identity(EntityState::Active, EntityState::Active))
        .begin_login("alice", "acme", &session())
        .await;
    let unknown = service(identity(EntityState::Active, EntityState::Active))
        .begin_login("nobody", "acme", &session())
        .await;
    assert!(
        matches!(known, Ok(LoginOutcome::InvalidCredentials)),
        "{known:?}"
    );
    assert!(
        matches!(unknown, Ok(LoginOutcome::InvalidCredentials)),
        "{unknown:?}"
    );
}

#[tokio::test]
async fn suspended_tenant_answers_like_an_unknown_tenant() {
    let id = identity(suspended(None), EntityState::Active);
    let observer = id.clone();
    let suspended_tenant = service(id).begin_login("alice", "acme", &session()).await;
    let unknown_tenant = service(identity(EntityState::Active, EntityState::Active))
        .begin_login("alice", "no-such-tenant", &session())
        .await;
    assert!(
        matches!(suspended_tenant, Ok(LoginOutcome::InvalidCredentials)),
        "{suspended_tenant:?}"
    );
    assert!(
        matches!(unknown_tenant, Ok(LoginOutcome::InvalidCredentials)),
        "{unknown_tenant:?}"
    );
    assert_eq!(
        observer.events().last().and_then(|e| e.error.clone()),
        Some(AuthFailureReason::NotActive),
        "the audit row keeps the real reason"
    );
}

#[tokio::test]
async fn an_ended_suspension_no_longer_blocks_login() {
    let past = chrono::Utc::now() - chrono::Duration::minutes(1);
    let id = identity(EntityState::Active, suspended(Some(past)));
    let observer = id.clone();
    let outcome = service(id).begin_login("alice", "acme", &session()).await;
    // It gets past the status gate to the no-methods gate, which has no
    // methods configured in this fixture.
    assert!(
        matches!(outcome, Ok(LoginOutcome::InvalidCredentials)),
        "{outcome:?}"
    );
    assert_eq!(
        observer.events().last().and_then(|e| e.error.clone()),
        Some(AuthFailureReason::NoFactorsConfigured)
    );
}

#[tokio::test]
async fn a_running_suspension_still_blocks_login() {
    let future = chrono::Utc::now() + chrono::Duration::hours(1);
    let outcome = service(identity(EntityState::Active, suspended(Some(future))))
        .begin_login("alice", "acme", &session())
        .await;
    assert!(
        matches!(outcome, Ok(LoginOutcome::Locked { .. })),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn logout_ends_this_session_and_leaves_the_users_others() {
    let registry = MemorySessionRegistry::new();
    let here = session();
    let elsewhere = session();
    for s in [&here, &elsewhere] {
        s.set_authenticated(uid(), tid(), chrono::Utc::now()).await;
        registry
            .register(&uid(), &s.session_id().await)
            .await
            .unwrap();
    }
    let svc = AuthnService::builder(
        identity(EntityState::Active, EntityState::Active),
        MockFactorStore::new(),
    )
    .with_registry(registry.clone())
    .build()
    .with_audit_context(AuditContext::default());

    let here_sid = here.session_id().await;
    let elsewhere_sid = elsewhere.session_id().await;
    svc.logout(&here).await.unwrap();

    assert!(!registry.is_valid(&uid(), &here_sid).await.unwrap());
    assert!(
        registry.is_valid(&uid(), &elsewhere_sid).await.unwrap(),
        "logging out here must not sign the user out of their other devices"
    );
}

/// A failing audit write must not leave the session authenticated: logout
/// reports the store error and the session is cleared and its id rotated.
#[tokio::test]
async fn logout_clears_the_session_even_when_the_audit_write_fails() {
    let registry = MemorySessionRegistry::new();
    let here = session();
    here.set_authenticated(uid(), tid(), chrono::Utc::now())
        .await;
    registry
        .register(&uid(), &here.session_id().await)
        .await
        .unwrap();
    let id = identity(EntityState::Active, EntityState::Active);
    id.arm_record_event_failure();
    let svc = AuthnService::builder(id, MockFactorStore::new())
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());

    let before = here.session_id().await;
    let result = svc.logout(&here).await;

    assert!(
        matches!(result, Err(crate::authn::error::AuthnError::Store(_))),
        "the audit failure is still reported: {result:?}"
    );
    assert!(
        !here.is_authenticated().await,
        "the session must be signed out whatever the audit store did"
    );
    assert_ne!(here.session_id().await, before, "the id is rotated");
    assert!(!registry.is_valid(&uid(), &before).await.unwrap());
}

/// An app-level rotation keeps the registry entry in step with the id.
#[tokio::test]
async fn rotate_session_moves_the_registry_entry_to_the_new_id() {
    let registry = MemorySessionRegistry::new();
    let here = session();
    here.set_authenticated(uid(), tid(), chrono::Utc::now())
        .await;
    let old = here.session_id().await;
    registry.register(&uid(), &old).await.unwrap();
    let svc = AuthnService::builder(
        identity(EntityState::Active, EntityState::Active),
        MockFactorStore::new(),
    )
    .with_registry(registry.clone())
    .build()
    .with_audit_context(AuditContext::default());

    svc.rotate_session(&here).await.unwrap();

    let new = here.session_id().await;
    assert_ne!(old, new);
    assert!(registry.is_valid(&uid(), &new).await.unwrap());
    assert!(!registry.is_valid(&uid(), &old).await.unwrap());
    assert!(here.is_authenticated().await);
}
