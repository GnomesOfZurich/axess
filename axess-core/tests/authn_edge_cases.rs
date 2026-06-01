#![cfg(feature = "testing")]
//! AuthnService edge cases: empty factor chains, missing flows,
//! suspended users, unknown tenants, and bare ZeroizedString / AuthnScope
//! invariants that don't fit elsewhere.

mod common;

use axess_core::authn::{
    error::AuthnError,
    factor::{FactorCredential, FactorKind, ZeroizedString},
    service::{AuthnService, LoginOutcome},
    store::AuthMethod,
    types::{AuthnScope, EntityState, StatusDetail, User},
};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::Utc;
use common::{password_config, test_tenant, test_user, tid, uid};

/// Empty factor chain should return InvalidCredentials from begin_login.
#[tokio::test]
async fn empty_factor_chain() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            AuthnScope::User {
                tenant_id: tid("t1"),
                user_id: uid("u1"),
            },
            password_config("Gnomes2+"),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential(
                "empty",
                vec![], // Empty!
                AuthnScope::User {
                    tenant_id: tid("t1"),
                    user_id: uid("u1"),
                },
            ),
        );

    let service = AuthnService::new(identity, factors);
    let session = test_session();

    let outcome = service
        .begin_login("alice", "default", &session, None)
        .await
        .unwrap();
    assert!(matches!(outcome, LoginOutcome::InvalidCredentials));
}

/// verify_factor on a guest session should return NoFlow.
#[tokio::test]
async fn verify_factor_without_begin_returns_no_flow() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors);
    let session = test_session();

    let result = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("x")),
            &session,
        )
        .await;
    assert!(matches!(result, Err(AuthnError::NoFlow)));
}

/// prepare_factor on a guest session should return NoFlow.
#[tokio::test]
async fn prepare_factor_without_begin_returns_no_flow() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors);
    let session = test_session();

    let result = service.prepare_factor(&session).await;
    assert!(matches!(result, Err(AuthnError::NoFlow)));
}

/// Suspended user cannot login.
#[tokio::test]
async fn suspended_user_cannot_login() {
    let now = Utc::now();
    let suspended_user = User {
        id: uid("u1"),
        tenant_id: tid("t1"),
        identifier: "alice".into(),
        display_name: "Alice".into(),
        status: EntityState::Suspended(StatusDetail {
            reason: "test".into(),
            since: Utc::now(),
            until: None,
        }),
        webauthn_id: None,
        created_by: axess_core::authn::ids::UserId::system(),
        created_at: now,
        updated_by: axess_core::authn::ids::UserId::system(),
        updated_at: now,
    };
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(suspended_user);
    let factors = MockFactorStore::new()
        .with_factor(
            AuthnScope::User {
                tenant_id: tid("t1"),
                user_id: uid("u1"),
            },
            password_config("Gnomes2+"),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential(
                "password",
                vec![FactorKind::Password],
                AuthnScope::User {
                    tenant_id: tid("t1"),
                    user_id: uid("u1"),
                },
            ),
        );

    let service = AuthnService::new(identity, factors);
    let session = test_session();

    let outcome = service
        .begin_login("alice", "default", &session, None)
        .await;
    assert!(matches!(outcome, Ok(LoginOutcome::Locked { .. })));
}

/// Nonexistent tenant returns NotActive.
#[tokio::test]
async fn nonexistent_tenant_returns_error() {
    let identity = MockIdentityStore::new(); // No tenants!
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors);
    let session = test_session();

    let result = service
        .begin_login("alice", "nonexistent", &session, None)
        .await;
    assert!(matches!(result, Err(AuthnError::NotActive(_))));
}

/// SessionId display/parse round-trip.
#[test]
fn session_id_display_parse_roundtrip() {
    use axess_core::session::id::SessionId;
    use axess_core::testing::MockRng;

    let rng = MockRng::new(999);
    let id = SessionId::new(&rng);
    let s = id.to_string();
    let parsed: SessionId = s.parse().unwrap();
    assert_eq!(id, parsed);
}

/// ZeroizedString hides content in Debug output.
#[test]
fn zeroized_string_debug_hides_content() {
    let secret = ZeroizedString::new("super-secret");
    let debug = format!("{:?}", secret);
    assert!(!debug.contains("super-secret"));
    assert!(debug.contains("***"));
}

/// AuthnScope::key() produces distinct keys for each variant.
#[test]
fn authn_scope_keys_are_distinct() {
    let global = AuthnScope::Global;
    let tenant = AuthnScope::Tenant(tid("t1"));
    let user = AuthnScope::User {
        tenant_id: tid("t1"),
        user_id: uid("u1"),
    };

    assert_ne!(global.key(), tenant.key());
    assert_ne!(tenant.key(), user.key());
    assert_ne!(global.key(), user.key());
}
