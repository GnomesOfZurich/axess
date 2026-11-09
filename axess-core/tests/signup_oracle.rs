#![cfg(feature = "testing")]
//! With hidden conflicts a taken identifier gives the response a free one
//! does, down to the session id the response sets: the cookie must not say
//! which identifiers have an account.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::authn::types::EntityState;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{test_tenant, test_user};

fn service() -> RequestAuthnService<MockIdentityStore, MockFactorStore> {
    let mut existing = test_user("u1", "alice@example.com");
    existing.status = EntityState::Active;
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(existing);
    AuthnService::builder(identity, MockFactorStore::new())
        .build()
        .with_audit_context(AuditContext::default())
}

fn candidate(identifier: &str) -> axess_core::authn::types::User {
    let mut user = test_user("u2", identifier);
    user.status = EntityState::Candidate;
    user
}

#[tokio::test]
async fn a_taken_identifier_rotates_the_session_id_as_a_free_one_does() {
    let svc = service();

    let free = test_session();
    let before_free = free.session_id().await;
    svc.begin_signup(candidate("bob@example.com"), "default", &free)
        .await
        .unwrap();
    let free_rotated = free.session_id().await != before_free;

    let taken = test_session();
    let before_taken = taken.session_id().await;
    svc.begin_signup(candidate("alice@example.com"), "default", &taken)
        .await
        .unwrap();
    let taken_rotated = taken.session_id().await != before_taken;

    assert!(free_rotated, "a free identifier rotates the session id");
    assert_eq!(
        taken_rotated, free_rotated,
        "the session cookie tells a taken identifier from a free one"
    );
}
