#![cfg(feature = "testing")]
//! With hidden conflicts a taken identifier gives the response a free one
//! does, down to the session id the response sets: the cookie must not say
//! which identifiers have an account.

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::service::{AuthnService, RequestAuthnService, SignupOutcome};
use axess_core::authn::types::EntityState;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{test_tenant, test_user};

fn service() -> RequestAuthnService<MockIdentityStore, MockFactorStore> {
    let clock = common::test_clock();
    let mut existing = test_user("u1", "alice@example.com");
    existing.status = EntityState::Active;
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(existing);
    AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
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
    let before_free = free.session_key().await;
    svc.begin_signup(candidate("bob@example.com"), "default", &free)
        .await
        .unwrap();
    let free_rotated = free.session_key().await != before_free;

    let taken = test_session();
    let before_taken = taken.session_key().await;
    svc.begin_signup(candidate("alice@example.com"), "default", &taken)
        .await
        .unwrap();
    let taken_rotated = taken.session_key().await != before_taken;

    assert!(free_rotated, "a free identifier rotates the session id");
    assert_eq!(
        taken_rotated, free_rotated,
        "the session cookie tells a taken identifier from a free one"
    );
}

/// After the response, the two sessions are in the same state and answer
/// every later signup call alike: a wrong secret is refused the same way,
/// and the signup can be begun again on both. Before, the taken session
/// stayed `Guest` and `complete_signup` said `NoFlow` where the free one
/// said `InvalidAssertion`, a second request that told the two apart.
#[tokio::test]
async fn a_taken_identifier_leaves_the_session_as_a_free_one_does() {
    use axess_core::authn::error::AuthnError;
    use axess_core::session::data::AuthState;
    let svc = service();

    let free = test_session();
    svc.begin_signup(candidate("bob@example.com"), "default", &free)
        .await
        .unwrap();
    let taken = test_session();
    svc.begin_signup(candidate("alice@example.com"), "default", &taken)
        .await
        .unwrap();

    let pending = |state: &AuthState| matches!(state, AuthState::PendingWorkflow { .. });
    assert!(
        pending(&free.auth_state().await),
        "a free identifier is pending"
    );
    assert_eq!(
        pending(&taken.auth_state().await),
        pending(&free.auth_state().await),
        "the session state tells a taken identifier from a free one"
    );

    let refused = |outcome: Result<(), AuthnError<_>>| match outcome {
        Err(AuthnError::InvalidAssertion) => "invalid assertion",
        Err(AuthnError::NoFlow) => "no flow",
        Err(_) => "another error",
        Ok(()) => "accepted",
    };
    let on_free = refused(svc.complete_signup(&free, "not the secret").await);
    let on_taken = refused(svc.complete_signup(&taken, "not the secret").await);
    assert_eq!(on_free, "invalid assertion");
    assert_eq!(
        on_taken, on_free,
        "a follow-up with a wrong secret tells a taken identifier from a free one"
    );

    let again_free = svc
        .begin_signup(candidate("bob@example.com"), "default", &free)
        .await
        .unwrap();
    let again_taken = svc
        .begin_signup(candidate("alice@example.com"), "default", &taken)
        .await
        .unwrap();
    assert!(matches!(again_free, SignupOutcome::Started(_)));
    assert!(
        matches!(again_taken, SignupOutcome::Started(_)),
        "a resubmitted taken identifier still answers as a free one: {again_taken:?}"
    );
}
