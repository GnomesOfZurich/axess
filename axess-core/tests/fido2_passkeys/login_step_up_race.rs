//! A step-up begun while another request changes the session. The step-up
//! is for the user the session held when it was asked: a session that
//! changed hands before the step-up was written is refused and left as the
//! other request made it.

use axess_core::testing::fixtures as common;

use super::fixture::*;
use axess_core::Clock;
use axess_core::authn::error::AuthnError;
use axess_core::authn::factor::FactorKind;
use axess_core::authn::ids::{TenantId, UserId};
use axess_core::session::extractor::AuthSession;
use axess_core::testing::{AuthSessionTestExt, test_session};
use common::{test_user, test_user_in_tenant};

/// A session of `alice`, and a request armed to sign `user` of `tenant` in
/// on it while the step-up reads the factor store.
async fn session_taken_over_by(f: &Fixture, user: UserId, tenant: TenantId) -> AuthSession {
    let alice = test_user("u1", "alice");
    let session = test_session();
    session
        .set_authenticated(alice.id, alice.tenant_id, f.clock.now())
        .await;
    let (racing, now) = (session.clone(), f.clock.now());
    *f.factors.before_next_resolve.lock().unwrap() = Some(Box::pin(async move {
        racing.set_authenticated(user, tenant, now).await;
    }));
    session
}

#[tokio::test]
async fn a_step_up_is_refused_when_the_session_became_another_users_meanwhile() {
    let f = fixture();
    let alice = test_user("u1", "alice");
    let bob = test_user("u2", "bob");
    let elsewhere = test_user_in_tenant("u1", "alice", "other");
    assert_eq!(elsewhere.id, alice.id);
    assert_ne!(elsewhere.tenant_id, alice.tenant_id);

    for (user, tenant) in [(bob.id, bob.tenant_id), (elsewhere.id, elsewhere.tenant_id)] {
        let session = session_taken_over_by(&f, user, tenant).await;

        let res = f
            .service
            .begin_step_up(&session, vec![FactorKind::Fido2])
            .await;

        assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
        assert!(
            session.is_authenticated().await,
            "the session is left as the other request made it"
        );
        assert_eq!(session.user_id().await, Some(user));
        assert_eq!(session.tenant_id().await, Some(tenant));
        let stamp = session.get_custom("axess.login.flow").await;
        assert!(stamp.is_none(), "no flow stamp is left behind: {stamp:?}");
    }
}

/// The refusal is for the change of hands, not for the other request: one
/// that leaves the session with the same user in the same tenant does not
/// stop the step-up.
#[tokio::test]
async fn a_step_up_goes_on_when_the_other_request_left_the_same_user() {
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = session_taken_over_by(&f, alice.id, alice.tenant_id).await;

    let first = f
        .service
        .begin_step_up(&session, vec![FactorKind::Fido2])
        .await
        .unwrap();

    assert_eq!(first, FactorKind::Fido2);
    assert!(!session.is_authenticated().await, "mid step-up");
}
