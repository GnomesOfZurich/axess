//! `AuthSession::authenticating_state`: its three branches (Authenticating,
//! Guest, Authenticated).

use super::*;

#[tokio::test]
async fn authenticating_state_destructures_authenticating_session() {
    let session = authenticating_session(vec![FactorKind::Password, FactorKind::Totp]).await;
    let (user_id, tenant_id, remaining) = session
        .authenticating_state()
        .await
        .expect("Authenticating session must produce a triple");
    assert_eq!(user_id, uid("u1"));
    assert_eq!(tenant_id, tid("t1"));
    assert_eq!(
        remaining,
        vec![
            crate::authn::factor::FactorStep::Required(FactorKind::Password),
            crate::authn::factor::FactorStep::Required(FactorKind::Totp),
        ]
    );
}

#[tokio::test]
async fn authenticating_state_returns_none_for_guest_session() {
    let session = test_session(); // Guest by default
    assert!(
        session.authenticating_state().await.is_none(),
        "Guest sessions must not surface a triple; callers map None to AuthnError::NoFlow"
    );
}

#[tokio::test]
async fn authenticating_state_returns_none_for_authenticated_session() {
    let session = authenticating_session(vec![FactorKind::Password]).await;
    // Advance through the only remaining factor to flip to Authenticated.
    session
        .advance_factor(
            crate::authn::assurance::FactorAssurance::for_kind(FactorKind::Password, start()),
            &[],
        )
        .await;
    assert!(session.is_authenticated().await);
    assert!(
        session.authenticating_state().await.is_none(),
        "Authenticated sessions are no longer mid-flow; must yield None"
    );
}
