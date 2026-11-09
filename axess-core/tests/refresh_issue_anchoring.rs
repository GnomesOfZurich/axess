#![cfg(feature = "testing")]
//! A refresh token issued from a session is anchored at the session's login,
//! not at the moment of issue: redeeming it never makes an old
//! authentication look new, and a session past the family's lifetime gets no
//! token.

mod common;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::session::data::AuthState;
use axess_core::session::refresh::{Refresh, RefreshTokenConfig};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::{
    MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    mock_refresh_store::MemoryRefreshTokenStore,
    test_session,
};
use chrono::Duration;
use common::{test_tenant, test_user};

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn svc(clock: &MockClock) -> Svc {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default())
}

#[tokio::test]
async fn a_token_issued_from_an_old_session_keeps_the_login_time_through_redemption() {
    let clock = MockClock::now();
    let svc = svc(&clock);
    let user = test_user("u1", "alice");
    let login = clock.now() - Duration::days(6);
    let session = test_session();
    session
        .set_authenticated(user.id, user.tenant_id, login)
        .await;
    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig {
        rotation: true,
        ..Default::default()
    };

    let (plaintext, record) = svc
        .issue_refresh_token(&session, &store, &config, None, None)
        .await
        .expect("a six day old session still gets a token");
    assert_eq!(record.authn_time, Some(login));

    let (rotated, _) = Refresh::any_tenant(&plaintext, |_| async { true })
        .run(&store, &config, &MockRng::new(5), clock.now())
        .await
        .expect("the token redeems");
    match rotated.auth_state {
        AuthState::Authenticated { authn_time, .. } => assert_eq!(authn_time, login),
        other => panic!("expected an authenticated session, got {other:?}"),
    }
}

#[tokio::test]
async fn a_session_past_the_family_lifetime_gets_no_token() {
    let clock = MockClock::now();
    let svc = svc(&clock);
    let user = test_user("u1", "alice");
    let session = test_session();
    session
        .set_authenticated(user.id, user.tenant_id, clock.now() - Duration::days(8))
        .await;
    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig {
        rotation: true,
        max_lifetime: Some(Duration::days(7)),
        ttl: Duration::days(7),
        ..Default::default()
    };

    let res = svc
        .issue_refresh_token(&session, &store, &config, None, None)
        .await;

    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
}
