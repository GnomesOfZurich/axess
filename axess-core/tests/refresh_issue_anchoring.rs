#![cfg(feature = "testing")]
//! A refresh token issued from a session is anchored at the session's login,
//! not at the moment of issue: redeeming it never makes an old
//! authentication look new, and a session past the family's lifetime gets no
//! token.

use axess_clock::testing::Shift;
use axess_core::testing::fixtures as common;

use axess_clock::SignedDuration;
use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::factor::{FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::service::{AuthnService, FactorOutcome, RequestAuthnService};
use axess_core::blocking::KdfExecutor;
use axess_core::session::data::AuthState;
use axess_core::session::refresh::{Refresh, RefreshTokenConfig};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::{
    MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    mock_refresh_store::MemoryRefreshTokenStore,
    test_session,
};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn svc(clock: &MockClock) -> Svc {
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default())
}

/// The service with a password `alice` can step up with.
fn svc_with_password(clock: &MockClock) -> Svc {
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Sample2+"))
        .with_method(&uid("u1"), password_method());
    AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_kdf_executor(std::sync::Arc::new(KdfExecutor::inline()))
        .build()
        .with_audit_context(AuditContext::default())
}

#[tokio::test]
async fn a_token_issued_from_an_old_session_keeps_the_login_time_through_redemption() {
    let clock = common::test_clock();
    let svc = svc(&clock);
    let user = test_user("u1", "alice");
    let login = clock.now().minus(SignedDuration::days(6));
    let session = test_session();
    session
        .set_authenticated(user.id, user.tenant_id, login)
        .await;
    let store = MemoryRefreshTokenStore::new().with_clock(std::sync::Arc::new(clock.clone()));
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
        .without_device_check()
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
    let clock = common::test_clock();
    let svc = svc(&clock);
    let user = test_user("u1", "alice");
    let session = test_session();
    session
        .set_authenticated(
            user.id,
            user.tenant_id,
            clock.now().minus(SignedDuration::days(8)),
        )
        .await;
    let store = MemoryRefreshTokenStore::new().with_clock(std::sync::Arc::new(clock.clone()));
    let config = RefreshTokenConfig {
        rotation: true,
        max_lifetime: Some(std::time::Duration::from_hours(7 * 24)),
        ttl: std::time::Duration::from_hours(7 * 24),
        ..Default::default()
    };

    let res = svc
        .issue_refresh_token(&session, &store, &config, None, None)
        .await;

    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
}

/// A session whose authentication time lies in the future (a clock that
/// ran ahead, an integrator's mistake) gets a token anchored at now, never
/// later: the family's lifetime and every recency gate count from the
/// moment of issue at the latest.
#[tokio::test]
async fn an_authentication_time_in_the_future_is_anchored_at_now() {
    let clock = common::test_clock();
    let svc = svc(&clock);
    let user = test_user("u1", "alice");
    let ahead = clock.now().plus(SignedDuration::hours(3));
    let session = test_session();
    session
        .set_authenticated(user.id, user.tenant_id, ahead)
        .await;
    let store = MemoryRefreshTokenStore::new().with_clock(std::sync::Arc::new(clock.clone()));
    let config = RefreshTokenConfig {
        rotation: true,
        ..Default::default()
    };

    let (_, record) = svc
        .issue_refresh_token(&session, &store, &config, None, None)
        .await
        .expect("a session is issued a token");
    assert_eq!(
        record.authn_time,
        Some(clock.now()),
        "an authentication time ahead of now is read as now"
    );
}

/// A step-up proves presence but is not a login. A token issued after one
/// carries the login's time, so the family's lifetime does not start again,
/// and the session redeemed from it has the login as its login and as its
/// last proof of presence.
#[tokio::test]
async fn a_token_issued_after_a_step_up_keeps_the_login_time_through_redemption() {
    let clock = common::test_clock();
    let svc = svc_with_password(&clock);
    let user = test_user("u1", "alice");
    let login = clock.now().minus(SignedDuration::minutes(50));
    let session = test_session();
    session
        .set_authenticated(user.id, user.tenant_id, login)
        .await;
    svc.begin_step_up(&session, vec![FactorKind::Password])
        .await
        .expect("the step-up opens");
    let done = svc
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("Sample2+")),
            &session,
        )
        .await
        .expect("the step-up is verified");
    assert!(matches!(done, FactorOutcome::Authenticated), "{done:?}");
    let stepped = session.snapshot().await.expect("signed in");
    assert_eq!(
        stepped.authn_time,
        clock.now(),
        "the step-up proved presence"
    );
    assert_eq!(stepped.signed_in_at, login, "the login is still the login");

    let store = MemoryRefreshTokenStore::new().with_clock(std::sync::Arc::new(clock.clone()));
    let config = RefreshTokenConfig {
        rotation: true,
        ..Default::default()
    };
    let (plaintext, record) = svc
        .issue_refresh_token(&session, &store, &config, None, None)
        .await
        .expect("the session gets a token");
    assert_eq!(record.authn_time, Some(login));

    let (rotated, _) = Refresh::any_tenant(&plaintext, |_| async { true })
        .without_device_check()
        .run(&store, &config, &MockRng::new(5), clock.now())
        .await
        .expect("the token redeems");
    match rotated.auth_state {
        AuthState::Authenticated {
            authn_time,
            signed_in_at,
            ..
        } => {
            assert_eq!(signed_in_at, login);
            assert_eq!(authn_time, login);
        }
        other => panic!("expected an authenticated session, got {other:?}"),
    }
}
