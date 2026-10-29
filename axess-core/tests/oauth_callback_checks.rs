//! Callback and UserInfo checks that need only the mock provider: the RFC 9207
//! `iss` parameter and the UserInfo `sub` binding.
//!
//! Run with: `cargo test -p axess-core --features testing-oauth --test oauth_callback_checks`

#![cfg(feature = "testing-oauth")]

mod common;

use axess_core::authn::AuditContext;
use axess_core::{
    authn::service::AuthnService,
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    },
};
use axess_factors::oauth::{MockOAuthProvider, OAuthError, OAuthLoginOptions};
use common::test_tenant;

type Svc = axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn service(mock: MockOAuthProvider) -> Svc {
    AuthnService::builder(
        MockIdentityStore::new().with_tenant(test_tenant()),
        MockFactorStore::new(),
    )
    .with_oauth_provider(mock)
    .build()
    .with_audit_context(AuditContext::default())
}

async fn begun(svc: &Svc, name: &str) -> (axess_core::session::extractor::AuthSession, String) {
    let session = test_session();
    svc.begin_oauth_login(name, &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin");
    let state = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(str::to_owned))
        .expect("state");
    (session, state)
}

fn idp(name: &str) -> MockOAuthProvider {
    MockOAuthProvider::new(name).with_user("alice", "a@example.com", vec![], vec![])
}

/// A callback whose `iss` is another server\'s is refused as a mix-up, before
/// the code is exchanged; the provider\'s own issuer passes.
#[tokio::test]
async fn a_callback_iss_that_is_not_the_providers_is_refused() {
    let svc = service(idp("idp"));

    let (session, state) = begun(&svc, "idp").await;
    let err = svc
        .finish_oauth_login_with_iss("code", &state, Some("https://evil.example.com"), &session)
        .await
        .expect_err("a different issuer is a mix-up");
    assert!(matches!(err, OAuthError::CsrfMismatch), "got {err:?}");

    let (session, state) = begun(&svc, "idp").await;
    svc.finish_oauth_login_with_iss("code", &state, Some("https://idp.example.com"), &session)
        .await
        .expect("the provider\'s own issuer is accepted");
}

/// A missing `iss` is refused when the IdP advertises that it sends one, and
/// accepted when it does not.
#[tokio::test]
async fn a_missing_iss_is_refused_only_when_the_idp_advertises_it() {
    let svc = service(idp("strict").with_iss_parameter_required());
    let (session, state) = begun(&svc, "strict").await;
    let err = svc
        .finish_oauth_login_with_iss("code", &state, None, &session)
        .await
        .expect_err("the IdP sends iss, so its absence is refused");
    assert!(matches!(err, OAuthError::CsrfMismatch), "got {err:?}");

    let svc = service(idp("lax"));
    let (session, state) = begun(&svc, "lax").await;
    svc.finish_oauth_login_with_iss("code", &state, None, &session)
        .await
        .expect("an IdP that does not advertise it need not send it");
}

/// A UserInfo response for another subject is refused and returns no claims.
#[tokio::test]
async fn userinfo_for_another_subject_is_refused() {
    let svc = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(MockOAuthProvider::new("ui").with_user(
            "bob",
            "b@example.com",
            vec![],
            vec![],
        ))
        .build();

    let err = svc
        .fetch_userinfo("ui", "token", "alice")
        .await
        .expect_err("sub=bob is not alice");
    assert!(matches!(err, OAuthError::SubjectMismatch), "got {err:?}");
    assert!(!err.to_string().contains("bob") && !err.to_string().contains("alice"));

    let claims = svc.fetch_userinfo("ui", "token", "bob").await.unwrap();
    assert_eq!(claims.sub, "bob");
}
