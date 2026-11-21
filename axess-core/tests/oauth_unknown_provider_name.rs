//! A provider name the caller passed in, which is often the request's own
//! text (the `{provider}` of a route), reaches an error and an audit row
//! the way it reaches a span: control characters and the line separators
//! escaped, and cut at 128 bytes. A name nobody registered must not carry
//! a forged log line, or kilobytes, into `OAuthError::UnknownProvider` or
//! into the factor of the refresh's failure row.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_unknown_provider_name`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::service::AuthnService;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::oauth::{OAuthError, OAuthLoginOptions};
use common::{test_tenant, tid};

/// The most bytes the escaped and cut name may take.
const NAME_BOUND: usize = 128;

fn hostile_name() -> String {
    format!("sso\r\nINFO forged line\u{1b}[2J{}", "x".repeat(10_000))
}

fn assert_carried_safely(what: &str, name: &str) {
    assert!(
        name.len() <= NAME_BOUND,
        "{what}: {} bytes of the name",
        name.len()
    );
    assert!(
        !name.chars().any(char::is_control),
        "{what}: a control character reached it: {name:?}"
    );
    assert!(name.starts_with("sso"), "{what}: {name}");
}

fn unknown_name(what: &str, err: OAuthError) -> String {
    match err {
        OAuthError::UnknownProvider(name) => name,
        other => panic!("{what}: UnknownProvider, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unknown_name_reaches_the_error_escaped_and_cut() {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let authn = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let name = hostile_name();
    let session = test_session();

    let err = authn
        .begin_oauth_login(&name, &OAuthLoginOptions::default(), &session)
        .await
        .expect_err("nothing is registered");
    assert_carried_safely("begin", &unknown_name("begin", err));

    let key = authn.new_dpop_key();
    let err = authn
        .oauth_global()
        .generate_dpop_proof(&name, &key, "GET", "https://api.example/", None)
        .await
        .expect_err("nothing is registered");
    assert_carried_safely("dpop proof", &unknown_name("dpop proof", err));

    let scoped = authn.oauth_in_tenant(&tid("acme"));
    let err = scoped
        .revoke_oauth_token(&name, "token", None, None)
        .await
        .expect_err("nothing is registered");
    assert_carried_safely("scoped revoke", &unknown_name("scoped revoke", err));
    let err = scoped
        .fetch_userinfo(&name, "token", "subject", None)
        .await
        .expect_err("nothing is registered");
    assert_carried_safely("scoped userinfo", &unknown_name("scoped userinfo", err));
}

#[tokio::test]
async fn a_refresh_under_an_unknown_name_writes_the_name_escaped_and_cut() {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let name = hostile_name();

    let err = authn
        .oauth_global()
        .refresh_oauth_token(&name, "refresh", "subject", None, None)
        .await
        .expect_err("nothing is registered");
    assert_carried_safely("refresh", &unknown_name("refresh", err));
    let err = authn
        .oauth_global()
        .refresh_oauth_token(&name, "", "subject", None, None)
        .await
        .expect_err("no refresh token");
    assert!(matches!(err, OAuthError::NoRefreshToken), "{err:?}");

    let rows = identity.events();
    assert_eq!(rows.len(), 2, "{rows:?}");
    for row in rows {
        let Some(FactorKind::Federated(FederatedProvider::Custom(written))) = row.factor_kind
        else {
            panic!("the row names the provider: {:?}", row.factor_kind);
        };
        assert_carried_safely("refresh row", &written);
    }
}
