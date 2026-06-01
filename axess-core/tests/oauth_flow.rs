//! OAuth begin/finish ceremony: CSRF guard, expiry cap, MockOAuthProvider surface.

#![cfg(feature = "testing-oauth")]

mod common;

use axess_core::{
    authn::service::AuthnService,
    testing::{
        MockClock,
        mock_authn::{MockFactorStore, MockIdentityStore},
        oauth_wiremock::{
            oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints, oauth_setup_provider,
        },
        test_session,
    },
};
use axess_factors::oauth::{OAuthLoginOptions, OAuthProviderConfig};
use common::test_tenant;
use wiremock::MockServer;

// ── CSRF / expiry tests (need real HTTP for discovery) ─────────────────────

/// OAuth flow with CSRF mismatch should fail.
#[tokio::test]
async fn oauth_csrf_mismatch_rejected() {
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider: OAuthProviderConfig = oauth_setup_provider(&server).await;

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(provider);

    let session = test_session();
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .unwrap();

    let result = authn
        .finish_oauth_login("fake-code", "wrong-state", &session)
        .await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::CsrfMismatch
    ));
}

/// OAuth flow with expired ceremony should fail.
#[tokio::test]
async fn oauth_expired_ceremony_rejected() {
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = oauth_setup_provider(&server).await;

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let clock = MockClock::now();
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(provider);

    let session = test_session();
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .unwrap();

    let stored_state = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap();

    // Advance past 10-minute timeout.
    clock.advance_secs(601);

    let result = authn
        .finish_oauth_login("fake-code", &stored_state, &session)
        .await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::Expired
    ));
}

/// When an operator configures `ceremony_timeout` higher than
/// the RFC 6749 §4.1.2 RECOMMENDED 600 s authorisation-code lifetime,
/// the effective expiry MUST still be capped at 600 s. Without this
/// cap the auth-code lifetime inherits the operator's wider window:
/// the exact thing the spec is trying to prevent.
#[tokio::test]
async fn oauth_ceremony_capped_at_rfc_600s_even_when_provider_overrides() {
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    // Provider advertises a 30-min ceremony_timeout. The AS would happily
    // honour it; the axess-side cap clamps the *axess* expiry check at 600 s.
    let provider = oauth_setup_provider(&server)
        .await
        .with_ceremony_timeout(std::time::Duration::from_secs(1800));

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let clock = MockClock::now();
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(provider);

    let session = test_session();
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .unwrap();

    let stored_state = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap();

    // 10 minutes + 1 s. The provider's advertised ceremony_timeout is
    // 30 min, so without the cap the ceremony would still be live.
    clock.advance_secs(601);

    let result = authn
        .finish_oauth_login("fake-code", &stored_state, &session)
        .await;
    match result {
        Err(axess_factors::oauth::OAuthError::Expired) => {}
        other => panic!(
            "ceremony with 30-min provider override should still expire at 600 s, got {other:?}"
        ),
    }
}

/// Unknown provider should fail.
#[tokio::test]
async fn oauth_unknown_provider_rejected() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new());

    let session = test_session();
    let result = authn
        .begin_oauth_login("nonexistent", &OAuthLoginOptions::default(), &session)
        .await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::UnknownProvider(_)
    ));
}

// ── MockOAuthProvider tests ──────────────────────────────────────────────────

/// MockOAuthProvider returns configured user claims via exchange_code.
#[tokio::test]
async fn mock_oauth_provider_returns_configured_user() {
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("mock-idp").with_user(
        "user-42",
        "bob@example.com",
        vec!["engineers", "admins"],
        vec!["viewer"],
    );

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(mock);

    let claims = authn
        .refresh_oauth_token("mock-idp", "any-refresh-token")
        .await
        .expect("mock refresh should succeed");

    assert_eq!(claims.subject, "user-42");
    assert_eq!(claims.email.as_deref(), Some("bob@example.com"));
    assert_eq!(claims.groups, vec!["engineers", "admins"]);
    assert_eq!(claims.roles, vec!["viewer"]);
    assert_eq!(claims.provider.as_ref(), "mock-idp");
    assert!(
        claims.refresh_token.is_some(),
        "mock should return a refresh token"
    );
}

/// MockOAuthProvider simulates a provider failure.
#[tokio::test]
async fn mock_oauth_provider_simulates_failure() {
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("failing-idp").with_failure("IdP is down for maintenance");

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(mock);

    let result = authn.refresh_oauth_token("failing-idp", "some-token").await;
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        axess_factors::oauth::OAuthError::TokenExchange(msg) => {
            assert!(
                msg.contains("IdP is down for maintenance"),
                "expected maintenance message, got: {msg}"
            );
        }
        other => panic!("expected TokenExchange, got: {other:?}"),
    }
}
