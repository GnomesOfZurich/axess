//! OAuth/OIDC integration tests using oauth2-test-server.
//!
//! Run with: `cargo test -p axess-core --features oauth --test oauth_flow`

#![cfg(feature = "oauth")]

use axess_core::{
    authn::{
        oauth::OAuthProviderConfig,
        service::AuthnService,
        types::{EntityState, Tenant, User},
    },
    utils::testing::{
        MockClock,
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    },
};
use oauth2_test_server::OAuthTestServer;

fn test_tenant() -> Tenant {
    Tenant {
        id: "t1".into(),
        identifier: "default".into(),
        display_name: "Test".into(),
        status: EntityState::Active,
    }
}

fn test_user() -> User {
    User {
        id: "u1".into(),
        tenant_id: "t1".into(),
        identifier: "alice".into(),
        display_name: "Alice".into(),
        status: EntityState::Active,
        webauthn_id: None,
    }
}

/// Helper: get the issuer URL using localhost (matches the test server's discovery doc).
fn issuer_url(server: &OAuthTestServer) -> String {
    server.issuer().replace("127.0.0.1", "localhost")
}

/// Helper: set up an OAuth provider against the test server.
async fn setup_provider(
    server: &OAuthTestServer,
) -> (OAuthProviderConfig, oauth2_test_server::Client) {
    let client_meta = serde_json::json!({
        "redirect_uris": ["http://localhost:3000/auth/callback/test"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic"
    });
    let test_client = server.register_client(client_meta).await;

    let provider = OAuthProviderConfig::discover(
        "test",
        &issuer_url(server),
        &test_client.client_id,
        test_client.client_secret.as_deref().unwrap_or(""),
        "http://localhost:3000/auth/callback/test",
    )
    .await
    .expect("OIDC discovery should succeed");

    (provider, test_client)
}

/// OAuth flow with CSRF mismatch should fail.
#[tokio::test]
async fn oauth_csrf_mismatch_rejected() {
    let server = OAuthTestServer::start().await;
    let (provider, _) = setup_provider(&server).await;

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(provider);

    let session = test_session();
    authn
        .begin_oauth_login("test", &Default::default(), &session)
        .await
        .unwrap();

    // Use wrong CSRF state.
    let result = authn
        .finish_oauth_login("fake-code", "wrong-state", &session)
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        axess_core::authn::oauth::OAuthError::CsrfMismatch
    ));
}

/// OAuth flow with expired ceremony should fail.
#[tokio::test]
async fn oauth_expired_ceremony_rejected() {
    let server = OAuthTestServer::start().await;
    let (provider, _) = setup_provider(&server).await;

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let clock = MockClock::now();
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(provider);

    let session = test_session();
    authn
        .begin_oauth_login("test", &Default::default(), &session)
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
        axess_core::authn::oauth::OAuthError::Expired
    ));
}

/// Unknown provider should fail.
#[tokio::test]
async fn oauth_unknown_provider_rejected() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new());

    let session = test_session();
    let result = authn
        .begin_oauth_login("nonexistent", &Default::default(), &session)
        .await;
    assert!(matches!(
        result.unwrap_err(),
        axess_core::authn::oauth::OAuthError::UnknownProvider(_)
    ));
}

/// Full OAuth flow: begin → approve → finish → complete_oauth_login.
///
/// This test exercises the real token exchange against the local OIDC test
/// server, including PKCE verification and ID token validation.
///
/// Currently ignored: the test server's token endpoint may not return an
/// ID token for codes obtained via approve_consent (scope not preserved).
/// Run manually with: `cargo test --features oauth -- --ignored oauth_full_flow`
#[tokio::test]
#[ignore = "requires investigation of test server id_token generation"]
async fn oauth_full_flow() {
    let server = OAuthTestServer::start().await;
    let (provider, _) = setup_provider(&server).await;

    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user());
    let clock = MockClock::now();
    let authn = AuthnService::new(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(provider);

    // Begin OAuth flow.
    let session2 = test_session();
    let (auth_url2, _) = authn
        .begin_oauth_login("test", &Default::default(), &session2)
        .await
        .unwrap();

    let stored_state = session2
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap();

    // Approve consent — returns the authorization code.
    let auth_code = server.approve_consent(&auth_url2, "test-user-123").await;

    // Finish the OAuth flow — exchanges code, validates ID token.
    let claims = authn
        .finish_oauth_login(&auth_code, &stored_state, &session2)
        .await
        .expect("finish_oauth_login should succeed");

    assert!(!claims.subject.is_empty());
    assert_eq!(claims.provider.as_ref(), "test");

    // Complete the login by linking to a local user.
    authn
        .complete_oauth_login(&test_user(), &claims, &session2)
        .await
        .expect("complete_oauth_login should succeed");

    assert!(session2.is_authenticated().await);
    assert_eq!(session2.user_id().await.unwrap().as_ref(), "u1");

    // Verify audit events.
    let events = identity.events();
    assert!(
        events.len() >= 2,
        "expected >=2 events, got {}",
        events.len()
    );
}
