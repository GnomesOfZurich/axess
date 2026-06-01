//! OAuth refresh_token + userinfo surface, including audit-event tagging.

#![cfg(all(feature = "oauth", feature = "testing"))]

mod common;

use axess_core::{
    authn::service::AuthnService,
    testing::mock_authn::{MockFactorStore, MockIdentityStore},
};
use common::test_tenant;

/// OAuth refresh roundtrip: refresh_oauth_token returns updated claims.
#[tokio::test]
async fn oauth_refresh_roundtrip() {
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("refresh-idp").with_user(
        "user-99",
        "carol@example.com",
        vec!["team-a"],
        vec!["editor"],
    );

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn =
        AuthnService::new(identity.clone(), MockFactorStore::new()).with_oauth_provider(mock);

    let claims = authn
        .refresh_oauth_token("refresh-idp", "stored-refresh-token")
        .await
        .expect("refresh should succeed");

    assert_eq!(claims.subject, "user-99");
    assert_eq!(claims.email.as_deref(), Some("carol@example.com"));
    assert_eq!(claims.groups, vec!["team-a"]);
    assert_eq!(claims.roles, vec!["editor"]);
    assert_eq!(claims.provider.as_ref(), "refresh-idp");

    let events = identity.events();
    assert!(!events.is_empty(), "expected at least one audit event");
}

/// Refresh with empty token returns NoRefreshToken error and records a
/// `token_refresh_no_token` Failure audit event.
#[tokio::test]
async fn oauth_refresh_empty_token_rejected() {
    use axess_core::authn::event::AuthEventStatus;
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("test-idp2").with_user("user-1", "a@b.com", vec![], vec![]);

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn =
        AuthnService::new(identity.clone(), MockFactorStore::new()).with_oauth_provider(mock);

    let result = authn.refresh_oauth_token("test-idp2", "").await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::NoRefreshToken
    ));

    let events = identity.events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event_status, AuthEventStatus::Failure)
                && e.error.as_deref() == Some("token_refresh_no_token")),
        "expected a Failure event tagged token_refresh_no_token, got {events:?}"
    );
}

/// Refresh against unknown provider returns UnknownProvider error and
/// records a `token_refresh_unknown_provider` Failure audit event.
#[tokio::test]
async fn oauth_refresh_unknown_provider_rejected() {
    use axess_core::authn::event::AuthEventStatus;

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity.clone(), MockFactorStore::new());

    let result = authn.refresh_oauth_token("nonexistent", "some-token").await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::UnknownProvider(_)
    ));

    let events = identity.events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event_status, AuthEventStatus::Failure)
                && e.error.as_deref() == Some("token_refresh_unknown_provider")),
        "expected a Failure event tagged token_refresh_unknown_provider, got {events:?}"
    );
}

/// fetch_userinfo with empty access token returns NoAccessToken error.
#[tokio::test]
async fn oauth_userinfo_empty_token_rejected() {
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("ui-idp").with_user("u1", "x@y.com", vec![], vec![]);
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(mock);

    let result = authn.fetch_userinfo("ui-idp", "").await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::NoAccessToken
    ));
}

/// fetch_userinfo with unknown provider returns UnknownProvider error.
#[tokio::test]
async fn oauth_userinfo_unknown_provider_rejected() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new());

    let result = authn.fetch_userinfo("nope", "some-token").await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::UnknownProvider(_)
    ));
}
