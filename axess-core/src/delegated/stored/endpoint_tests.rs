//! The provider's token endpoint is HTTPS (or loopback HTTP), and the
//! default client follows no redirects.

use super::*;
use crate::delegated::error::DelegatedError;
use axess_clock::Timestamp;
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use axess_identity::{TenantId, UserId};
use axess_rng::testing::MockRng;
use std::sync::Arc;
use url::Url;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn t0() -> Timestamp {
    Timestamp::from_unix_seconds(1_700_000_000).expect("fixed t0")
}

fn provider_at(token_endpoint: &str) -> Arc<DelegatedProvider> {
    Arc::new(DelegatedProvider::new(
        "p",
        Url::parse("https://idp.example/authorize").unwrap(),
        Url::parse(token_endpoint).unwrap(),
        "client",
        "secret",
        Url::parse("https://example.org/callback").unwrap(),
    ))
}

#[tokio::test]
async fn a_plain_http_remote_token_endpoint_is_refused_before_any_request() {
    let provider = provider_at("http://192.0.2.1:9/token");
    let (_, ctx) = begin_grant(&provider, &[], &MockRng::new(1)).expect("begin_grant");
    let err = complete_grant(
        &provider,
        &ctx,
        "code",
        &ctx.state,
        &grant_client(|settings| settings).expect("client"),
        &MockClock::at(t0()),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, DelegatedError::Transport(m) if m.contains("must be https")),
        "{err}"
    );
}

#[tokio::test]
async fn the_default_session_client_does_not_follow_a_redirect() {
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&target)
        .await;
    let first = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", target.uri().as_str()))
        .expect(1)
        .mount(&first)
        .await;

    let provider = provider_at(&format!("{}/token", first.uri()));
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    let (tenant, user) = (TenantId::from_bytes([1; 16]), UserId::from_bytes([2; 16]));
    store
        .save(
            &tenant,
            &user,
            StoredDelegation {
                provider: provider.name.clone(),
                registration: Some(GrantRegistration::of(&provider)),
                access_token: "stale".into(),
                refresh_token: Some("rt".into()),
                expires_at: Some(t0().minus(axess_clock::SignedDuration::seconds(60))),
                scopes: vec![],
                token_type: "Bearer".to_string(),
            },
        )
        .await
        .expect("save");
    let session = StoredDelegationSession::new(provider, store, tenant, user)
        .expect("the default client builds")
        .with_clock(Arc::new(MockClock::at(t0())));
    assert!(session.get_access_token().await.is_err());
}

fn provider_with_authorization_endpoint(authorization_endpoint: &str) -> DelegatedProvider {
    DelegatedProvider::new(
        "p",
        Url::parse(authorization_endpoint).unwrap(),
        Url::parse("https://idp.example/token").unwrap(),
        "client",
        "secret",
        Url::parse("https://example.org/callback").unwrap(),
    )
}

/// The browser is sent to the authorization endpoint with the client id, the
/// PKCE challenge and the `state` in the URL: a plain-HTTP remote endpoint
/// would carry them in clear.
#[test]
fn a_plain_http_remote_authorization_endpoint_is_refused_by_begin_grant() {
    let provider = provider_with_authorization_endpoint("http://192.0.2.1:9/authorize");

    let refused = begin_grant(&provider, &[], &MockRng::new(1));

    assert!(
        matches!(&refused, Err(DelegatedError::Transport(m)) if m.contains("must be https")),
        "{:?}",
        refused.map(|(url, _)| url.scheme().to_owned())
    );
}

#[test]
fn a_loopback_or_https_authorization_endpoint_is_accepted_by_begin_grant() {
    for endpoint in [
        "http://127.0.0.1:8080/authorize",
        "http://localhost:8080/authorize",
        "http://[::1]:8080/authorize",
        "https://idp.example/authorize",
    ] {
        let provider = provider_with_authorization_endpoint(endpoint);
        assert!(
            begin_grant(&provider, &[], &MockRng::new(1)).is_ok(),
            "{endpoint}"
        );
    }
}

fn provider_with_redirect_uri(redirect_uri: &str) -> DelegatedProvider {
    DelegatedProvider::new(
        "p",
        Url::parse("https://idp.example/authorize").unwrap(),
        Url::parse("https://idp.example/token").unwrap(),
        "client",
        "secret",
        Url::parse(redirect_uri).unwrap(),
    )
}

/// The IdP sends the browser back to `redirect_uri` with the code and the
/// `state`: a plain-HTTP remote one would carry them in clear, so it is
/// refused by name before the browser is sent anywhere.
#[test]
fn a_plain_http_remote_redirect_uri_is_refused_by_begin_grant() {
    let provider = provider_with_redirect_uri("http://app.example/cb");

    let refused = begin_grant(&provider, &[], &MockRng::new(1));

    assert!(
        matches!(&refused, Err(DelegatedError::Transport(m)) if m.contains("redirect_uri")),
        "{:?}",
        refused.map(|(url, _)| url.scheme().to_owned())
    );
}

#[test]
fn a_loopback_or_https_redirect_uri_is_accepted_by_begin_grant() {
    for redirect_uri in [
        "http://127.0.0.1:3000/cb",
        "http://localhost:3000/cb",
        "http://[::1]:3000/cb",
        "https://app.example/cb",
    ] {
        let provider = provider_with_redirect_uri(redirect_uri);
        assert!(
            begin_grant(&provider, &[], &MockRng::new(1)).is_ok(),
            "{redirect_uri}"
        );
    }
}

/// The code exchange echoes `redirect_uri` to the token endpoint; a provider
/// whose `redirect_uri` the grant could not have begun with is refused here
/// too, before any request.
#[tokio::test]
async fn a_plain_http_remote_redirect_uri_is_refused_by_complete_grant() {
    let provider = provider_with_redirect_uri("http://app.example/cb");
    let context = GrantContext {
        state: "state-value".to_string(),
        code_verifier: axess_factors::ZeroizedString::from(
            "verifier-verifier-verifier-verifier-verifier-ok".to_string(),
        ),
        requested_scopes: vec![],
        registration: GrantRegistration::of(&provider),
    };

    let err = complete_grant(
        &provider,
        &context,
        "code",
        "state-value",
        &grant_client(|settings| settings).expect("client"),
        &MockClock::at(t0()),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(&err, DelegatedError::Transport(m) if m.contains("redirect_uri")),
        "{err}"
    );
}
