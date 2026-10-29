//! The provider's token endpoint is HTTPS (or loopback HTTP), and the
//! default client follows no redirects.

use super::*;
use crate::delegated::error::DelegatedError;
use axess_clock::testing::MockClock;
use axess_identity::{TenantId, UserId};
use axess_rng::testing::MockRng;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use url::Url;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).expect("fixed t0")
}

fn provider_at(token_endpoint: &str) -> Arc<DelegatedProvider> {
    Arc::new(DelegatedProvider::new(
        "p",
        Url::parse("https://idp.example/authorize").unwrap(),
        Url::parse(token_endpoint).unwrap(),
        "client",
        "secret",
        Url::parse("https://gnomes.local/callback").unwrap(),
    ))
}

#[tokio::test]
async fn a_plain_http_remote_token_endpoint_is_refused_before_any_request() {
    let provider = provider_at("http://192.0.2.1:9/token");
    let (_url, ctx) = begin_grant(&provider, &[], &MockRng::new(1)).expect("begin_grant");
    let err = complete_grant(
        &provider,
        &ctx,
        "code",
        &ctx.state,
        &reqwest::Client::new(),
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
                access_token: "stale".into(),
                refresh_token: Some("rt".into()),
                expires_at: Some(t0() - chrono::Duration::seconds(60)),
                scopes: vec![],
                token_type: "Bearer".to_string(),
            },
        )
        .await
        .expect("save");
    let session = StoredDelegationSession::new(provider, store, tenant, user)
        .with_clock(Arc::new(MockClock::at(t0())));
    assert!(session.get_access_token().await.is_err());
}
