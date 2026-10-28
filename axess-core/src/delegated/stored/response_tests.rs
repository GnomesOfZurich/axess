//! Token-endpoint response handling: an expired lifetime is expired, an
//! omitted scope is unchanged, a bearer string is for bearer tokens, a
//! callback needs a state, and no response is read without a bound.

use super::*;
use crate::delegated::error::DelegatedError;
use axess_clock::testing::MockClock;
use axess_identity::{TenantId, UserId};
use axess_rng::testing::MockRng;
use chrono::{DateTime, Utc};
use serde_json::json;
use std::sync::Arc;
use url::Url;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).expect("fixed t0")
}

fn provider(server: &MockServer) -> Arc<DelegatedProvider> {
    Arc::new(
        DelegatedProvider::new(
            "test-provider",
            Url::parse(&format!("{}/oauth2/authorize", server.uri())).unwrap(),
            Url::parse(&format!("{}/oauth2/token", server.uri())).unwrap(),
            "axess-client-id",
            "axess-secret",
            Url::parse("https://gnomes.local/callback").unwrap(),
        )
        .with_default_scopes(["mail.read", "mail.send"]),
    )
}

async fn respond(server: &MockServer, status: u16, body: Vec<u8>) {
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(status).set_body_raw(body, "application/json"))
        .mount(server)
        .await;
}

async fn grant(server: &MockServer) -> Result<StoredDelegation, DelegatedError> {
    let provider = provider(server);
    let (_url, ctx) = begin_grant(&provider, &[], &MockRng::new(1)).expect("begin_grant");
    complete_grant_at(
        &provider,
        &ctx,
        "code",
        &ctx.state,
        &reqwest::Client::new(),
        t0(),
    )
    .await
}

fn stored(provider: &DelegatedProvider, scopes: &[&str], token_type: &str) -> StoredDelegation {
    StoredDelegation {
        provider: provider.name.clone(),
        access_token: "stale".into(),
        refresh_token: Some("rfr".into()),
        expires_at: Some(t0() - chrono::Duration::seconds(60)),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        token_type: token_type.to_string(),
    }
}

async fn session_over(
    provider: Arc<DelegatedProvider>,
    credential: StoredDelegation,
) -> (
    StoredDelegationSession<MemoryDelegatedCredentialStore>,
    Arc<MemoryDelegatedCredentialStore>,
    TenantId,
    UserId,
) {
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    let (tenant, user) = (TenantId::from_bytes([1; 16]), UserId::from_bytes([2; 16]));
    store.save(&tenant, &user, credential).await.expect("save");
    let session = StoredDelegationSession::new(provider, store.clone(), tenant, user)
        .with_clock(Arc::new(MockClock::at(t0())));
    (session, store, tenant, user)
}

#[tokio::test]
async fn expires_in_zero_is_already_expired_not_never_expiring() {
    let server = MockServer::start().await;
    respond(
        &server,
        200,
        br#"{"access_token":"t","expires_in":0}"#.to_vec(),
    )
    .await;

    let cred = grant(&server).await.expect("grant");

    assert_eq!(cred.expires_at, Some(t0()));
    assert!(
        !cred.is_fresh(t0(), chrono::Duration::zero()),
        "a token that expired on arrival is not fresh"
    );
}

#[tokio::test]
async fn a_zero_lifetime_credential_is_refreshed_on_next_use() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "renewed", "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let provider = provider(&server);
    let mut credential = stored(&provider, &[], "Bearer");
    credential.expires_at = Some(t0());
    let (session, ..) = session_over(provider, credential).await;

    assert_eq!(session.get_access_token().await.expect("token"), "renewed");
}

#[tokio::test]
async fn refresh_without_scope_keeps_the_stored_scopes() {
    let server = MockServer::start().await;
    respond(
        &server,
        200,
        br#"{"access_token":"renewed","expires_in":3600}"#.to_vec(),
    )
    .await;
    let provider = provider(&server);
    let (session, store, tenant, user) = session_over(
        provider.clone(),
        stored(&provider, &["mail.read"], "Bearer"),
    )
    .await;

    session.get_access_token().await.expect("token");

    let after = store
        .load(&tenant, &user, &provider.name)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.scopes, vec!["mail.read".to_string()]);
}

#[tokio::test]
async fn refresh_with_a_scope_replaces_the_stored_scopes() {
    let server = MockServer::start().await;
    respond(
        &server,
        200,
        br#"{"access_token":"renewed","expires_in":3600,"scope":"mail.send"}"#.to_vec(),
    )
    .await;
    let provider = provider(&server);
    let (session, store, tenant, user) = session_over(
        provider.clone(),
        stored(&provider, &["mail.read"], "Bearer"),
    )
    .await;

    session.get_access_token().await.expect("token");

    let after = store
        .load(&tenant, &user, &provider.name)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.scopes, vec!["mail.send".to_string()]);
}

#[tokio::test]
async fn code_exchange_without_scope_stores_the_requested_scopes() {
    let server = MockServer::start().await;
    respond(
        &server,
        200,
        br#"{"access_token":"t","expires_in":60}"#.to_vec(),
    )
    .await;

    let cred = grant(&server).await.expect("grant");

    assert_eq!(cred.scopes, vec!["mail.read", "mail.send"]);
}

#[tokio::test]
async fn an_empty_state_is_refused_even_when_the_callback_state_is_empty_too() {
    let server = MockServer::start().await;
    let provider = provider(&server);
    let (_url, mut ctx) = begin_grant(&provider, &[], &MockRng::new(1)).expect("begin_grant");
    ctx.state = String::new();

    let err = complete_grant(&provider, &ctx, "code", "", &reqwest::Client::new())
        .await
        .expect_err("an empty state checks nothing");

    assert!(matches!(err, DelegatedError::StateMismatch), "got {err:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_non_bearer_token_is_not_handed_out_as_a_bearer_string() {
    let server = MockServer::start().await;
    let provider = provider(&server);
    let mut credential = stored(&provider, &[], "DPoP");
    credential.expires_at = Some(t0() + chrono::Duration::hours(1));
    let (session, ..) = session_over(provider, credential).await;

    let err = session.get_access_token().await.expect_err("DPoP token");

    assert!(
        matches!(&err, DelegatedError::UnsupportedTokenType(t) if t == "DPoP"),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_refresh_that_returns_a_non_bearer_token_is_refused() {
    let server = MockServer::start().await;
    respond(
        &server,
        200,
        br#"{"access_token":"bound","expires_in":3600,"token_type":"DPoP"}"#.to_vec(),
    )
    .await;
    let provider = provider(&server);
    let (session, ..) = session_over(provider.clone(), stored(&provider, &[], "Bearer")).await;

    let err = session.get_access_token().await.expect_err("DPoP refresh");

    assert!(
        matches!(err, DelegatedError::UnsupportedTokenType(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn bearer_is_matched_case_insensitively() {
    let server = MockServer::start().await;
    let provider = provider(&server);
    let mut credential = stored(&provider, &[], "bearer");
    credential.expires_at = Some(t0() + chrono::Duration::hours(1));
    let (session, ..) = session_over(provider, credential).await;

    assert_eq!(session.get_access_token().await.expect("token"), "stale");
}

#[tokio::test]
async fn a_huge_error_body_is_cut_to_one_kib_in_the_error() {
    let server = MockServer::start().await;
    respond(&server, 500, vec![b'x'; 10 * 1024 * 1024]).await;

    let err = grant(&server).await.expect_err("500");

    let DelegatedError::TokenEndpoint { status, body } = err else {
        panic!("expected TokenEndpoint, got {err:?}");
    };
    assert_eq!(status, 500);
    assert!(
        body.len() <= 1024 + "…[truncated]".len(),
        "body held {} bytes",
        body.len()
    );
    assert!(body.ends_with("…[truncated]"));
}

#[tokio::test]
async fn a_short_error_body_is_kept_whole() {
    let server = MockServer::start().await;
    respond(&server, 500, b"upstream broke".to_vec()).await;

    let err = grant(&server).await.expect_err("500");

    let DelegatedError::TokenEndpoint { body, .. } = err else {
        panic!("expected TokenEndpoint, got {err:?}");
    };
    assert_eq!(body, "upstream broke");
}

#[tokio::test]
async fn a_one_mib_success_body_is_refused() {
    let server = MockServer::start().await;
    let mut body = br#"{"access_token":"t","pad":""#.to_vec();
    body.extend(std::iter::repeat_n(b'a', 1024 * 1024));
    body.extend_from_slice(br#""}"#);
    respond(&server, 200, body).await;

    let err = grant(&server).await.expect_err("oversized");

    assert!(
        matches!(err, DelegatedError::MalformedResponse(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_success_body_at_the_cap_is_read() {
    let server = MockServer::start().await;
    let prefix = br#"{"access_token":"t","pad":""#;
    let suffix = br#""}"#;
    let mut body = prefix.to_vec();
    body.extend(std::iter::repeat_n(
        b'a',
        crate::delegated::body::MAX_SUCCESS_BODY_BYTES - prefix.len() - suffix.len(),
    ));
    body.extend_from_slice(suffix);
    assert_eq!(body.len(), crate::delegated::body::MAX_SUCCESS_BODY_BYTES);
    respond(&server, 200, body).await;

    grant(&server)
        .await
        .expect("a body of exactly the cap is read");
}
