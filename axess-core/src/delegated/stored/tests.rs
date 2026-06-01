//! Phase 5a: tests for the stored-delegation flow.
//!
//! `wiremock` stands up the IdP's authorization + token endpoints.
//! `MemoryDelegatedCredentialStore` exercises the persistence
//! contract end-to-end. `MockClock` makes the refresh-before-expiry
//! decision deterministic.

use super::*;
use axess_clock::testing::MockClock;
use axess_identity::{TenantId, UserId};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::sync::Arc;
use url::Url;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).expect("fixed t0")
}

fn sample_tenant() -> TenantId {
    TenantId::from_bytes([1u8; 16])
}

fn sample_user() -> UserId {
    UserId::from_bytes([2u8; 16])
}

fn build_provider(server_uri: &str) -> Arc<DelegatedProvider> {
    Arc::new(
        DelegatedProvider::new(
            "test-provider",
            Url::parse(&format!("{server_uri}/oauth2/authorize")).unwrap(),
            Url::parse(&format!("{server_uri}/oauth2/token")).unwrap(),
            "axess-client-id",
            "axess-secret",
            Url::parse("https://gnomes.local/callback").unwrap(),
        )
        .with_default_scopes(["mail.read", "mail.send"]),
    )
}

#[test]
fn begin_grant_produces_well_formed_authorization_url() {
    let server_uri = "https://idp.example";
    let provider = build_provider(server_uri);
    let (url, context) = begin_grant(&provider, &[]).expect("begin_grant");

    // The URL must point at the configured authorization endpoint
    // and carry every RFC 6749 + RFC 7636 required param.
    assert_eq!(url.host_str(), Some("idp.example"));
    assert_eq!(url.path(), "/oauth2/authorize");
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(
        q.get("client_id").map(String::as_str),
        Some("axess-client-id")
    );
    assert_eq!(
        q.get("redirect_uri").map(String::as_str),
        Some("https://gnomes.local/callback")
    );
    assert_eq!(
        q.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert!(q.contains_key("code_challenge"));
    assert_eq!(q.get("state").map(String::as_str), Some(&context.state[..]));
    // Default scopes from the provider config.
    assert_eq!(
        q.get("scope").map(String::as_str),
        Some("mail.read mail.send")
    );
}

#[test]
fn begin_grant_respects_scope_override() {
    let provider = build_provider("https://idp.example");
    let (url, _ctx) =
        begin_grant(&provider, &["calendar.events".to_string()]).expect("begin_grant");
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(
        q.get("scope").map(String::as_str),
        Some("calendar.events"),
        "override must replace default scopes"
    );
}

#[tokio::test]
async fn complete_grant_exchanges_code_for_credential() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=auth-code-42"))
        .and(body_string_contains("code_verifier="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-access",
            "refresh_token": "tok-refresh",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "mail.read",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server.uri());
    let (_url, ctx) = begin_grant(&provider, &[]).expect("begin_grant");

    let http = reqwest::Client::new();
    let cred = complete_grant(&provider, &ctx, "auth-code-42", &ctx.state, &http)
        .await
        .expect("complete_grant");
    assert_eq!(cred.provider, "test-provider");
    assert_eq!(&*cred.access_token, "tok-access");
    assert_eq!(cred.refresh_token.as_deref(), Some("tok-refresh"));
    assert_eq!(cred.scopes, vec!["mail.read".to_string()]);
    assert!(cred.expires_at.is_some());
}

#[tokio::test]
async fn complete_grant_rejects_state_mismatch() {
    let server = MockServer::start().await;
    // No mock mounted; `complete_grant` must reject before any HTTP
    // call lands.
    let provider = build_provider(&server.uri());
    let (_url, ctx) = begin_grant(&provider, &[]).expect("begin_grant");

    let http = reqwest::Client::new();
    let err = complete_grant(&provider, &ctx, "code", "WRONG-STATE", &http)
        .await
        .expect_err("state mismatch must reject");
    assert!(
        matches!(err, crate::delegated::error::DelegatedError::StateMismatch),
        "expected StateMismatch, got {err:?}"
    );
    // Confirm no HTTP call was made.
    let received = server.received_requests().await.expect("rcv");
    assert!(received.is_empty(), "state mismatch must short-circuit");
}

#[tokio::test]
async fn complete_grant_surfaces_token_endpoint_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_request",
            "error_description": "missing client_id",
        })))
        .mount(&server)
        .await;
    let provider = build_provider(&server.uri());
    let (_url, ctx) = begin_grant(&provider, &[]).expect("begin_grant");

    let http = reqwest::Client::new();
    let err = complete_grant(&provider, &ctx, "code", &ctx.state, &http)
        .await
        .expect_err("400 must propagate");
    match err {
        crate::delegated::error::DelegatedError::TokenEndpoint { status, .. } => {
            assert_eq!(status, 400);
        }
        other => panic!("expected TokenEndpoint, got {other:?}"),
    }
}

#[tokio::test]
async fn memory_store_round_trips_credential() {
    let store = MemoryDelegatedCredentialStore::new();
    let tenant = sample_tenant();
    let user = sample_user();
    let credential = StoredDelegation {
        provider: "gmail".to_string(),
        access_token: "tok".into(),
        refresh_token: Some("rfr".into()),
        expires_at: Some(t0() + chrono::Duration::hours(1)),
        scopes: vec!["mail.read".to_string()],
        token_type: "Bearer".to_string(),
    };
    store
        .save(&tenant, &user, credential.clone())
        .await
        .expect("save");
    let loaded = store
        .load(&tenant, &user, "gmail")
        .await
        .expect("load")
        .expect("present");
    assert_eq!(&*loaded.access_token, "tok");
    assert_eq!(loaded.refresh_token.as_deref(), Some("rfr"));
    store.revoke(&tenant, &user, "gmail").await.expect("revoke");
    let after = store.load(&tenant, &user, "gmail").await.expect("load2");
    assert!(after.is_none(), "revoke must remove the record");
}

#[tokio::test]
async fn session_returns_fresh_token_from_store() {
    let server = MockServer::start().await;
    let provider = build_provider(&server.uri());
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    let tenant = sample_tenant();
    let user = sample_user();

    let credential = StoredDelegation {
        provider: provider.name.clone(),
        access_token: "fresh-token".into(),
        refresh_token: Some("rfr".into()),
        expires_at: Some(t0() + chrono::Duration::hours(1)),
        scopes: vec![],
        token_type: "Bearer".to_string(),
    };
    store.save(&tenant, &user, credential).await.expect("save");

    let clock = Arc::new(MockClock::at(t0()));
    let session =
        StoredDelegationSession::new(provider, store.clone(), tenant, user).with_clock(clock);
    let token = session.get_access_token().await.expect("token");
    assert_eq!(token, "fresh-token");
    // No HTTP call should have happened; fresh token in store.
    assert!(
        server.received_requests().await.expect("rcv").is_empty(),
        "fresh cache must skip refresh"
    );
}

#[tokio::test]
async fn session_not_connected_when_store_empty() {
    let server = MockServer::start().await;
    let provider = build_provider(&server.uri());
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    let session = StoredDelegationSession::new(provider, store, sample_tenant(), sample_user());
    let err = session
        .get_access_token()
        .await
        .expect_err("no record → NotConnected");
    assert!(
        matches!(err, crate::delegated::error::DelegatedError::NotConnected),
        "expected NotConnected, got {err:?}"
    );
}

#[tokio::test]
async fn session_refreshes_expired_access_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=existing-refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "refreshed-access",
            "refresh_token": "rotated-refresh",
            "expires_in": 3600,
            "token_type": "Bearer",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server.uri());
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    let tenant = sample_tenant();
    let user = sample_user();

    // Seed with a credential that's already expired.
    let credential = StoredDelegation {
        provider: provider.name.clone(),
        access_token: "stale".into(),
        refresh_token: Some("existing-refresh".into()),
        expires_at: Some(t0() - chrono::Duration::seconds(60)),
        scopes: vec![],
        token_type: "Bearer".to_string(),
    };
    store.save(&tenant, &user, credential).await.expect("save");

    let clock = Arc::new(MockClock::at(t0()));
    let session = StoredDelegationSession::new(provider.clone(), store.clone(), tenant, user)
        .with_clock(clock);
    let token = session
        .get_access_token()
        .await
        .expect("must refresh + return new token");
    assert_eq!(token, "refreshed-access");

    // Refreshed credential must have been persisted with the rotated
    // refresh token.
    let after = store
        .load(&tenant, &user, &provider.name)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(&*after.access_token, "refreshed-access");
    assert_eq!(after.refresh_token.as_deref(), Some("rotated-refresh"));
}

#[tokio::test]
async fn session_preserves_refresh_token_when_idp_omits_it() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "refreshed-access",
            "expires_in": 3600,
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server.uri());
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    let tenant = sample_tenant();
    let user = sample_user();
    let credential = StoredDelegation {
        provider: provider.name.clone(),
        access_token: "stale".into(),
        refresh_token: Some("original-refresh".into()),
        expires_at: Some(t0() - chrono::Duration::seconds(60)),
        scopes: vec![],
        token_type: "Bearer".to_string(),
    };
    store.save(&tenant, &user, credential).await.expect("save");

    let clock = Arc::new(MockClock::at(t0()));
    let session = StoredDelegationSession::new(provider.clone(), store.clone(), tenant, user)
        .with_clock(clock);
    let _ = session.get_access_token().await.expect("refresh");

    let after = store
        .load(&tenant, &user, &provider.name)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(
        after.refresh_token.as_deref(),
        Some("original-refresh"),
        "IdP omitted refresh_token in response → original must persist"
    );
}

#[tokio::test]
async fn session_surfaces_refresh_rejected_on_invalid_grant() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "user revoked",
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server.uri());
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    let tenant = sample_tenant();
    let user = sample_user();
    let credential = StoredDelegation {
        provider: provider.name.clone(),
        access_token: "stale".into(),
        refresh_token: Some("rejected".into()),
        expires_at: Some(t0() - chrono::Duration::seconds(60)),
        scopes: vec![],
        token_type: "Bearer".to_string(),
    };
    store.save(&tenant, &user, credential).await.expect("save");

    let clock = Arc::new(MockClock::at(t0()));
    let session = StoredDelegationSession::new(provider, store, tenant, user).with_clock(clock);
    let err = session
        .get_access_token()
        .await
        .expect_err("invalid_grant → RefreshRejected");
    assert!(
        matches!(
            err,
            crate::delegated::error::DelegatedError::RefreshRejected
        ),
        "expected RefreshRejected, got {err:?}"
    );
}
