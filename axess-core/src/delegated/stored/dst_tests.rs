//! Deterministic tests for the grant flow and the refresh path:
//! injected RNG and clock, and single-flight refresh against a
//! rotating IdP.

use std::sync::{Arc, Mutex};

use axess_clock::testing::MockClock;
use axess_identity::{TenantId, UserId};
use axess_rng::SecureRng;
use axess_rng::testing::MockRng;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::delegated::error::DelegatedError;

fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_500_000_000, 0).expect("fixed t0")
}

fn provider(server_uri: &str) -> Arc<DelegatedProvider> {
    Arc::new(DelegatedProvider::new(
        "dst-provider",
        Url::parse(&format!("{server_uri}/authorize")).unwrap(),
        Url::parse(&format!("{server_uri}/token")).unwrap(),
        "client",
        "secret",
        Url::parse("https://app.example/callback").unwrap(),
    ))
}

fn stale(refresh: &str, provider: &DelegatedProvider) -> StoredDelegation {
    StoredDelegation {
        provider: provider.name.clone(),
        access_token: "stale".into(),
        refresh_token: Some(refresh.into()),
        expires_at: Some(t0() - Duration::seconds(10)),
        scopes: vec![],
        token_type: "Bearer".into(),
    }
}

fn token_body(access: &str, refresh: &str) -> serde_json::Value {
    json!({"access_token": access, "refresh_token": refresh, "expires_in": 3600})
}

#[test]
fn begin_grant_draws_verifier_then_state_from_the_injected_rng() {
    let provider = provider("https://idp.example");
    let (url, ctx) = begin_grant(&provider, &[], &MockRng::new(77)).expect("begin_grant");

    let reference = MockRng::new(77);
    let mut verifier_raw = [0u8; 32];
    let mut state_raw = [0u8; 32];
    reference.fill_bytes(&mut verifier_raw);
    reference.fill_bytes(&mut state_raw);
    let verifier = URL_SAFE_NO_PAD.encode(verifier_raw);
    let state = URL_SAFE_NO_PAD.encode(state_raw);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    assert_eq!(&*ctx.code_verifier, verifier.as_str());
    assert_eq!(ctx.state, state);
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(q.get("state"), Some(&state));
    assert_eq!(q.get("code_challenge"), Some(&challenge));
    assert_eq!(ctx.state.len(), 43);
    assert_ne!(&*ctx.code_verifier, ctx.state.as_str());
}

#[tokio::test]
async fn complete_grant_at_measures_expiry_from_the_supplied_instant() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_body("a", "r")))
        .mount(&server)
        .await;
    let provider = provider(&server.uri());
    let (_url, ctx) = begin_grant(&provider, &[], &MockRng::new(1)).expect("begin_grant");
    let cred = complete_grant_at(
        &provider,
        &ctx,
        "code",
        &ctx.state,
        &reqwest::Client::new(),
        t0(),
    )
    .await
    .expect("complete");
    assert_eq!(cred.expires_at, Some(t0() + Duration::seconds(3600)));
}

#[tokio::test]
async fn complete_grant_rejects_a_state_of_the_same_length_and_a_prefix() {
    let provider = provider("https://idp.example");
    let (_url, ctx) = begin_grant(&provider, &[], &MockRng::new(1)).expect("begin_grant");
    let http = reqwest::Client::new();
    let mut flipped = ctx.state.clone().into_bytes();
    flipped[0] = if flipped[0] == b'A' { b'B' } else { b'A' };
    let flipped = String::from_utf8(flipped).unwrap();
    for bad in [flipped.as_str(), &ctx.state[..ctx.state.len() - 1], ""] {
        let err = complete_grant(&provider, &ctx, "c", bad, &http, &axess_clock::SystemClock)
            .await
            .expect_err("state must match exactly");
        assert!(matches!(err, DelegatedError::StateMismatch), "{bad}");
    }
}

#[tokio::test]
async fn session_refresh_expiry_follows_the_injected_clock() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_body("fresh", "r2")))
        .mount(&server)
        .await;
    let provider = provider(&server.uri());
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    let (tenant, user) = (TenantId::from_bytes([9; 16]), UserId::from_bytes([1; 16]));
    store
        .save(&tenant, &user, stale("r1", &provider))
        .await
        .unwrap();
    let session = StoredDelegationSession::new(provider.clone(), store.clone(), tenant, user)
        .with_clock(Arc::new(MockClock::at(t0())));
    assert_eq!(session.get_access_token().await.unwrap(), "fresh");
    let saved = store
        .load(&tenant, &user, &provider.name)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.expires_at, Some(t0() + Duration::seconds(3600)));
}

/// A rotating IdP: the first redemption of `r1` succeeds, any replay is
/// `invalid_grant`. Eight concurrent callers must produce one POST.
#[tokio::test]
async fn concurrent_refreshes_redeem_a_rotating_token_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=r1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(token_body("fresh", "r2"))
                .set_delay(std::time::Duration::from_millis(150)),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .mount(&server)
        .await;

    let provider = provider(&server.uri());
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    let (tenant, user) = (TenantId::from_bytes([9; 16]), UserId::from_bytes([2; 16]));
    store
        .save(&tenant, &user, stale("r1", &provider))
        .await
        .unwrap();
    let clock = Arc::new(MockClock::at(t0()));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let session = StoredDelegationSession::new(provider.clone(), store.clone(), tenant, user)
            .with_clock(clock.clone());
        tasks.push(tokio::spawn(
            async move { session.get_access_token().await },
        ));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().expect("every caller succeeds"), "fresh");
    }
    let posts = server.received_requests().await.unwrap();
    assert_eq!(posts.len(), 1, "exactly one POST reaches the IdP");
}

/// Store that serves a scripted sequence of loads, standing in for
/// another node rotating the credential mid-refresh.
struct ScriptedStore {
    loads: Mutex<Vec<StoredDelegation>>,
}

impl DelegatedCredentialStore for ScriptedStore {
    async fn load(
        &self,
        _tenant: &TenantId,
        _user: &UserId,
        _provider: &str,
    ) -> Result<Option<StoredDelegation>, String> {
        let mut loads = self.loads.lock().unwrap();
        let next = if loads.len() > 1 {
            loads.remove(0)
        } else {
            loads[0].clone()
        };
        Ok(Some(next))
    }
    async fn save(&self, _: &TenantId, _: &UserId, _: StoredDelegation) -> Result<(), String> {
        Ok(())
    }
    async fn revoke(&self, _: &TenantId, _: &UserId, _: &str) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::test]
async fn rejected_refresh_reloads_and_uses_a_credential_another_node_rotated() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .mount(&server)
        .await;
    let provider = provider(&server.uri());
    let mut rotated = stale("r2", &provider);
    rotated.access_token = "from-other-node".into();
    rotated.expires_at = Some(t0() + Duration::seconds(3600));
    // Loads: initial, after the lock, then after the rejection.
    let store = Arc::new(ScriptedStore {
        loads: Mutex::new(vec![
            stale("r1", &provider),
            stale("r1", &provider),
            rotated,
        ]),
    });
    let session = StoredDelegationSession::new(
        provider,
        store,
        TenantId::from_bytes([9; 16]),
        UserId::from_bytes([3; 16]),
    )
    .with_clock(Arc::new(MockClock::at(t0())));
    assert_eq!(session.get_access_token().await.unwrap(), "from-other-node");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
