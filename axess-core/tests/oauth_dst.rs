//! The OAuth flow takes its time and its randomness from injected sources.
//!
//! Time: both token paths that carry `exp` are covered: the back-channel logout
//! JWT (verified by axess against the cached JWKS) and the ID token
//! (verified inside `openidconnect`). Every token here is minted around a
//! mock instant years in the past, so a verifier that read the wall clock
//! would refuse all of them.
//!
//! Run with: `cargo test -p axess-core --features testing-oauth,jwt-rust-crypto --test oauth_dst`

#![cfg(feature = "testing-oauth")]

use axess_clock::testing::MockClock;
use axess_core::testing::oauth_wiremock::{
    oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints, oauth_setup_provider,
};
use axess_factors::oauth::{OAuthError, OAuthProvider};
use axess_rng::{SecureRng, testing::MockRng};
use chrono::TimeZone;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use std::sync::Arc;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// 2020-09-13T12:26:40Z.
const MOCK_EPOCH: i64 = 1_600_000_000;

fn mock_clock() -> Arc<MockClock> {
    Arc::new(MockClock::at(
        chrono::Utc.timestamp_opt(MOCK_EPOCH, 0).unwrap(),
    ))
}

fn sign(private_der: &[u8], kid: &str, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    axess_factors::jwt::ensure_crypto_provider();
    jsonwebtoken::encode(&header, claims, &EncodingKey::from_rsa_der(private_der))
        .expect("JWT encode")
}

#[tokio::test]
async fn logout_jwt_exp_follows_the_injected_clock() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let (private_der, jwk, kid) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let clock = mock_clock();
    let provider = oauth_setup_provider(&server)
        .await
        .with_clock(clock.clone());

    let token = sign(
        &private_der,
        &kid,
        &json!({
            "iss": issuer,
            "aud": "test-client-id",
            "iat": MOCK_EPOCH,
            "exp": MOCK_EPOCH + 120,
            "jti": "logout-1",
            "sub": "user-123",
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        }),
    );

    provider
        .verify_logout_jwt(&token)
        .expect("inside its life on the injected clock");

    clock.advance_secs(120 + 61);
    let err = provider
        .verify_logout_jwt(&token)
        .expect_err("past exp plus leeway on the injected clock");
    assert!(
        matches!(&err, OAuthError::IdTokenValidation(m) if m.contains("token expired")),
        "got {err:?}"
    );
}

async fn exchange_with(clock: Option<Arc<MockClock>>) -> Result<(), OAuthError> {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let (private_der, jwk, kid) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let mut provider = oauth_setup_provider(&server).await;
    if let Some(clock) = clock {
        provider = provider.with_clock(clock);
    }

    let id_token = sign(
        &private_der,
        &kid,
        &json!({
            "iss": issuer,
            "sub": "alice",
            "aud": "test-client-id",
            "iat": MOCK_EPOCH,
            "exp": MOCK_EPOCH + 3600,
            "nonce": "n-1",
        }),
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        })))
        .mount(&server)
        .await;

    provider
        .exchange_code("code", "verifier".to_string(), "n-1".to_string())
        .await
        .map(|_| ())
}

#[tokio::test]
async fn id_token_exp_follows_the_injected_clock() {
    exchange_with(Some(mock_clock()))
        .await
        .expect("an ID token inside its life on the injected clock is accepted");

    let err = exchange_with(None)
        .await
        .expect_err("the same token is long expired on the system clock");
    assert!(
        matches!(err, OAuthError::IdTokenValidation(_)),
        "got {err:?}"
    );
}

/// Base64url of the next 32-byte draw, as the ceremony encodes each secret.
fn next_secret(rng: &MockRng) -> String {
    use base64::Engine as _;
    let mut raw = [0u8; 32];
    rng.fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

async fn begin_with_seed(seed: u64) -> (url::Url, String, String) {
    use axess_core::authn::service::AuthnService;
    use axess_core::testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    };

    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = oauth_setup_provider(&server).await;
    let authn = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(provider)
        .with_rng(MockRng::new(seed))
        .build();
    let session = test_session();
    let (url, state) = authn
        .begin_oauth_login("test", &Default::default(), &session)
        .await
        .expect("begin");
    let nonce = session
        .get_custom("axess.oauth.nonce")
        .await
        .and_then(|v| v.as_str().map(String::from))
        .expect("nonce");
    // The server's port differs between runs; keep only what the RNG decides.
    (url, state, nonce)
}

#[tokio::test]
async fn pkce_state_and_nonce_come_from_the_service_rng() {
    let (url, state, nonce) = begin_with_seed(42).await;

    let reference = MockRng::new(42);
    let verifier = next_secret(&reference);
    let expected_state = next_secret(&reference);
    let expected_nonce = next_secret(&reference);
    assert_eq!(state, expected_state);
    assert_eq!(nonce, expected_nonce);

    use base64::Engine as _;
    use sha2::Digest;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["state"], expected_state);
    assert_eq!(query["nonce"], expected_nonce);
    assert_eq!(query["code_challenge"], challenge);

    let (_, other_state, _) = begin_with_seed(43).await;
    assert_ne!(state, other_state);
}

#[cfg(feature = "fapi")]
#[tokio::test]
async fn dpop_iat_and_jti_come_from_the_service_clock_and_rng() {
    use axess_core::authn::service::AuthnService;
    use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
    use base64::Engine as _;

    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = oauth_setup_provider(&server).await;
    let clock = mock_clock();
    let authn = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(provider)
        .with_rng(MockRng::new(5))
        .with_clock(MockClock::clone(&clock))
        .build();

    // The key is drawn once, from the service's rng; each proof then draws
    // only its `jti`.
    let key = authn.new_dpop_key();
    let proof = |c: &str| {
        authn
            .generate_dpop_proof("test", &key, "GET", "https://rs.example/x", Some(c))
            .expect("proof")
    };
    let payload = |jwt: &str| -> serde_json::Value {
        let part = jwt.split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    };

    let first = payload(&proof("at-1").proof_jwt);
    clock.advance_secs(30);
    let second = payload(&proof("at-1").proof_jwt);

    assert_eq!(first["iat"], MOCK_EPOCH);
    assert_eq!(second["iat"], MOCK_EPOCH + 30);

    // The key takes the first 32 bytes; each proof then takes 16 `jti` bytes.
    let reference = MockRng::new(5);
    let mut seed = [0u8; 32];
    reference.fill_bytes(&mut seed);
    assert_eq!(
        key.thumbprint().unwrap(),
        axess_factors::oauth::DpopKey::from_seed(seed)
            .thumbprint()
            .unwrap()
    );
    let mut jti = [0u8; 16];
    reference.fill_bytes(&mut jti);
    assert_eq!(
        first["jti"].as_str().unwrap(),
        uuid::Builder::from_random_bytes(jti)
            .into_uuid()
            .to_string()
    );
    assert_ne!(first["jti"], second["jti"]);
}

async fn authn_with(
    provider: axess_factors::oauth::OAuthProviderConfig,
) -> axess_core::authn::service::AuthnService<
    axess_core::testing::mock_authn::MockIdentityStore,
    axess_core::testing::mock_authn::MockFactorStore,
> {
    use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
    axess_core::authn::service::AuthnService::builder(
        MockIdentityStore::new(),
        MockFactorStore::new(),
    )
    .with_oauth_provider(provider)
    .build()
}

async fn jwks_requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("recording is on")
        .iter()
        .filter(|r| r.url.path() == "/jwks")
        .count()
}

/// `refresh_all_jwks` runs one pass with no timer, and the provider's
/// debounce is measured on the provider's injected clock.
#[tokio::test]
async fn refresh_all_jwks_follows_the_provider_clock() {
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let clock = mock_clock();
    let provider = oauth_setup_provider(&server)
        .await
        .with_clock(clock.clone());
    let authn = authn_with(provider).await;
    let at_discovery = jwks_requests(&server).await;

    assert!(authn.refresh_all_jwks().await.is_empty());
    assert_eq!(jwks_requests(&server).await, at_discovery + 1);

    assert!(authn.refresh_all_jwks().await.is_empty());
    assert_eq!(
        jwks_requests(&server).await,
        at_discovery + 1,
        "inside the debounce window the second pass fetches nothing"
    );

    clock.advance_secs(61);
    assert!(authn.refresh_all_jwks().await.is_empty());
    assert_eq!(jwks_requests(&server).await, at_discovery + 2);
}

#[tokio::test]
async fn refresh_all_jwks_reports_the_failing_provider() {
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = oauth_setup_provider(&server).await;
    let authn = authn_with(provider).await;

    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let failures = authn.refresh_all_jwks().await;
    assert_eq!(failures.len(), 1);
    assert_eq!(&*failures[0].0, "test");
}

fn long_lived_logout_jwt(private_der: &[u8], kid: &str, issuer: &str) -> String {
    sign(
        private_der,
        kid,
        &json!({
            "iss": issuer,
            "aud": "test-client-id",
            "iat": MOCK_EPOCH,
            "exp": MOCK_EPOCH + 48 * 3600,
            "jti": "logout-age",
            "sub": "user-123",
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        }),
    )
}

/// A key set fetched at T verifies a logout JWT at T + 23 h and is refused
/// at T + 25 h, with a token that is itself still valid, until a refresh
/// succeeds.
#[tokio::test]
async fn cached_jwks_expire_after_the_maximum_age() {
    let server = MockServer::start().await;
    let (private_der, jwk, kid) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let clock = mock_clock();
    let provider = oauth_setup_provider(&server)
        .await
        .with_clock(clock.clone());
    let token = long_lived_logout_jwt(&private_der, &kid, &server.uri());

    clock.advance_secs(23 * 3600);
    provider
        .verify_logout_jwt(&token)
        .expect("a 23 hour old key set still verifies");

    clock.advance_secs(2 * 3600);
    let err = provider
        .verify_logout_jwt(&token)
        .expect_err("a 25 hour old key set is refused");
    assert!(matches!(err, OAuthError::JwksExpired), "got {err:?}");

    provider.refresh_jwks().await.expect("refresh");
    provider
        .verify_logout_jwt(&token)
        .expect("verifies again after the fetch");
}

/// The builder starts the refresh loop, keeps the cached keys current, and
/// the loop ends with the last clone of the service.
#[tokio::test]
async fn builder_started_refresh_loop_runs_and_stops_with_the_service() {
    use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = oauth_setup_provider(&server).await;
    let at_discovery = jwks_requests(&server).await;

    let authn = axess_core::authn::service::AuthnService::builder(
        MockIdentityStore::new(),
        MockFactorStore::new(),
    )
    .with_oauth_provider(provider)
    .with_jwks_refresh(std::time::Duration::from_millis(30))
    .build();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        jwks_requests(&server).await > at_discovery,
        "the loop fetched the key set"
    );

    drop(authn);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let after_drop = jwks_requests(&server).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        jwks_requests(&server).await,
        after_drop,
        "no fetches once the service is dropped"
    );
}

// ── ID tokens verify against the refreshable key set ─────────────────────────

fn id_token_with_exp(private_der: &[u8], kid: &str, issuer: &str, exp: i64) -> String {
    sign(
        private_der,
        kid,
        &json!({
            "iss": issuer,
            "sub": "alice",
            "aud": "test-client-id",
            "iat": MOCK_EPOCH,
            "exp": exp,
            "nonce": "n-1",
        }),
    )
}

async fn mount_token_endpoint(server: &MockServer, id_token: &str) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        })))
        .mount(server)
        .await;
}

/// The IdP rotates its signing key after discovery. A token signed with the
/// new key verifies: the provider refreshes the key set on the unknown key
/// and retries, instead of trusting the set parsed at discovery.
#[tokio::test]
async fn id_token_signed_with_a_rotated_key_verifies_after_the_refresh() {
    let server = MockServer::start().await;
    let (_, old_jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &old_jwk).await;
    let provider = oauth_setup_provider(&server).await.with_clock(mock_clock());

    let (new_der, mut new_jwk, _) = oauth_generate_rsa_keypair();
    new_jwk["kid"] = json!("test-key-2");
    server.reset().await;
    oauth_mount_oidc_endpoints(&server, &new_jwk).await;
    let id_token = id_token_with_exp(&new_der, "test-key-2", &server.uri(), MOCK_EPOCH + 3600);
    mount_token_endpoint(&server, &id_token).await;

    let claims = provider
        .exchange_code("code", "verifier".to_string(), "n-1".to_string())
        .await
        .expect("the rotated key is picked up");
    assert_eq!(claims.subject, "alice");
}

/// A token signed with a key the IdP never published is refused even after
/// the refresh.
#[tokio::test]
async fn id_token_signed_with_an_unpublished_key_is_refused_after_one_refresh() {
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = oauth_setup_provider(&server).await.with_clock(mock_clock());
    let (rogue_der, _, _) = oauth_generate_rsa_keypair();
    let id_token = id_token_with_exp(&rogue_der, "rogue", &server.uri(), MOCK_EPOCH + 3600);
    mount_token_endpoint(&server, &id_token).await;
    let before = jwks_requests(&server).await;

    let err = provider
        .exchange_code("code", "verifier".to_string(), "n-1".to_string())
        .await
        .expect_err("no key matches");

    assert!(
        matches!(err, OAuthError::IdTokenValidation(_)),
        "got {err:?}"
    );
    assert_eq!(jwks_requests(&server).await, before + 1, "refreshed once");
}

/// An otherwise valid ID token is refused once the key set is older than
/// `max_age` and the refresh fails, and accepted again after a refresh
/// succeeds.
#[tokio::test]
async fn id_token_is_refused_while_the_key_set_is_expired() {
    let server = MockServer::start().await;
    let (private_der, jwk, kid) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let clock = mock_clock();
    let provider = oauth_setup_provider(&server)
        .await
        .with_clock(clock.clone());
    let id_token = id_token_with_exp(&private_der, &kid, &server.uri(), MOCK_EPOCH + 48 * 3600);
    mount_token_endpoint(&server, &id_token).await;

    clock.advance_secs(23 * 3600);
    provider
        .exchange_code("code", "verifier".to_string(), "n-1".to_string())
        .await
        .expect("a 23 hour old key set verifies");

    clock.advance_secs(2 * 3600);
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(1)
        .mount(&server)
        .await;
    let err = provider
        .exchange_code("code", "verifier".to_string(), "n-1".to_string())
        .await
        .expect_err("a 25 hour old key set with the endpoint down");
    assert!(matches!(err, OAuthError::JwksExpired), "got {err:?}");

    server.reset().await;
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    mount_token_endpoint(&server, &id_token).await;
    clock.advance_secs(6);
    provider
        .exchange_code("code", "verifier".to_string(), "n-1".to_string())
        .await
        .expect("verifies again once a refresh succeeds");
}

/// The refresh-token path verifies its ID token the same way: a rotated key
/// is picked up through a refresh of the key set.
#[tokio::test]
async fn refresh_response_id_token_with_a_rotated_key_verifies() {
    let server = MockServer::start().await;
    let (_, old_jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &old_jwk).await;
    let provider = oauth_setup_provider(&server).await.with_clock(mock_clock());
    let (new_der, mut new_jwk, _) = oauth_generate_rsa_keypair();
    new_jwk["kid"] = json!("test-key-2");
    server.reset().await;
    oauth_mount_oidc_endpoints(&server, &new_jwk).await;
    let id_token = id_token_with_exp(&new_der, "test-key-2", &server.uri(), MOCK_EPOCH + 3600);
    mount_token_endpoint(&server, &id_token).await;

    let outcome = provider
        .refresh_token("refresh-1", Some("n-1"))
        .await
        .expect("the rotated key is picked up on refresh too");
    let claims = outcome
        .id_token_claims
        .expect("the response had an ID token");
    assert_eq!(claims.subject, "alice");
}
