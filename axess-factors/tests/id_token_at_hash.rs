#![cfg(feature = "oauth")]
//! The `at_hash` of an ID token is checked against the access token the
//! same response carries (OpenID Connect Core 1.0 section 3.1.3.6): a
//! response whose access token is not the one the ID token was issued
//! with is refused, and one whose hash matches is accepted.

use axess_clock::Clock as _;
use axess_clock::testing::MockClock;
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::{OAuthError, OAuthProvider, OAuthProviderConfig};
use axess_testing::oauth_wiremock::{oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CLIENT_ID: &str = "client";
const ISSUED_ACCESS_TOKEN: &str = "access-token-issued-with-the-id-token";
const SWAPPED_ACCESS_TOKEN: &str = "access-token-from-another-response";

/// The `at_hash` of `access_token` under RS256: the left half of its
/// SHA-256 digest, base64url without padding.
fn at_hash(access_token: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

fn id_token(
    issuer: &str,
    now: i64,
    kid: &str,
    private_der: &[u8],
    at_hash: Option<&str>,
) -> String {
    let mut claims = json!({
        "iss": issuer,
        "sub": "user-1",
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "nonce": "n-1",
    });
    if let Some(hash) = at_hash {
        claims["at_hash"] = json!(hash);
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    axess_factors::jwt::encode(&header, &claims, &EncodingKey::from_rsa_der(private_der))
        .expect("JWT encode")
}

/// Exchange a code at a loopback identity provider whose token response
/// carries [`ISSUED_ACCESS_TOKEN`] and an ID token whose `at_hash` is
/// `hashed`'s, or none.
async fn exchange(hashed: Option<&str>) -> Result<(), OAuthError> {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let (private_der, jwk, kid) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let clock = MockClock::at_reference();
    let provider = OAuthProviderConfig::discover_screened(
        "idp",
        &issuer,
        CLIENT_ID,
        "secret",
        "https://rp.example/callback",
        EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .expect("discovery")
    .with_clock(Arc::new(clock.clone()))
    .without_dpop()
    .build()
    .expect("build");

    let hash = hashed.map(at_hash);
    let token = id_token(
        &issuer,
        clock.now().unix_seconds(),
        &kid,
        &private_der,
        hash.as_deref(),
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ISSUED_ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": token,
        })))
        .mount(&server)
        .await;

    provider
        .exchange_code("code", "verifier".to_string(), "n-1".to_string(), None)
        .await
        .map(|claims| assert_eq!(claims.subject, "user-1"))
}

#[tokio::test]
async fn an_id_token_whose_at_hash_is_of_the_access_token_sent_is_accepted() {
    exchange(Some(ISSUED_ACCESS_TOKEN))
        .await
        .expect("the hash is of the access token the response carries");
}

#[tokio::test]
async fn an_id_token_whose_at_hash_is_of_another_access_token_is_refused() {
    let err = exchange(Some(SWAPPED_ACCESS_TOKEN))
        .await
        .expect_err("the access token is not the one the ID token was issued with");
    assert!(
        matches!(&err, OAuthError::IdTokenValidation(reason) if reason.contains("at_hash")),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_id_token_without_at_hash_is_not_held_to_one() {
    exchange(None)
        .await
        .expect("no at_hash: the response is read as before");
}
