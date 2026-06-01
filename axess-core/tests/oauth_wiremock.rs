//! Full-flow OAuth/OIDC integration test using wiremock.
//!
//! Exercises the real HTTP code path: OIDC discovery → JWKS fetch →
//! begin_oauth_login → finish_oauth_login (token exchange + ID token
//! verification). No external services needed; wiremock serves all endpoints.
//!
//! Run with: `cargo test -p axess-core --features oauth,testing --test oauth_wiremock`

#![cfg(all(feature = "oauth", feature = "testing"))]

mod common;

use axess_core::{
    authn::service::AuthnService,
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    },
};
use axess_factors::oauth::{OAuthLoginOptions, OAuthProviderConfig};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{test_tenant, test_user};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Generate an RSA-2048 key pair and return (private DER, JWK public key JSON, kid).
fn generate_rsa_keypair() -> (Vec<u8>, serde_json::Value, String) {
    use rsa::RsaPrivateKey;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
    let public_key = private_key.to_public_key();

    let kid = "test-key-1".to_string();

    // Private key in PKCS#1 DER for jsonwebtoken.
    let private_der = private_key
        .to_pkcs1_der()
        .expect("PKCS1 DER encode")
        .as_bytes()
        .to_vec();

    // Build JWK from the public key components.
    let n_bytes = {
        use rsa::traits::PublicKeyParts;
        public_key.n().to_bytes_be()
    };
    let e_bytes = {
        use rsa::traits::PublicKeyParts;
        public_key.e().to_bytes_be()
    };

    let jwk = json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(&n_bytes),
        "e": URL_SAFE_NO_PAD.encode(&e_bytes),
    });

    (private_der, jwk, kid)
}

/// Build an OIDC discovery document pointing to wiremock endpoints.
fn discovery_document(issuer: &str) -> serde_json::Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "email", "name", "iss", "aud", "exp", "iat", "nonce"],
    })
}

/// Build a signed ID token JWT.
fn build_id_token(
    issuer: &str,
    client_id: &str,
    subject: &str,
    nonce: &str,
    kid: &str,
    private_der: &[u8],
) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": issuer,
        "sub": subject,
        "aud": client_id,
        "exp": now + 3600,
        "iat": now,
        "nonce": nonce,
        "email": "alice@example.com",
        "email_verified": true,
        "name": "Alice Test",
    });

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());

    let key = EncodingKey::from_rsa_der(private_der);
    jsonwebtoken::encode(&header, &claims, &key).expect("JWT encode")
}

/// Full OIDC discovery → provider setup succeeds against wiremock.
#[tokio::test]
async fn oidc_discovery_succeeds() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let (_, jwk, _) = generate_rsa_keypair();

    // Mount discovery endpoint.
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;

    // Mount JWKS endpoint.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;

    let provider = OAuthProviderConfig::discover(
        "test",
        &issuer,
        "test-client-id",
        "test-client-secret",
        "http://localhost:3000/callback",
    )
    .await;

    assert!(provider.is_ok(), "discovery failed: {:?}", provider.err());
}

/// Full flow: discover → begin_oauth_login → finish_oauth_login with signed JWT.
#[tokio::test]
async fn full_oauth_flow_with_signed_id_token() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let client_id = "test-client-id";
    let (private_der, jwk, kid) = generate_rsa_keypair();

    // Mount discovery.
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;

    // Mount JWKS.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;

    // Discover the provider.
    let provider = OAuthProviderConfig::discover(
        "test",
        &issuer,
        client_id,
        "test-secret",
        "http://localhost:3000/callback",
    )
    .await
    .expect("discovery should succeed");

    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(provider);

    let session = test_session();

    // 1. Begin OAuth login; get the authorization URL.
    let (auth_url, _csrf_state) = authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin_oauth_login should succeed");

    // Verify the auth URL points to our mock server.
    assert!(
        auth_url
            .as_str()
            .starts_with(&format!("{issuer}/authorize")),
        "auth URL should point to mock: {auth_url}"
    );

    // 2. Extract the nonce from the session (we need it to build a valid ID token).
    let nonce = session
        .get_custom("axess.oauth.nonce")
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .expect("nonce should be in session");

    let csrf_state = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .expect("CSRF state should be in session");

    // 3. Build a signed ID token.
    let id_token = build_id_token(
        &issuer,
        client_id,
        "alice-subject",
        &nonce,
        &kid,
        &private_der,
    );

    // 4. Mount the token endpoint; returns the signed ID token.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        })))
        .mount(&server)
        .await;

    // 5. Finish the OAuth login with the correct CSRF state and a dummy code.
    let result = authn
        .finish_oauth_login("authorization-code-from-idp", &csrf_state, &session)
        .await;

    match result {
        Ok(claims) => {
            assert_eq!(claims.subject.as_str(), "alice-subject");
            assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        }
        Err(e) => {
            panic!("finish_oauth_login failed: {e:?}");
        }
    }
}

/// Token endpoint returning error should propagate as TokenExchange error.
#[tokio::test]
async fn oauth_token_endpoint_error_propagates() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let (_, jwk, _) = generate_rsa_keypair();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;

    // Token endpoint returns an error.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "authorization code expired"
        })))
        .mount(&server)
        .await;

    let provider = OAuthProviderConfig::discover(
        "test",
        &issuer,
        "client-id",
        "secret",
        "http://localhost:3000/callback",
    )
    .await
    .unwrap();

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(provider);

    let session = test_session();
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .unwrap();

    let csrf = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap();

    let result = authn
        .finish_oauth_login("expired-code", &csrf, &session)
        .await;
    assert!(result.is_err(), "should fail on token exchange error");
}

/// A 400 response carrying `error: "unsupported_token_type"`
/// (RFC 7009 §2.2.1) maps to the typed `UnsupportedTokenType` variant
/// rather than the catch-all `TokenExchange`.
#[tokio::test]
async fn revoke_unsupported_token_type_maps_to_typed_variant() {
    use axess_factors::oauth::{OAuthError, OAuthProvider};

    let server = MockServer::start().await;
    let issuer = server.uri();
    let (_, jwk, _) = generate_rsa_keypair();

    let mut discovery = discovery_document(&issuer);
    discovery["revocation_endpoint"] = json!(format!("{issuer}/revoke"));

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;

    // RFC 7009: AS rejects with 400 + unsupported_token_type.
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "unsupported_token_type",
        })))
        .mount(&server)
        .await;

    let provider = OAuthProviderConfig::discover(
        "test",
        &issuer,
        "client-id",
        "secret",
        "http://localhost:3000/callback",
    )
    .await
    .unwrap()
    .with_revocation_endpoint(format!("{issuer}/revoke"));

    let err = provider
        .revoke_token("dummy-token", Some("access_token"))
        .await
        .expect_err("revoke must fail on unsupported_token_type");
    assert!(
        matches!(err, OAuthError::UnsupportedTokenType),
        "expected OAuthError::UnsupportedTokenType, got {err:?}"
    );
}

/// A logout JWT signed by a key whose `kid` is not in the
/// cached JWKS produces the typed `OAuthError::UnknownKid(kid)`,
/// not a `Config(...)` string error. The back-channel logout handler
/// pattern-matches on this variant to drive the JWKS-refresh + retry.
#[tokio::test]
async fn unknown_kid_yields_typed_variant() {
    use axess_factors::oauth::{OAuthError, OAuthProvider};

    let server = MockServer::start().await;
    let issuer = server.uri();
    // JWKS publishes "key-1" only.
    let (_, jwk_published, _kid_published) = generate_rsa_keypair();
    // We sign with a different key + a kid the JWKS does NOT carry.
    let (private_unknown, _jwk_unknown, _) = generate_rsa_keypair();
    let kid_unknown = "rotated-but-not-yet-published".to_string();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk_published] })))
        .mount(&server)
        .await;

    let provider = OAuthProviderConfig::discover(
        "test",
        &issuer,
        "client-id",
        "secret",
        "http://localhost:3000/callback",
    )
    .await
    .unwrap();

    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": issuer,
        "aud": "client-id",
        "iat": now,
        "jti": "logout-1",
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        "sub": "user-123",
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid_unknown.clone());
    let key = EncodingKey::from_rsa_der(&private_unknown);
    let token = jsonwebtoken::encode(&header, &claims, &key).expect("JWT encode");

    let err = provider
        .verify_logout_jwt(&token)
        .expect_err("verify must fail on unknown kid");
    match err {
        OAuthError::UnknownKid(kid) => {
            assert_eq!(kid, kid_unknown);
        }
        other => panic!("expected OAuthError::UnknownKid, got {other:?}"),
    }
}

/// A 503 response from the revocation endpoint maps to the
/// typed `TokenEndpointTransient` variant so callers can decide to
/// retry instead of treating it the same as a permanent rejection.
#[tokio::test]
async fn revoke_5xx_maps_to_transient_variant() {
    use axess_factors::oauth::{OAuthError, OAuthProvider};

    let server = MockServer::start().await;
    let issuer = server.uri();
    let (_, jwk, _) = generate_rsa_keypair();

    let mut discovery = discovery_document(&issuer);
    discovery["revocation_endpoint"] = json!(format!("{issuer}/revoke"));

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(
            ResponseTemplate::new(503).set_body_string("upstream temporarily unavailable"),
        )
        .mount(&server)
        .await;

    let provider = OAuthProviderConfig::discover(
        "test",
        &issuer,
        "client-id",
        "secret",
        "http://localhost:3000/callback",
    )
    .await
    .unwrap()
    .with_revocation_endpoint(format!("{issuer}/revoke"));

    let err = provider
        .revoke_token("dummy-token", None)
        .await
        .expect_err("revoke must fail on 5xx");
    match err {
        OAuthError::TokenEndpointTransient { status, body } => {
            assert_eq!(status, 503);
            assert!(body.contains("upstream temporarily unavailable"));
        }
        other => panic!("expected TokenEndpointTransient, got {other:?}"),
    }
}
