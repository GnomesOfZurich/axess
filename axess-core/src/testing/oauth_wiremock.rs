//! OIDC test fixture against `wiremock`: mounts a discovery document, a JWKS
//! endpoint, and gives the caller everything needed to drive an
//! [`OAuthProviderConfig`](axess_factors::oauth::OAuthProviderConfig) end-to-end without external infrastructure.
//!
//! Adopters writing integration tests for code that depends on
//! [`AuthnService::begin_oauth_login`](crate::authn::service::AuthnService)
//! / `finish_oauth_login` / `complete_oauth_login` can spin up an
//! in-process IdP that returns canned responses, exercise the real OIDC
//! discovery + PKCE + state machinery, and assert on the result without
//! touching Keycloak / Auth0 / Cognito.
//!
//! Gated behind the `testing-oauth` feature (pulls in `wiremock` + `rsa`).
//!
//! ## Typical usage
//!
//! ```ignore
//! use axess_core::testing::oauth_wiremock::{
//!     oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints, oauth_setup_provider,
//! };
//! use wiremock::MockServer;
//!
//! let server = MockServer::start().await;
//! let (_private_der, jwk, _kid) = oauth_generate_rsa_keypair();
//! oauth_mount_oidc_endpoints(&server, &jwk).await;
//! let provider = oauth_setup_provider(&server).await;
//! // ... drive begin_oauth_login(&provider, ...) against the wiremock IdP ...
//! ```

use axess_factors::oauth::OAuthProviderConfig;

/// Build an OIDC discovery document for the given issuer. The shape covers
/// the discovery fields axess actually reads; it is not a complete
/// rfc8414 metadata response.
pub fn oauth_discovery_document(issuer: &str) -> serde_json::Value {
    serde_json::json!({
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

/// Generate an RSA-2048 key pair, returning `(private DER bytes, public JWK
/// JSON, kid)`. The kid is a stable label (`"test-key-1"`) so callers can
/// re-mint tokens with the same id across requests. The private DER is the
/// PKCS#1-shape blob `jsonwebtoken::EncodingKey::from_rsa_der` expects.
pub fn oauth_generate_rsa_keypair() -> (Vec<u8>, serde_json::Value, String) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};

    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = private_key.to_public_key();

    let kid = "test-key-1".to_string();
    let private_der = private_key.to_pkcs1_der().unwrap().as_bytes().to_vec();

    let jwk = serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
    });

    (private_der, jwk, kid)
}

/// Mount OIDC discovery + JWKS on the given wiremock server. After this
/// returns, `GET {server.uri()}/.well-known/openid-configuration` and
/// `GET {server.uri()}/jwks` resolve. Caller is responsible for mounting
/// `/token` / `/authorize` / `/userinfo` etc. for the specific flow under
/// test.
pub async fn oauth_mount_oidc_endpoints(server: &wiremock::MockServer, jwk: &serde_json::Value) {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };
    let issuer = server.uri();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oauth_discovery_document(&issuer)))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "keys": [jwk] })),
        )
        .mount(server)
        .await;
}

/// Run OIDC discovery against the given wiremock server and return a
/// configured [`OAuthProviderConfig`] pointed at it. Uses stable test
/// values for the client id (`"test-client-id"`), secret (`"test-secret"`),
/// and redirect URI (`"http://localhost:3000/callback"`).
pub async fn oauth_setup_provider(server: &wiremock::MockServer) -> OAuthProviderConfig {
    OAuthProviderConfig::discover(
        "test",
        &server.uri(),
        "test-client-id",
        "test-secret",
        "http://localhost:3000/callback",
    )
    .await
    .expect("OIDC discovery should succeed")
}
