//! The refresh-token exchange against a wiremock IdP: an ID token is optional
//! (OIDC Core 12.2) and its nonce, when present, must be the original one.
//!
//! Run with: `cargo test -p axess-core --features testing-oauth,jwt-rust-crypto --test oauth_refresh_outcome`

#![cfg(feature = "testing-oauth")]

use axess_core::testing::oauth_wiremock::{
    oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints, oauth_setup_provider,
};
use axess_factors::oauth::{OAuthError, OAuthProvider, OAuthProviderConfig};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct Idp {
    server: MockServer,
    der: Vec<u8>,
    kid: String,
    provider: OAuthProviderConfig,
}

async fn idp() -> Idp {
    let server = MockServer::start().await;
    let (der, jwk, kid) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = oauth_setup_provider(&server).await;
    Idp {
        server,
        der,
        kid,
        provider,
    }
}

impl Idp {
    fn id_token(&self, nonce: Option<&str>) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({
            "iss": self.server.uri(),
            "sub": "alice",
            "aud": "test-client-id",
            "iat": now,
            "exp": now + 600,
        });
        if let Some(n) = nonce {
            claims["nonce"] = json!(n);
        }
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        axess_factors::jwt::ensure_crypto_provider();
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_rsa_der(&self.der)).unwrap()
    }

    async fn respond(&self, body: serde_json::Value) {
        self.server.reset().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&self.server)
            .await;
    }
}

/// A refresh response with no ID token is a success carrying the rotated
/// refresh token, not an error that drops it: the IdP has already spent the
/// token that was sent.
#[tokio::test]
async fn a_refresh_response_without_an_id_token_returns_the_rotated_tokens() {
    let idp = idp().await;
    idp.respond(json!({
        "access_token": "at2", "token_type": "Bearer", "expires_in": 600,
        "refresh_token": "rt2",
    }))
    .await;

    let outcome = idp
        .provider
        .refresh_token("rt1", Some("n1"))
        .await
        .expect("no ID token is not a failure");
    assert!(outcome.id_token_claims.is_none());
    assert_eq!(&*outcome.refresh_token, "rt2");
    assert_eq!(&*outcome.access_token, "at2");
    assert_eq!(outcome.expires_in, Some(600));
}

/// Without a rotated token in the response the token that was sent stays.
#[tokio::test]
async fn the_sent_refresh_token_is_returned_when_the_idp_does_not_rotate() {
    let idp = idp().await;
    idp.respond(json!({ "access_token": "at2", "token_type": "Bearer", "expires_in": 60 }))
        .await;
    let outcome = idp.provider.refresh_token("rt1", None).await.unwrap();
    assert_eq!(&*outcome.refresh_token, "rt1");
}

/// OIDC Core 12.2: a nonce in a refresh ID token must equal the original; a
/// missing one is accepted.
#[tokio::test]
async fn the_refresh_id_token_nonce_must_be_the_original_when_present() {
    let idp = idp().await;
    let respond_with = |nonce: Option<&str>| {
        json!({
            "access_token": "at2", "token_type": "Bearer", "expires_in": 60,
            "refresh_token": "rt2", "id_token": idp.id_token(nonce),
        })
    };

    idp.respond(respond_with(Some("evil"))).await;
    let err = idp
        .provider
        .refresh_token("rt1", Some("n1"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, OAuthError::IdTokenValidation(_)),
        "got {err:?}"
    );

    // A nonce with no original to compare it to is refused too.
    let err = idp.provider.refresh_token("rt1", None).await.unwrap_err();
    assert!(
        matches!(err, OAuthError::IdTokenValidation(_)),
        "got {err:?}"
    );

    idp.respond(respond_with(Some("n1"))).await;
    let ok = idp.provider.refresh_token("rt1", Some("n1")).await.unwrap();
    assert_eq!(ok.id_token_claims.unwrap().subject, "alice");

    idp.respond(respond_with(None)).await;
    let ok = idp.provider.refresh_token("rt1", Some("n1")).await.unwrap();
    assert_eq!(ok.id_token_claims.unwrap().subject, "alice");
}
