#![cfg(feature = "oauth")]
//! The discovery entry points that take no policy run under the default
//! one, `EgressPolicy::screened`, as the OIDC primitives do: the issuer URL,
//! every endpoint the document names and the addresses connected to are
//! screened unless the caller names another policy through the
//! `discover_screened` forms.

use axess_factors::client_assertion::ClientAssertionSigner;
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::OAuthProviderConfig;
use axess_testing::oauth_wiremock::oauth_discovery_document;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REDIRECT: &str = "https://rp.example/callback";

/// An identity provider on loopback, over plain HTTP.
async fn loopback_idp() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(oauth_discovery_document(&server.uri())),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "keys": [] })))
        .mount(&server)
        .await;
    server
}

fn signer() -> ClientAssertionSigner {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    ClientAssertionSigner::new(
        "client",
        jsonwebtoken::EncodingKey::from_ec_der(&key.serialize_der()),
        jsonwebtoken::Algorithm::ES256,
    )
    .expect("the key signs under its algorithm")
}

async fn requests_seen(server: &MockServer) -> usize {
    server.received_requests().await.expect("requests").len()
}

/// `discover` screens the issuer URL under the default policy: a loopback
/// identity provider over plain HTTP is refused by name, before any request.
#[tokio::test]
async fn discover_refuses_a_loopback_issuer_under_its_default_policy() {
    let idp = loopback_idp().await;

    let err = OAuthProviderConfig::discover("idp", &idp.uri(), "client", "secret", REDIRECT)
        .await
        .expect_err("the default policy screens the issuer URL");

    let message = err.to_string();
    assert!(
        message.contains("issuer URL") && message.contains("refused"),
        "{message}"
    );
    assert_eq!(requests_seen(&idp).await, 0, "a request reached the issuer");
}

/// The same for the `private_key_jwt` form.
#[tokio::test]
async fn discover_with_private_key_jwt_refuses_a_loopback_issuer_under_its_default_policy() {
    let idp = loopback_idp().await;

    let err =
        OAuthProviderConfig::discover_with_private_key_jwt("idp", &idp.uri(), signer(), REDIRECT)
            .await
            .expect_err("the default policy screens the issuer URL");

    let message = err.to_string();
    assert!(
        message.contains("issuer URL") && message.contains("refused"),
        "{message}"
    );
    assert_eq!(requests_seen(&idp).await, 0, "a request reached the issuer");
}

/// The named opt-in for local development reaches the same identity
/// provider, through both forms.
#[tokio::test]
async fn the_loopback_opt_in_reaches_a_loopback_issuer() {
    let clock = axess_clock::testing::MockClock::at_reference();
    let idp = loopback_idp().await;
    let policy = EgressPolicy::screened_allowing_loopback_http();

    OAuthProviderConfig::discover_screened("idp", &idp.uri(), "client", "secret", REDIRECT, policy)
        .await
        .expect("the loopback opt-in")
        .with_clock(std::sync::Arc::new(clock.clone()))
        .build()
        .expect("build");
    OAuthProviderConfig::discover_screened_with_private_key_jwt(
        "idp",
        &idp.uri(),
        signer(),
        REDIRECT,
        policy,
    )
    .await
    .expect("the loopback opt-in, private_key_jwt")
    .with_clock(std::sync::Arc::new(clock.clone()))
    .build()
    .expect("build");
}
