#![cfg(feature = "oauth")]
//! A success answer that does not parse is reported without the remote
//! party's text in full: serde quotes the value it could not read
//! (`invalid type: string "...", expected u64`), and an identity provider
//! that puts tens of kilobytes where a number belongs must not put them
//! into one error and one log line. Each refusal is bounded and keeps the
//! position serde reported.

use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::{OAuthProvider, OAuthProviderConfig};
use axess_testing::oauth_wiremock::oauth_discovery_document;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Far longer than any refusal may grow.
const LONG: usize = 60 * 1024;
/// The most bytes a refusal may carry, its fixed text included.
const BOUND: usize = 1024;

fn long_text() -> String {
    "A".repeat(LONG)
}

async fn answer(server: &MockServer, verb: &str, at: &str, body: serde_json::Value) {
    Mock::given(method(verb))
        .and(path(at))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// A loopback identity provider whose every endpoint answers 200 with a
/// long string where the response holds a number or a boolean.
async fn idp() -> MockServer {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let mut doc = oauth_discovery_document(&issuer);
    doc["pushed_authorization_request_endpoint"] = json!(format!("{issuer}/par"));
    answer(&server, "GET", "/.well-known/openid-configuration", doc).await;
    answer(&server, "GET", "/jwks", json!({ "keys": [] })).await;
    let long = long_text();
    answer(
        &server,
        "POST",
        "/token",
        json!({ "access_token": "a", "token_type": "Bearer", "expires_in": long }),
    )
    .await;
    answer(
        &server,
        "GET",
        "/userinfo",
        json!({ "sub": "u1", "email_verified": long }),
    )
    .await;
    answer(
        &server,
        "POST",
        "/par",
        json!({ "request_uri": "urn:x", "expires_in": long }),
    )
    .await;
    answer(
        &server,
        "POST",
        "/device",
        json!({
            "device_code": "d",
            "user_code": "u",
            "verification_uri": "https://idp.example/device",
            "expires_in": long,
        }),
    )
    .await;
    server
}

async fn provider(server: &MockServer) -> OAuthProviderConfig {
    let clock = axess_clock::testing::MockClock::at_reference();
    OAuthProviderConfig::discover_screened(
        "idp",
        &server.uri(),
        "client",
        "secret",
        "https://rp.example/callback",
        EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .expect("discovery")
    .with_clock(std::sync::Arc::new(clock.clone()))
    .with_device_authorization_endpoint(format!("{}/device", server.uri()))
    .without_dpop()
    .build()
    .expect("build")
}

fn assert_bounded(what: &str, message: String) {
    assert_bounded_at(what, message, true);
}

/// `positioned`: serde reported where it stopped, which a parse of bytes
/// does and a conversion of an already parsed document does not.
fn assert_bounded_at(what: &str, message: String, positioned: bool) {
    assert!(
        message.len() <= BOUND,
        "{what}: {} bytes in one error",
        message.len()
    );
    assert!(
        !message.contains(&"A".repeat(BOUND)),
        "{what}: the remote value is carried whole"
    );
    assert!(
        !positioned || message.contains("line 1 column"),
        "{what}: the position is kept: {message}"
    );
}

#[tokio::test]
async fn a_success_answer_that_does_not_parse_is_reported_bounded() {
    let server = idp().await;
    let provider = provider(&server).await;

    let err = provider
        .refresh_token_unchecked("refresh", None, None)
        .await
        .expect_err("the token response does not parse");
    assert_bounded("refresh", err.to_string());

    let err = provider
        .client_credentials(&[], None)
        .await
        .expect_err("the token response does not parse");
    assert_bounded("client_credentials", err.to_string());

    let Err(err) = provider.poll_device_token("d", 5, None, None).await else {
        panic!("device token poll: the token response does not parse");
    };
    assert_bounded("device token poll", err.to_string());

    let err = provider
        .fetch_userinfo_unchecked("access", None)
        .await
        .expect_err("the userinfo response does not parse");
    assert_bounded("userinfo", err.to_string());

    let err = provider
        .push_authorization_request(&[("response_type", "code")], None)
        .await
        .expect_err("the PAR response does not parse");
    assert_bounded("PAR", err.to_string());

    let err = provider
        .request_device_code(&[])
        .await
        .expect_err("the device response does not parse");
    assert_bounded("device authorization", err.to_string());
}

/// A discovery document whose typed metadata does not parse is refused
/// bounded as well: discovery reads up to its own cap from the issuer.
#[tokio::test]
async fn a_discovery_document_that_does_not_parse_is_reported_bounded() {
    let server = MockServer::start().await;
    let mut doc = oauth_discovery_document(&server.uri());
    doc["response_types_supported"] = json!(long_text());
    answer(&server, "GET", "/.well-known/openid-configuration", doc).await;
    answer(&server, "GET", "/jwks", json!({ "keys": [] })).await;
    let Err(err) = OAuthProviderConfig::discover_screened(
        "idp",
        &server.uri(),
        "client",
        "secret",
        "https://rp.example/callback",
        EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    else {
        panic!("the document does not parse");
    };
    assert_bounded_at("discovery", err.to_string(), false);
}

/// The outbound client's token response with a long string where a number
/// belongs is refused bounded.
#[cfg(feature = "outbound-oauth")]
#[tokio::test]
async fn an_outbound_token_response_that_does_not_parse_is_reported_bounded() {
    let clock = axess_clock::testing::MockClock::at_reference();
    use axess_factors::outbound_oauth_client::{ClientAuthMethod, OutboundOAuthClient};
    let server = MockServer::start().await;
    answer(
        &server,
        "POST",
        "/token",
        json!({ "access_token": "a", "token_type": "Bearer", "expires_in": long_text() }),
    )
    .await;
    let client = OutboundOAuthClient::new_screened(
        format!("{}/token", server.uri()).parse().unwrap(),
        ClientAuthMethod::ClientSecretPost {
            client_id: "client".into(),
            client_secret: axess_factors::ZeroizedString::new("secret".to_string()),
        },
        EgressPolicy::screened_allowing_loopback_http(),
    )
    .expect("client")
    .with_clock(std::sync::Arc::new(clock.clone()));

    let err = client.get_access_token().await.expect_err("does not parse");

    assert_bounded("outbound token", err.to_string());
}

/// The social provider's userinfo answer of 60 KiB that is not JSON is
/// refused bounded.
#[cfg(feature = "social")]
#[tokio::test]
async fn a_social_userinfo_answer_that_does_not_parse_is_reported_bounded() {
    use axess_factors::social::{SocialClaims, SocialError, SocialProvider, SocialProviderConfig};
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(long_text(), "application/json"))
        .mount(&server)
        .await;
    let mapper = |_: &serde_json::Value| -> Result<SocialClaims, SocialError> {
        Err(SocialError::ClaimMapping("not reached".into()))
    };
    let provider = SocialProvider::new_screened(
        SocialProviderConfig {
            name: "social".into(),
            authorization_endpoint: format!("{}/authorize", server.uri()),
            token_endpoint: format!("{}/token", server.uri()),
            userinfo_endpoint: format!("{}/user", server.uri()),
            client_id: "id".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app.example/cb".into(),
            scopes: vec![],
        },
        mapper,
        EgressPolicy::screened_allowing_loopback_http(),
    )
    .expect("provider");

    let err = provider
        .fetch_userinfo("access")
        .await
        .expect_err("not JSON");
    assert_bounded("social userinfo", err.to_string());
}
