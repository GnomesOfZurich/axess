#![cfg(feature = "oauth")]
//! The device-flow poll reads the token endpoint's refusal as RFC 8628
//! section 3.5 names them: `authorization_pending` is a poll to repeat,
//! `slow_down` a poll to repeat at an interval five seconds longer, and
//! any other code a denial that carries the endpoint's description.

use axess_clock::testing::MockClock;
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::{DeviceTokenOutcome, OAuthProvider, OAuthProviderConfig};
use serde_json::json;
use std::sync::Arc;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A loopback identity provider whose token endpoint answers a device
/// grant by the device code it names.
async fn idp() -> MockServer {
    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            axess_testing::oauth_wiremock::oauth_discovery_document(&issuer),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [] })))
        .mount(&server)
        .await;
    for (code, body) in [
        ("pending", json!({ "error": "authorization_pending" })),
        ("slow", json!({ "error": "slow_down" })),
        (
            "denied",
            json!({ "error": "access_denied", "error_description": "the user said no" }),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(format!("device_code={code}")))
            .respond_with(ResponseTemplate::new(400).set_body_json(body))
            .mount(&server)
            .await;
    }
    server
}

async fn provider(server: &MockServer) -> OAuthProviderConfig {
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
    .with_clock(Arc::new(MockClock::at_reference()))
    .without_dpop()
    .build()
    .expect("build")
}

#[tokio::test]
async fn each_refusal_of_the_poll_is_its_own_outcome() {
    let server = idp().await;
    let provider = provider(&server).await;

    let pending = provider
        .poll_device_token("pending", 5, None, None)
        .await
        .expect("a refusal to answer later is not an error");
    assert!(
        matches!(pending, DeviceTokenOutcome::Pending),
        "{pending:?}"
    );

    let slow = provider
        .poll_device_token("slow", 5, None, None)
        .await
        .expect("a request to slow down is not an error");
    assert!(
        matches!(slow, DeviceTokenOutcome::SlowDown { new_interval: 10 }),
        "{slow:?}"
    );

    let denied = provider
        .poll_device_token("denied", 5, None, None)
        .await
        .expect("a denial is an outcome, not an error");
    assert!(
        matches!(&denied, DeviceTokenOutcome::Denied(text) if text == "the user said no"),
        "{denied:?}"
    );
}
