#![cfg(feature = "oauth")]
//! A refusal keeps its `error` code however long its body is. The text a
//! refusal carries into an error or a log line is cut at 1 KiB, but the code
//! is read from the whole answer (up to the cap of a success body), so a
//! long `error_description`, before the code or after it, does not turn
//! `invalid_grant` into a bare status.

use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::{OAuthError, OAuthProvider, OAuthProviderConfig};
use axess_testing::oauth_wiremock::oauth_discovery_document;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A refusal body far over 1 KiB: well over the cut of a message.
const LONG: usize = 4 * 1024;
/// A refusal body past the cap at which a success answer is refused as too
/// large (64 KiB): a refusal is read up to that cap and never past it.
const PAST_THE_SUCCESS_CAP: usize = 80 * 1024;

/// A refusal body with a description of `description_bytes`, first or last.
fn refusal(code: &str, description_first: bool, description_bytes: usize) -> String {
    let description = "D".repeat(description_bytes);
    if description_first {
        format!(r#"{{"error_description":"{description}","error":"{code}"}}"#)
    } else {
        format!(r#"{{"error":"{code}","error_description":"{description}"}}"#)
    }
}

async fn idp(code: &str, description_first: bool) -> MockServer {
    idp_with(code, description_first, LONG).await
}

async fn idp_with(code: &str, description_first: bool, description_bytes: usize) -> MockServer {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let mut doc = oauth_discovery_document(&issuer);
    doc["revocation_endpoint"] = json!(format!("{issuer}/revoke"));
    for (verb, at, body) in [
        ("GET", "/.well-known/openid-configuration", doc.to_string()),
        ("GET", "/jwks", json!({ "keys": [] }).to_string()),
    ] {
        Mock::given(method(verb))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
    }
    for at in ["/token", "/device", "/revoke"] {
        Mock::given(method("POST"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(400).set_body_raw(
                refusal(code, description_first, description_bytes),
                "application/json",
            ))
            .mount(&server)
            .await;
    }
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

#[tokio::test]
async fn a_long_refusal_keeps_its_error_code() {
    for description_first in [false, true] {
        let server = idp("invalid_grant", description_first).await;
        let provider = provider(&server).await;
        let order = if description_first { "last" } else { "first" };

        let err = provider
            .refresh_token_unchecked("refresh", None, None)
            .await
            .expect_err("refused");
        let message = err.to_string();
        assert!(
            message.contains("invalid_grant"),
            "refresh, code {order}: {message}"
        );
        assert!(
            message.len() <= 2 * 1024,
            "refresh: {} bytes",
            message.len()
        );

        let err = provider
            .client_credentials(&[], None)
            .await
            .expect_err("refused");
        assert!(
            matches!(&err, OAuthError::TokenExchange(code) if code == "invalid_grant"),
            "client_credentials, code {order}: {err}"
        );

        let err = provider
            .request_device_code(&[])
            .await
            .expect_err("refused");
        assert!(
            matches!(&err, OAuthError::DeviceAuthorization(code) if code == "invalid_grant"),
            "device authorization, code {order}: {err}"
        );
    }
}

/// The one refusal whose code changes the outcome: an authorization server
/// that cannot revoke this kind of token says `unsupported_token_type`,
/// which callers treat as nothing to do, whatever else the body says.
#[tokio::test]
async fn a_long_revocation_refusal_keeps_unsupported_token_type() {
    for description_first in [false, true] {
        let server = idp("unsupported_token_type", description_first).await;
        let provider = provider(&server).await;
        let err = provider
            .revoke_token("access", Some("access_token"), None)
            .await
            .expect_err("refused");
        assert!(
            matches!(err, OAuthError::UnsupportedTokenType),
            "code {}: {err:?}",
            if description_first { "last" } else { "first" }
        );
    }
}

/// The device poll reads its outcome from the code: a long body that says
/// `authorization_pending` is still pending, not a denial.
#[tokio::test]
async fn a_long_device_poll_answer_keeps_its_outcome() {
    use axess_factors::oauth::DeviceTokenOutcome;
    for description_first in [false, true] {
        let server = idp("authorization_pending", description_first).await;
        let provider = provider(&server).await;
        let outcome = provider
            .poll_device_token("d", 5, None, None)
            .await
            .expect("an outcome");
        assert!(
            matches!(outcome, DeviceTokenOutcome::Pending),
            "code {}",
            if description_first { "last" } else { "first" }
        );
    }
}

/// A refusal longer than the success-body cap is not refused for its
/// length: it is read up to that cap, and the code before the cut is kept.
/// A success answer that long is refused, as too large to be a token
/// response.
#[tokio::test]
async fn a_refusal_past_the_success_cap_keeps_its_error_code() {
    let server = idp_with("invalid_grant", false, PAST_THE_SUCCESS_CAP).await;
    let provider = provider(&server).await;

    let err = provider
        .client_credentials(&[], None)
        .await
        .expect_err("refused");
    assert!(
        matches!(&err, OAuthError::TokenExchange(code) if code == "invalid_grant"),
        "client_credentials: {err}"
    );

    let err = provider
        .refresh_token_unchecked("refresh", None, None)
        .await
        .expect_err("refused");
    assert!(err.to_string().contains("invalid_grant"), "refresh: {err}");
}
