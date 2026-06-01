//! Phase 5b: tests for RFC 8693 token exchange.
//!
//! `wiremock` stands up the token endpoint. Tests cover the
//! happy-path exchange, optional actor token, error propagation, and
//! Azure-AD-style OBO shape.

use super::*;
use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn token_url(server: &MockServer) -> Url {
    Url::parse(&format!("{}/oauth2/token", server.uri())).unwrap()
}

#[tokio::test]
async fn exchange_happy_path_returns_downstream_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
        ))
        .and(body_string_contains("subject_token=user-jwt-here"))
        .and(body_string_contains(
            "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
        ))
        .and(body_string_contains(
            "audience=https%3A%2F%2Fcompute-worker.gnomes",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "downstream-jwt",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 600,
            "scope": "compute.read compute.write",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = TokenExchangeClient::new(token_url(&server), "gnomes-api", Some("shh".into()));
    let req = TokenExchangeRequest::new("user-jwt-here", token_types::JWT)
        .with_audience("https://compute-worker.gnomes")
        .with_scopes(["compute.read", "compute.write"]);
    let resp = client.exchange(&req).await.expect("exchange");

    assert_eq!(&*resp.access_token, "downstream-jwt");
    assert_eq!(resp.token_type, "Bearer");
    assert_eq!(resp.expires_in, Some(600));
    assert_eq!(
        resp.scopes,
        vec!["compute.read".to_string(), "compute.write".to_string()]
    );
}

#[tokio::test]
async fn exchange_passes_actor_token_for_azure_obo_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("subject_token=user-jwt"))
        .and(body_string_contains("actor_token=axess-workload-jwt"))
        .and(body_string_contains(
            "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "graph-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = TokenExchangeClient::new(token_url(&server), "axess-tenant", Some("shh".into()));
    let req = TokenExchangeRequest::new("user-jwt", token_types::JWT)
        .with_actor_token("axess-workload-jwt", token_types::JWT)
        .with_audience("https://graph.microsoft.com");
    let _ = client
        .exchange(&req)
        .await
        .expect("OBO shape with actor token must succeed");
}

#[tokio::test]
async fn exchange_works_without_client_secret_for_mtls_auth() {
    // No shared secret; adopter authenticates via mTLS at the
    // transport layer (configured on the reqwest::Client). The
    // request body must NOT carry client_secret in this mode.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("subject_token=user-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "downstream",
            "expires_in": 3600,
        })))
        .mount(&server)
        .await;

    let client = TokenExchangeClient::new(token_url(&server), "axess", None);
    let req = TokenExchangeRequest::new("user-token", token_types::JWT);
    let resp = client.exchange(&req).await.expect("exchange");
    assert_eq!(&*resp.access_token, "downstream");

    let received = server.received_requests().await.expect("rcv");
    let body = String::from_utf8(received[0].body.clone()).expect("utf8");
    assert!(
        !body.contains("client_secret"),
        "no client_secret in body when constructed with None; got: {body}"
    );
}

#[tokio::test]
async fn exchange_propagates_token_endpoint_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_target",
            "error_description": "audience not allowed",
        })))
        .mount(&server)
        .await;

    let client = TokenExchangeClient::new(token_url(&server), "axess", Some("shh".into()));
    let req = TokenExchangeRequest::new("token", token_types::JWT)
        .with_audience("https://forbidden.example");
    let err = client.exchange(&req).await.expect_err("400 must propagate");
    match err {
        crate::delegated::error::DelegatedError::TokenEndpoint { status, body } => {
            assert_eq!(status, 400);
            assert!(body.contains("invalid_target"));
        }
        other => panic!("expected TokenEndpoint, got {other:?}"),
    }
}

#[tokio::test]
async fn exchange_rejects_empty_access_token_in_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "",
            "expires_in": 3600,
        })))
        .mount(&server)
        .await;

    let client = TokenExchangeClient::new(token_url(&server), "axess", Some("shh".into()));
    let req = TokenExchangeRequest::new("token", token_types::JWT);
    let err = client
        .exchange(&req)
        .await
        .expect_err("empty access_token must reject");
    assert!(
        matches!(
            err,
            crate::delegated::error::DelegatedError::MalformedResponse(_)
        ),
        "expected MalformedResponse, got {err:?}"
    );
}

#[tokio::test]
async fn exchange_carries_resource_when_set() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains(
            "resource=https%3A%2F%2Fapi.gnomes%2Fv1%2Fmarket",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "scoped-to-market-api",
            "expires_in": 600,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = TokenExchangeClient::new(token_url(&server), "axess", Some("shh".into()));
    let req = TokenExchangeRequest::new("token", token_types::JWT)
        .with_resource(Url::parse("https://api.gnomes/v1/market").unwrap());
    let _ = client.exchange(&req).await.expect("resource carried");
}
