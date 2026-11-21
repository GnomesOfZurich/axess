//! Tests for the outbound OAuth client.
//!
//! Token endpoint is stood up via `wiremock`. Caching + refresh
//! behaviour is exercised against an injected [`MockClock`] so the
//! tests are deterministic.
//!
//! This file holds the fixtures every topic shares; the tests sit by topic
//! in the files under `tests/`.

use super::*;
use axess_clock::Timestamp;
use axess_clock::testing::MockClock;
use serde_json::json;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn t0() -> Timestamp {
    Timestamp::from_unix_seconds(1_700_000_000).expect("fixed t0")
}

async fn token_server_returning(body: serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    server
}

fn token_url(server: &MockServer) -> Url {
    Url::parse(&format!("{}/oauth2/token", server.uri())).expect("token URL")
}

fn basic() -> ClientAuthMethod {
    ClientAuthMethod::ClientSecretBasic {
        client_id: "axess".into(),
        client_secret: "shh".into(),
    }
}

/// A client under the policy for a mock on the loopback interface: the
/// default, `screened`, refuses loopback.
fn loopback_new(
    token_url: Url,
    auth_method: ClientAuthMethod,
) -> Result<OutboundOAuthClient, OAuthClientError> {
    OutboundOAuthClient::new_screened(
        token_url,
        auth_method,
        crate::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
}

mod caching;
mod client_auth;
mod responses;
mod transport;
