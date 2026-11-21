#![cfg(feature = "oauth")]
//! The client-authentication probe against a token endpoint: the client's
//! own request is read only between two controls, each a credential known
//! to be wrong, and a refusal of the grant proves the client only when both
//! controls were refused as `invalid_client`.

use axess_factors::egress::{EgressPolicy, ScreenedClient};
use axess_factors::oauth::{ClientAuthProbe, ProbeClientAuth, probe_client_authentication};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CLIENT_ID: &str = "client-1";
const OWNERS_SECRET: &str = "s3cret0";
/// The control the probe derives from [`OWNERS_SECRET`]: its last digit
/// swapped with its neighbour.
const CONTROL_SECRET: &str = "s3cret1";

fn oauth_error(status: u16, error: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(serde_json::json!({ "error": error }))
}

fn presenting(secret: &str) -> impl wiremock::Match {
    body_string_contains(format!("client_secret={secret}"))
}

fn client() -> ScreenedClient {
    EgressPolicy::screened_allowing_loopback_http()
        .build_client(|settings| settings)
        .expect("client")
}

async fn probe(server: &MockServer) -> ClientAuthProbe {
    let clock = axess_clock::testing::MockClock::at_reference();
    let rng = axess_rng::testing::MockRng::new(7);
    probe_client_authentication(
        &client(),
        &format!("{}/token", server.uri()),
        ProbeClientAuth::SecretPost {
            client_id: CLIENT_ID,
            client_secret: OWNERS_SECRET,
        },
        "https://rp.example/callback",
        &clock,
        &rng,
    )
    .await
}

/// The secrets the token requests presented, in order.
async fn presented(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|request| {
            let body = String::from_utf8_lossy(&request.body).into_owned();
            url::form_urlencoded::parse(body.as_bytes())
                .find(|(name, _)| name == "client_secret")
                .map(|(_, value)| value.into_owned())
                .unwrap_or_default()
        })
        .collect()
}

/// An endpoint that checks the secret: the control refused as
/// `invalid_client` before and after the owner's secret, which is refused
/// as a grant. The client is proven.
#[tokio::test]
async fn a_grant_refusal_between_two_refused_controls_proves_the_client() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(presenting(OWNERS_SECRET))
        .respond_with(oauth_error(400, "invalid_grant"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(presenting(CONTROL_SECRET))
        .respond_with(oauth_error(401, "invalid_client"))
        .mount(&server)
        .await;

    assert_eq!(
        probe(&server).await,
        ClientAuthProbe::Authenticated {
            error: "invalid_grant".to_owned()
        }
    );
    assert_eq!(
        presented(&server).await,
        [CONTROL_SECRET, OWNERS_SECRET, CONTROL_SECRET]
    );
}

/// An endpoint that ignores the secret refuses the control as a grant too:
/// nothing is proven, and the owner's secret is never sent.
#[tokio::test]
async fn a_control_refused_as_a_grant_proves_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(oauth_error(400, "invalid_grant"))
        .mount(&server)
        .await;

    let ClientAuthProbe::Unproven { reason } = probe(&server).await else {
        panic!("an endpoint that ignores the secret proved the client");
    };
    assert!(
        reason.contains("`invalid_grant`")
            && reason.contains("before the client's own")
            && reason.contains("does not authenticate this client"),
        "{reason}"
    );
    assert_eq!(presented(&server).await, [CONTROL_SECRET]);
}

/// A control after the owner's request that is no longer refused as
/// `invalid_client` undoes the proof: the endpoint stopped checking the
/// credential in between.
#[tokio::test]
async fn a_control_after_the_clients_request_not_refused_proves_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(presenting(CONTROL_SECRET))
        .respond_with(oauth_error(401, "invalid_client"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(oauth_error(400, "invalid_request"))
        .with_priority(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(presenting(OWNERS_SECRET))
        .respond_with(oauth_error(400, "invalid_grant"))
        .with_priority(1)
        .mount(&server)
        .await;

    let ClientAuthProbe::Unproven { reason } = probe(&server).await else {
        panic!("a control answered otherwise after the client's request proved the client");
    };
    assert!(
        reason.contains("after the client's own") && reason.contains("`invalid_request`"),
        "{reason}"
    );
    assert_eq!(
        presented(&server).await,
        [CONTROL_SECRET, OWNERS_SECRET, CONTROL_SECRET]
    );
}

/// The owner's secret refused as `invalid_client`, like the control: the
/// endpoint did not authenticate the client, and no second control is sent.
#[tokio::test]
async fn the_clients_own_secret_refused_as_invalid_client_is_not_authenticated() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(oauth_error(400, "invalid_client"))
        .mount(&server)
        .await;

    assert_eq!(probe(&server).await, ClientAuthProbe::NotAuthenticated);
    assert_eq!(presented(&server).await, [CONTROL_SECRET, OWNERS_SECRET]);
}
