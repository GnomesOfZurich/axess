//! The token-endpoint probe a tenant's registration passes before its record
//! is stored: the identity provider's answer to a token request made as the
//! client decides, as RFC 6749 section 5.2 reads it. A refusal of the grant
//! proves the client was authenticated; `invalid_client` proves it was not;
//! anything else proves nothing and the record is refused as unproven.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_tenant_ownership_probe`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_clock::testing::MockClock;
use axess_core::authn::ids::TenantId;
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, OwnershipProofs, StoredTenantOAuthProviders,
    TenantClientCredential, TenantDpop, TenantOAuthProviderRecord, TokenEndpointProbe,
};
use axess_factors::FactorSecret;
use axess_factors::client_assertion::SignerSpec;
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::OAuthError;
use axess_testing::mock_tracing::TracingCapture;
use axess_testing::oauth_wiremock::{
    oauth_discovery_document, oauth_generate_rsa_keypair, oauth_rsa_private_pem,
};
use jsonwebtoken::{DecodingKey, Validation};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const CLIENT_ID: &str = "client-1";
const SECRET: &str = "s3cret";
/// `client-1:s3cret`, base64.
const BASIC: &str = "Basic Y2xpZW50LTE6czNjcmV0";

fn tenant() -> TenantId {
    axess_core::authn::ids::testing::tenant("acme")
}

fn record(issuer: &str, credential: TenantClientCredential) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant(),
        name: "sso".into(),
        issuer: issuer.to_string(),
        client_id: CLIENT_ID.into(),
        redirect_url: "https://rp.example/callback".into(),
        scopes: vec![],
        credential,
        dpop: TenantDpop::Advertised,
        kind: None,
        revision: 0,
    }
}

fn secret() -> TenantClientCredential {
    TenantClientCredential::Secret(FactorSecret::Plain(SECRET.into()))
}

type Directory = StoredTenantOAuthProviders<MemoryTenantOAuthProviderStore>;

fn directory(clock: &MockClock, probe: TokenEndpointProbe) -> Directory {
    StoredTenantOAuthProviders::new_unencrypted(
        MemoryTenantOAuthProviderStore::new(),
        OwnershipProofs::accept(probe),
    )
    .with_clock(std::sync::Arc::new(clock.clone()))
    .with_egress_policy(EgressPolicy::screened_allowing_loopback_http())
}

/// An identity provider whose token endpoint answers every request with
/// `answer`.
async fn idp_answering(answer: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(oauth_discovery_document(&server.uri())),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(answer)
        .mount(&server)
        .await;
    server
}

/// An identity provider whose token endpoint answers `answer` to the
/// client's secret as HTTP Basic, and `invalid_client` to anything else.
async fn idp_authenticating(answer: ResponseTemplate) -> MockServer {
    let server = idp_answering(oauth_error(401, "invalid_client")).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("authorization", BASIC))
        .respond_with(answer)
        .with_priority(1)
        .mount(&server)
        .await;
    server
}

fn oauth_error(status: u16, error: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(serde_json::json!({ "error": error }))
}

/// Matches a token request whose `client_assertion` the RSA key `jwk`
/// names signed.
struct SignedBy(DecodingKey);

impl SignedBy {
    fn jwk(jwk: &serde_json::Value) -> Self {
        let component = |name: &str| jwk[name].as_str().unwrap_or_default().to_string();
        Self(
            DecodingKey::from_rsa_components(&component("n"), &component("e"))
                .expect("the fixture's JWK is an RSA key"),
        )
    }
}

impl Match for SignedBy {
    fn matches(&self, request: &Request) -> bool {
        let Some(assertion) = url::form_urlencoded::parse(&request.body)
            .find(|(name, _)| name == "client_assertion")
            .map(|(_, value)| value.into_owned())
        else {
            return false;
        };
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        axess_factors::jwt::decode::<serde_json::Value>(&assertion, &self.0, &validation).is_ok()
    }
}

/// How many requests reached the token endpoint.
async fn token_requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|request| request.url.path() == "/token")
        .count()
}

fn refusal(result: Result<TenantOAuthProviderRecord, OAuthError>) -> String {
    match result {
        Err(OAuthError::Config(text)) => text,
        Err(other) => panic!("expected a refusal by name, got {other:?}"),
        Ok(stored) => panic!("the record was stored: {}", stored.name),
    }
}

async fn stored(directory: &Directory) -> bool {
    directory
        .store()
        .get(&tenant(), "sso")
        .await
        .unwrap()
        .is_some()
}

/// Each refusal of the grant is given only to an authenticated client, so
/// each proves ownership and the record is stored, from a provider that
/// refuses any other secret as `invalid_client`.
#[tokio::test]
async fn each_refusal_of_the_grant_proves_the_client_and_the_record_is_stored() {
    let clock = MockClock::at_reference();
    for error in [
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
    ] {
        let server = idp_authenticating(oauth_error(400, error)).await;
        let directory = directory(&clock, TokenEndpointProbe::new());

        directory
            .upsert(record(&server.uri(), secret()))
            .await
            .unwrap_or_else(|e| panic!("{error} proves the client: {e}"));

        assert!(stored(&directory).await, "{error}");
    }
}

/// A record's name is its tenant's text: the line that records a proven
/// client carries it escaped.
#[tokio::test]
async fn a_proven_records_name_reaches_the_log_escaped() {
    let clock = MockClock::at_reference();
    let server = idp_authenticating(oauth_error(400, "invalid_grant")).await;
    let directory = directory(&clock, TokenEndpointProbe::new());
    let mut named = record(&server.uri(), secret());
    named.name = "sso\nWARN forged\u{202E}".into();
    let capture = TracingCapture::install();

    directory
        .upsert(named)
        .await
        .expect("a refusal of the grant proves the client");

    let events = capture.events();
    let line = events
        .iter()
        .find(|e| e.message.contains("ownership of its client is proven"))
        .unwrap_or_else(|| panic!("no line for the proof among {events:?}"));
    assert!(
        !line.message.chars().any(axess_identity::log_text::escapes),
        "{:?}",
        line.message
    );
    assert!(line.message.contains("WARN forged"), "{:?}", line.message);
}

/// `invalid_client` says the provider did not authenticate the client with
/// the record's credential: the record is refused by that name and nothing
/// is stored.
#[tokio::test]
async fn invalid_client_refuses_the_record_and_stores_nothing() {
    let clock = MockClock::at_reference();
    let server = idp_answering(oauth_error(401, "invalid_client")).await;
    let directory = directory(&clock, TokenEndpointProbe::new());

    let text = refusal(directory.upsert(record(&server.uri(), secret())).await);

    assert!(
        text.contains("ownership of its client is not proven"),
        "{text}"
    );
    assert!(text.contains("did not authenticate the client"), "{text}");
    assert!(
        !text.contains(&server.uri()),
        "the issuer is not echoed: {text}"
    );
    assert!(!stored(&directory).await);
}

/// Another error, a token, a redirect and an answer with no OAuth error (an
/// error page, a 400 with no `error`, a 400 that is not JSON, an `error`
/// that is not a string) say nothing of the client's authentication: each
/// is refused as unproven. What came back is on the trace for the operator,
/// never in the refusal the tenant reads, so a tenant pointing its issuer at
/// a host learns nothing of what answered there.
#[tokio::test]
async fn an_answer_that_proves_nothing_is_refused_as_unproven() {
    let clock = MockClock::at_reference();
    let cases = [
        (oauth_error(400, "invalid_request"), "`invalid_request`"),
        (
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "a", "token_type": "Bearer"
            })),
            "accepted a code it never issued",
        ),
        (
            ResponseTemplate::new(302).insert_header("location", "https://elsewhere.example/"),
            "redirect (HTTP 302)",
        ),
        (
            ResponseTemplate::new(500).set_body_string("down"),
            "HTTP 500 with no OAuth error",
        ),
        (
            ResponseTemplate::new(400).set_body_json(serde_json::json!({})),
            "HTTP 400 with no OAuth error",
        ),
        (
            ResponseTemplate::new(400).set_body_string("<html>bad request</html>"),
            "HTTP 400 with no OAuth error",
        ),
        (
            ResponseTemplate::new(400).set_body_json(serde_json::json!({ "error": 5 })),
            "HTTP 400 with no OAuth error",
        ),
    ];
    for (answer, named) in cases {
        let server = idp_answering(answer).await;
        let directory = directory(&clock, TokenEndpointProbe::new());
        let capture = TracingCapture::install();

        let text = refusal(directory.upsert(record(&server.uri(), secret())).await);

        assert!(text.contains("ownership is unproven"), "{named}: {text}");
        assert!(!text.contains(named), "{named} is not told: {text}");
        assert!(!text.contains("HTTP"), "no status is told: {text}");
        assert!(capture.contains(named), "{named} is on the trace");
        assert!(!stored(&directory).await, "{named}");
    }
}

/// A provider that refuses the grant whatever credential comes with it
/// (one that skips authenticating a public client, or checks the code
/// first) never checked the credential: the probe's first request, made
/// with a credential known to be wrong, gets that refusal, so nothing is
/// proven and the client's own credential is never sent, for the right
/// secret, a junk one and a key alike.
#[tokio::test]
async fn a_provider_that_refuses_the_grant_whatever_the_credential_proves_nothing() {
    let clock = MockClock::at_reference();
    let (der, _, _) = oauth_generate_rsa_keypair();
    let credentials = [
        ("the secret", secret()),
        (
            "a junk secret",
            TenantClientCredential::Secret(FactorSecret::Plain("anything-at-all".into())),
        ),
        (
            "a key",
            TenantClientCredential::PrivateKeyJwt {
                key_pem: FactorSecret::Plain(oauth_rsa_private_pem(&der).into()),
                signer: SignerSpec::new(jsonwebtoken::Algorithm::RS256),
            },
        ),
    ];
    for (named, credential) in credentials {
        let server = idp_answering(oauth_error(400, "invalid_grant")).await;
        let directory = directory(&clock, TokenEndpointProbe::new());
        let capture = TracingCapture::install();

        let text = refusal(directory.upsert(record(&server.uri(), credential)).await);

        assert!(text.contains("ownership is unproven"), "{named}: {text}");
        assert!(text.contains("an operator"), "{named}: {text}");
        assert!(
            capture.contains("does not authenticate this client"),
            "{named}: the reason is on the trace"
        );
        assert_eq!(
            token_requests(&server).await,
            1,
            "{named}: the first control only"
        );
        assert!(!stored(&directory).await, "{named}");
    }
}

/// The controls, before and after the client's own request, present
/// another secret than the record's: the provider refuses both, so the
/// client's answer proves it.
#[tokio::test]
async fn the_control_request_presents_a_secret_that_is_not_the_clients() {
    let clock = MockClock::at_reference();
    let server = idp_answering(oauth_error(401, "invalid_client")).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("authorization", BASIC))
        .respond_with(oauth_error(400, "invalid_grant"))
        .with_priority(1)
        .mount(&server)
        .await;

    directory(&clock, TokenEndpointProbe::new())
        .upsert(record(&server.uri(), secret()))
        .await
        .expect("the secret authenticates and the control does not");

    let headers: Vec<String> = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|request| request.url.path() == "/token")
        .filter_map(|request| request.headers.get("authorization"))
        .filter_map(|value| value.to_str().ok().map(str::to_string))
        .collect();
    assert_eq!(headers.len(), 3, "{headers:?}");
    assert_eq!(headers[1], BASIC);
    assert_ne!(headers[0], BASIC, "the first control is another secret");
    assert_ne!(headers[2], BASIC, "the second control is another secret");
}

/// RFC 6749 section 5.2 sends a refusal of the grant with HTTP 400 only: a
/// grant error under another status (a gateway's page, a misrouted
/// endpoint) is not read as one, and the record is refused as unproven.
#[tokio::test]
async fn a_grant_error_under_a_status_other_than_400_is_unproven() {
    let clock = MockClock::at_reference();
    for status in [401, 403, 404, 503] {
        let server = idp_answering(oauth_error(status, "invalid_grant")).await;
        let directory = directory(&clock, TokenEndpointProbe::new());

        let text = refusal(directory.upsert(record(&server.uri(), secret())).await);

        assert!(text.contains("ownership is unproven"), "{status}: {text}");
        assert!(!stored(&directory).await, "{status}");
    }
}

/// `invalid_client` is a failed authentication under 400 as under 401, and
/// under any other status proves nothing.
#[tokio::test]
async fn invalid_client_is_read_under_400_and_401_only() {
    let clock = MockClock::at_reference();
    for (status, named) in [
        (400, "did not authenticate the client"),
        (401, "did not authenticate the client"),
        (403, "ownership is unproven"),
        (503, "ownership is unproven"),
    ] {
        let server = idp_answering(oauth_error(status, "invalid_client")).await;
        let directory = directory(&clock, TokenEndpointProbe::new());

        let text = refusal(directory.upsert(record(&server.uri(), secret())).await);

        assert!(text.contains(named), "{status}: {text}");
        assert!(!stored(&directory).await, "{status}");
    }
}

/// A token endpoint that does not answer proves nothing either.
#[tokio::test]
async fn a_token_endpoint_that_does_not_answer_is_unproven() {
    let clock = MockClock::at_reference();
    let server = MockServer::start().await;
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let mut document = oauth_discovery_document(&server.uri());
    document["token_endpoint"] = serde_json::json!(format!("http://{closed}/token"));
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document))
        .mount(&server)
        .await;
    let directory = directory(&clock, TokenEndpointProbe::new());
    let capture = TracingCapture::install();

    let text = refusal(directory.upsert(record(&server.uri(), secret())).await);

    assert!(text.contains("ownership is unproven"), "{text}");
    assert!(!text.contains("did not answer"), "{text}");
    assert!(capture.contains("did not answer"), "on the trace");
    assert!(
        !text.contains(&closed.to_string()),
        "no address echoed: {text}"
    );
}

/// The probe authenticates as the client the tenant's provider would: the
/// secret as HTTP Basic by default, in the form when named, and the grant is
/// a code the endpoint never issued.
#[tokio::test]
async fn the_probe_presents_the_secret_as_configured() {
    let clock = MockClock::at_reference();
    let server = idp_answering(oauth_error(401, "invalid_client")).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("authorization", BASIC))
        .and(body_string_contains("grant_type=authorization_code"))
        .respond_with(oauth_error(400, "invalid_grant"))
        .with_priority(1)
        .mount(&server)
        .await;
    directory(&clock, TokenEndpointProbe::new())
        .upsert(record(&server.uri(), secret()))
        .await
        .expect("Basic authenticates");

    let server = idp_answering(oauth_error(401, "invalid_client")).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("client_id=client-1"))
        .and(body_string_contains("client_secret=s3cret"))
        .respond_with(oauth_error(400, "invalid_grant"))
        .with_priority(1)
        .mount(&server)
        .await;
    directory(&clock, TokenEndpointProbe::new().with_client_secret_post())
        .upsert(record(&server.uri(), secret()))
        .await
        .expect("the form authenticates");
}

/// A `private_key_jwt` record proves itself with an assertion signed by its
/// key, and the control's assertion, whose signature is not the key's, is
/// refused.
#[tokio::test]
async fn a_private_key_jwt_client_proves_itself_with_an_assertion() {
    let clock = MockClock::at_reference();
    let (der, jwk, _) = oauth_generate_rsa_keypair();
    let server = idp_answering(oauth_error(401, "invalid_client")).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
        ))
        .and(SignedBy::jwk(&jwk))
        .respond_with(oauth_error(400, "invalid_grant"))
        .with_priority(1)
        .mount(&server)
        .await;
    let credential = TenantClientCredential::PrivateKeyJwt {
        key_pem: FactorSecret::Plain(oauth_rsa_private_pem(&der).into()),
        signer: SignerSpec::new(jsonwebtoken::Algorithm::RS256),
    };

    directory(&clock, TokenEndpointProbe::new())
        .upsert(record(&server.uri(), credential))
        .await
        .expect("the assertion authenticates");
}

/// A public client has no credential to prove with: the probe refuses it by
/// name and makes no request.
#[tokio::test]
async fn the_probe_refuses_a_public_client_without_a_request() {
    let clock = MockClock::at_reference();
    let server = idp_answering(oauth_error(400, "invalid_grant")).await;
    let directory = directory(&clock, TokenEndpointProbe::new());

    let text = refusal(
        directory
            .upsert(record(
                &server.uri(),
                TenantClientCredential::Secret(FactorSecret::Plain(String::new().into())),
            ))
            .await,
    );

    assert!(text.contains("public client"), "{text}");
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(requests.is_empty(), "no request was made: {requests:?}");
}
