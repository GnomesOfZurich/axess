//! The probe's control: the requests made with a credential known to be
//! wrong, which a refusal of the grant must be checked against before it
//! proves anything. The control looks like the client's credential to a
//! provider that checks only its shape, it comes before and after the
//! client's own request, and when either control is answered with anything
//! but `invalid_client` nothing is proven.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_tenant_ownership_control`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::authn::ids::TenantId;
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, OwnershipProofs, StoredTenantOAuthProviders,
    TenantClientCredential, TenantDpop, TenantOAuthProviderRecord, TokenEndpointProbe,
};
use axess_factors::FactorSecret;
use axess_factors::client_assertion::SignerSpec;
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::OAuthError;
use axess_testing::oauth_wiremock::{
    oauth_discovery_document, oauth_generate_rsa_keypair, oauth_rsa_private_pem,
};
use base64::Engine as _;
use jsonwebtoken::{DecodingKey, Validation};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const CLIENT_ID: &str = "client-1";
/// The owner's secret: 32 hex digits, the shape the provider below checks.
const OWNERS_SECRET: &str = "0123456789abcdef0123456789abcdef";

fn tenant(label: &str) -> TenantId {
    axess_core::authn::ids::testing::tenant(label)
}

fn record(
    tenant_label: &str,
    issuer: &str,
    credential: TenantClientCredential,
) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant(tenant_label),
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

fn secret(text: &str) -> TenantClientCredential {
    TenantClientCredential::Secret(FactorSecret::Plain(text.into()))
}

type Directory = StoredTenantOAuthProviders<MemoryTenantOAuthProviderStore>;

fn directory(probe: TokenEndpointProbe) -> Directory {
    let clock = axess_clock::testing::MockClock::at_reference();
    StoredTenantOAuthProviders::new_unencrypted(
        MemoryTenantOAuthProviderStore::new(),
        OwnershipProofs::accept(probe),
    )
    .with_clock(Arc::new(clock.clone()))
    .with_egress_policy(EgressPolicy::screened_allowing_loopback_http())
}

fn oauth_error(status: u16, error: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(serde_json::json!({ "error": error }))
}

/// An identity provider whose discovery document answers at once.
async fn idp() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(oauth_discovery_document(&server.uri())),
        )
        .mount(&server)
        .await;
    server
}

/// The secret an HTTP Basic token request presents.
fn basic_secret(request: &Request) -> Option<String> {
    let value = request.headers.get("authorization")?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    decoded
        .split_once(':')
        .map(|(_, secret)| secret.to_string())
}

/// Matches a Basic token request whose secret is 32 lower-case hex digits:
/// the provider below checks the shape of a secret and nothing else.
struct WellFormedSecret;

impl Match for WellFormedSecret {
    fn matches(&self, request: &Request) -> bool {
        basic_secret(request).is_some_and(|secret| {
            secret.len() == 32
                && secret
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        })
    }
}

/// Matches a Basic token request that presents `secret`.
struct Presents(&'static str);

impl Match for Presents {
    fn matches(&self, request: &Request) -> bool {
        basic_secret(request).as_deref() == Some(self.0)
    }
}

fn refusal(result: Result<TenantOAuthProviderRecord, OAuthError>) -> String {
    match result {
        Err(OAuthError::Config(text)) => text,
        Err(other) => panic!("expected a refusal by name, got {other:?}"),
        Ok(stored) => panic!("the record was stored: {}", stored.name),
    }
}

/// The secrets the token requests presented, in order.
async fn presented(server: &MockServer) -> Vec<Option<String>> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|request| request.url.path() == "/token")
        .map(basic_secret)
        .collect()
}

/// A provider that refuses a malformed secret as `invalid_client` and
/// answers any well-formed one with `invalid_grant` never checked the
/// secret: a tenant guessing a well-formed secret it does not hold is
/// refused as unproven, because the control is as well-formed as the guess.
/// A malformed guess is refused as not authenticated.
#[tokio::test]
async fn a_provider_that_checks_only_the_shape_of_a_secret_proves_nothing() {
    let server = idp().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(WellFormedSecret)
        .respond_with(oauth_error(400, "invalid_grant"))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(oauth_error(401, "invalid_client"))
        .mount(&server)
        .await;
    let directory = directory(TokenEndpointProbe::new());

    let guess = "fedcba9876543210fedcba9876543210";
    let text = refusal(
        directory
            .upsert(record("squatter", &server.uri(), secret(guess)))
            .await,
    );
    assert!(text.contains("ownership is unproven"), "{text}");

    let text = refusal(
        directory
            .upsert(record("squatter", &server.uri(), secret("not-hex-at-all")))
            .await,
    );
    assert!(text.contains("did not authenticate the client"), "{text}");
    assert_eq!(
        directory.holder_of(&server.uri(), CLIENT_ID).await.unwrap(),
        None
    );
}

/// The control comes first, then the client's own request, then the
/// control again: three token requests, the client's secret only in the
/// second, and each control the secret with one character changed.
#[tokio::test]
async fn the_controls_come_before_and_after_the_clients_request() {
    let server = idp().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(Presents(OWNERS_SECRET))
        .respond_with(oauth_error(400, "invalid_grant"))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(oauth_error(401, "invalid_client"))
        .mount(&server)
        .await;

    directory(TokenEndpointProbe::new())
        .upsert(record("owner", &server.uri(), secret(OWNERS_SECRET)))
        .await
        .expect("the secret authenticates and both controls do not");

    let secrets = presented(&server).await;
    assert_eq!(secrets.len(), 3, "{secrets:?}");
    assert_eq!(secrets[1].as_deref(), Some(OWNERS_SECRET));
    for control in [&secrets[0], &secrets[2]] {
        let control = control.as_deref().expect("a Basic secret");
        assert_ne!(control, OWNERS_SECRET);
        assert_eq!(control.len(), OWNERS_SECRET.len());
        assert_eq!(control[..31], OWNERS_SECRET[..31], "the prefix is kept");
    }
}

/// A first control that is not refused as `invalid_client` proves nothing,
/// and the client's own secret is then never sent.
#[tokio::test]
async fn a_first_control_not_refused_sends_no_credential() {
    let server = idp().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(oauth_error(400, "invalid_grant"))
        .mount(&server)
        .await;

    let text = refusal(
        directory(TokenEndpointProbe::new())
            .upsert(record("owner", &server.uri(), secret(OWNERS_SECRET)))
            .await,
    );

    assert!(text.contains("ownership is unproven"), "{text}");
    let secrets = presented(&server).await;
    assert_eq!(secrets.len(), 1, "{secrets:?}");
    assert_ne!(secrets[0].as_deref(), Some(OWNERS_SECRET));
}

/// The answers a control can meet that are not `invalid_client`: a rate
/// limit, an outage, and no answer within the probe's timeout. Each is
/// unproven, whether it meets the first control or the second, though the
/// client's own request is refused as a grant.
#[tokio::test]
async fn a_control_answered_with_anything_but_invalid_client_proves_nothing() {
    let answers = [
        ("429", oauth_error(429, "slow_down")),
        (
            "503",
            ResponseTemplate::new(503).set_body_string("unavailable"),
        ),
        (
            "no answer",
            oauth_error(401, "invalid_client").set_delay(Duration::from_secs(5)),
        ),
    ];
    for (named, answer) in answers {
        for (control, first_control) in [("first", None), ("second", Some(1))] {
            let server = idp().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(Presents(OWNERS_SECRET))
                .respond_with(oauth_error(400, "invalid_grant"))
                .with_priority(1)
                .mount(&server)
                .await;
            if let Some(times) = first_control {
                Mock::given(method("POST"))
                    .and(path("/token"))
                    .respond_with(oauth_error(401, "invalid_client"))
                    .up_to_n_times(times)
                    .with_priority(2)
                    .mount(&server)
                    .await;
            }
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(answer.clone())
                .with_priority(3)
                .mount(&server)
                .await;
            let directory =
                directory(TokenEndpointProbe::new().with_timeout(Duration::from_millis(300)));

            let text = refusal(
                directory
                    .upsert(record("owner", &server.uri(), secret(OWNERS_SECRET)))
                    .await,
            );

            assert!(
                text.contains("ownership is unproven"),
                "{named}, {control} control: {text}"
            );
            assert_eq!(
                directory.holder_of(&server.uri(), CLIENT_ID).await.unwrap(),
                None,
                "{named}, {control} control"
            );
        }
    }
}

/// Matches a token request whose `client_assertion` carries a signature
/// the RSA key `jwk` made with the lowest bit of its last byte flipped.
struct SignedThenAltered(DecodingKey);

impl Match for SignedThenAltered {
    fn matches(&self, request: &Request) -> bool {
        let Some(assertion) = url::form_urlencoded::parse(&request.body)
            .find(|(name, _)| name == "client_assertion")
            .map(|(_, value)| value.into_owned())
        else {
            return false;
        };
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let Some((signed, signature)) = assertion.rsplit_once('.') else {
            return false;
        };
        let Ok(mut bytes) = engine.decode(signature) else {
            return false;
        };
        let Some(last) = bytes.last_mut() else {
            return false;
        };
        *last ^= 1;
        let restored = format!("{signed}.{}", engine.encode(bytes));
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        axess_factors::jwt::decode::<serde_json::Value>(&restored, &self.0, &validation).is_ok()
    }
}

/// The control assertion is the key's own signature with the lowest bit of
/// its last byte flipped: as long as a real one and encoded the same way, so
/// a provider that checks the signature's shape before the key sees nothing
/// amiss until the key check.
#[tokio::test]
async fn the_control_assertion_differs_from_a_signature_in_one_bit() {
    let (der, jwk, _) = oauth_generate_rsa_keypair();
    let component = |name: &str| jwk[name].as_str().unwrap_or_default().to_string();
    let key = DecodingKey::from_rsa_components(&component("n"), &component("e"))
        .expect("the fixture's JWK is an RSA key");
    let server = idp().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(SignedThenAltered(key))
        .respond_with(oauth_error(401, "invalid_client"))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(oauth_error(400, "invalid_grant"))
        .mount(&server)
        .await;
    let credential = TenantClientCredential::PrivateKeyJwt {
        key_pem: FactorSecret::Plain(oauth_rsa_private_pem(&der).into()),
        signer: SignerSpec::new(jsonwebtoken::Algorithm::RS256),
    };

    directory(TokenEndpointProbe::new())
        .upsert(record("owner", &server.uri(), credential))
        .await
        .expect("each control is the key's signature with one bit flipped");
}

/// Two tenants that both pass the probe for one pair, registering at the
/// same moment: the proofs run side by side, and one record is stored while
/// the other is refused as a held pair.
#[tokio::test]
async fn two_registrations_proven_at_once_store_one_record() {
    let server = MockServer::start().await;
    // Discovery waits, so both registrations pass the first check of the
    // pair before either is written.
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(oauth_discovery_document(&server.uri()))
                .set_delay(Duration::from_millis(200)),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header(
            "authorization",
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{CLIENT_ID}:{OWNERS_SECRET}"))
            )
            .as_str(),
        ))
        .respond_with(oauth_error(400, "invalid_grant"))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(oauth_error(401, "invalid_client"))
        .mount(&server)
        .await;
    let directory = Arc::new(directory(TokenEndpointProbe::new()));
    let issuer = server.uri();

    let (first, second) = tokio::join!(
        directory.upsert(record("acme", &issuer, secret(OWNERS_SECRET))),
        directory.upsert(record("beta", &issuer, secret(OWNERS_SECRET))),
    );

    let outcomes = [first, second];
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "{outcomes:?}"
    );
    let refused = outcomes
        .into_iter()
        .find_map(Result::err)
        .expect("one is refused");
    let text = refusal(Err(refused));
    assert!(
        text.contains("already registered by another record"),
        "{text}"
    );
    let holders = [
        directory.store().get(&tenant("acme"), "sso").await.unwrap(),
        directory.store().get(&tenant("beta"), "sso").await.unwrap(),
    ];
    assert_eq!(holders.iter().flatten().count(), 1, "one record is stored");
}
