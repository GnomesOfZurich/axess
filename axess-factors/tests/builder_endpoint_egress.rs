#![cfg(feature = "oauth")]
//! An endpoint named through a builder setter is held to the egress policy
//! discovery ran under, as an endpoint the discovery document names is: on
//! a screened provider a literal address in a reserved range is refused at
//! `build`, by the setting's name, and an unscreened provider takes it.

use axess_clock::testing::MockClock;
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::{OAuthError, OAuthProviderBuilder, OAuthProviderConfig};
use axess_testing::oauth_wiremock::oauth_discovery_document;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

async fn discovered(
    clock: &MockClock,
    idp: &MockServer,
    policy: EgressPolicy,
) -> OAuthProviderBuilder {
    OAuthProviderConfig::discover_screened(
        "idp",
        &idp.uri(),
        "client",
        "secret",
        "https://rp.example/callback",
        policy,
    )
    .await
    .expect("discovery over the loopback identity provider")
    .with_clock(std::sync::Arc::new(clock.clone()))
}

type Setter = fn(OAuthProviderBuilder, &str) -> OAuthProviderBuilder;

/// Each setter, with the setting name its refusal carries.
fn setters() -> [(&'static str, Setter); 4] {
    [
        ("pushed_authorization_request_endpoint", |b, url| {
            b.with_par_endpoint(url)
        }),
        ("revocation_endpoint", |b, url| {
            b.with_revocation_endpoint(url)
        }),
        ("end_session_endpoint", |b, url| {
            b.with_end_session_endpoint(url)
        }),
        ("device_authorization_endpoint", |b, url| {
            b.with_device_authorization_endpoint(url)
        }),
    ]
}

/// HTTPS URLs whose host is an address the screen refuses, and the range
/// the refusal names.
const RESERVED: [(&str, &str); 4] = [
    ("https://10.0.0.5/endpoint", "private"),
    ("https://169.254.169.254/latest", "metadata"),
    ("https://[fd00::1]/endpoint", "unique-local"),
    ("https://100.64.0.1/endpoint", "shared-address"),
];

/// Discovery against the loopback identity provider runs under the policy
/// that lets tests reach loopback; every other range stays screened, so each
/// setter's endpoint on a reserved address is refused, by the setting's name
/// and the range, without the URL.
#[tokio::test]
async fn a_screened_provider_refuses_a_setter_endpoint_on_a_reserved_address() {
    let clock = MockClock::at_reference();
    let idp = loopback_idp().await;
    for (what, set) in setters() {
        for (url, range) in RESERVED {
            let builder = discovered(
                &clock,
                &idp,
                EgressPolicy::screened_allowing_loopback_http(),
            )
            .await;
            let Err(err) = set(builder, url).build() else {
                panic!("{what} {url}: a reserved address is refused");
            };
            let OAuthError::Config(message) = err else {
                panic!("{what}: refused as Config, got {err:?}");
            };
            assert!(message.contains(what), "{what}: {message}");
            assert!(message.contains(range), "{what} {url}: {message}");
            assert!(!message.contains(url), "the URL is not echoed: {message}");
        }
    }
}

/// A host name passes the check at build (it is screened again on the
/// addresses it resolves to, at connect), and an unscreened provider takes a
/// reserved address: the policy decides, not the setter.
#[tokio::test]
async fn a_name_passes_and_an_unscreened_provider_takes_a_reserved_address() {
    let clock = MockClock::at_reference();
    let idp = loopback_idp().await;
    for (what, set) in setters() {
        let builder = discovered(
            &clock,
            &idp,
            EgressPolicy::screened_allowing_loopback_http(),
        )
        .await;
        set(builder, "https://idp.example/endpoint")
            .build()
            .unwrap_or_else(|e| panic!("{what}: a name is screened at connect: {e}"));
        for (url, _) in RESERVED {
            let builder = discovered(&clock, &idp, EgressPolicy::unscreened()).await;
            set(builder, url)
                .build()
                .unwrap_or_else(|e| panic!("{what} {url}: unscreened takes it: {e}"));
        }
    }
}
