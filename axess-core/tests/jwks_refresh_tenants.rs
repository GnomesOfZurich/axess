//! The JWKS refresh covers the providers tenants hold, not only the
//! service's own, and one slow provider does not hold up the others.
//!
//! Every IdP is a wiremock server on localhost.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test jwks_refresh_tenants`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::factor::FederatedProvider;
use axess_core::authn::ids::testing::tenant;
use axess_core::authn::service::AuthnService;
use axess_core::federation::oauth_tenant::LiveTenantOAuthProviders;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_factors::oauth::{OAuthError, OAuthProviderBuilder, OAuthProviderConfig};
use axess_testing::oauth_wiremock::{oauth_discovery_document, oauth_generate_rsa_keypair};
use common::{provider_admin, test_tenant};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REDIRECT: &str = "http://localhost:3000/callback";

async fn idp(jwks_delay: Duration) -> MockServer {
    let (_, jwk, _) = oauth_generate_rsa_keypair();
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
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(jwks_delay)
                .set_body_json(serde_json::json!({ "keys": [jwk] })),
        )
        .mount(&server)
        .await;
    server
}

async fn candidate(
    name: &str,
    uri: &str,
    clock: &MockClock,
) -> Result<OAuthProviderConfig, OAuthError> {
    OAuthProviderConfig::discover_screened(
        name,
        uri,
        "client",
        "secret",
        REDIRECT,
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .map(|b| b.with_clock(Arc::new(clock.clone())))
    .and_then(OAuthProviderBuilder::build)
}

async fn key_set_fetches(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == "/jwks")
        .count()
}

fn service(
    clock: &MockClock,
    live: &Arc<LiveTenantOAuthProviders>,
) -> AuthnService<MockIdentityStore, MockFactorStore> {
    AuthnService::builder(
        MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant()),
        MockFactorStore::new(),
    )
    .with_clock(clock.clone())
    .with_live_tenant_oauth_providers(live.clone())
    .build()
}

#[tokio::test]
async fn a_pass_refreshes_the_providers_tenants_hold() {
    let clock = common::test_clock();
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let service = service(&clock, &live);
    let server = idp(Duration::ZERO).await;
    service
        .with_audit_context(AuditContext::default())
        .reload_tenant_oauth_provider_as(
            &provider_admin(),
            &tenant("acme"),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate("sso", &server.uri(), &clock),
        )
        .await
        .expect("the tenant provider is installed");
    let built = key_set_fetches(&server).await;

    // Past the provider's 60 s debounce on its own clock.
    clock.advance(axess_clock::SignedDuration::seconds(61));
    let failures = service.refresh_all_jwks().await;

    assert!(failures.is_empty(), "{failures:?}");
    assert!(
        key_set_fetches(&server).await > built,
        "the tenant provider's key set was not refreshed"
    );
}

#[tokio::test]
async fn one_slow_key_set_does_not_hold_the_others_back() {
    const SLOW: Duration = Duration::from_millis(700);
    let clock = common::test_clock();
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let service = service(&clock, &live);
    let mut servers = Vec::new();
    for n in 0..4 {
        let server = idp(SLOW).await;
        service
            .with_audit_context(AuditContext::default())
            .reload_tenant_oauth_provider_as(
                &provider_admin(),
                &tenant(&format!("t{n}")),
                "sso",
                FederatedProvider::Custom("sso".into()),
                candidate("sso", &server.uri(), &clock),
            )
            .await
            .expect("the tenant provider is installed");
        servers.push(server);
    }

    clock.advance(axess_clock::SignedDuration::seconds(61));
    // The identity providers answer after a real delay, so the time the
    // refresh takes is the machine's, not the world's.
    let watch = axess_testing::stopwatch::Stopwatch::start();
    let failures = service.refresh_all_jwks().await;
    let took = watch.elapsed();

    assert!(failures.is_empty(), "{failures:?}");
    assert!(
        took < SLOW * 3,
        "four 700 ms refreshes took {took:?}: they ran one after another"
    );
}
