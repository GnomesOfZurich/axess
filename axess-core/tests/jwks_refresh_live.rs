//! The background JWKS refresh loop follows the live provider registry: after
//! a reload the next pass fetches the new key set URL and not the old one, and
//! a provider removed before the first pass is never polled.
//!
//! Every IdP is a wiremock server on localhost.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test jwks_refresh_live`

#![cfg(all(feature = "testing", feature = "oauth"))]

mod common;

use axess_core::authn::service::AuthnService;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_factors::oauth::{OAuthError, OAuthProviderBuilder, OAuthProviderConfig};
use axess_testing::oauth_wiremock::{oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints};
use common::{test_tenant, test_user};
use std::time::Duration;
use wiremock::MockServer;

const REDIRECT: &str = "http://localhost:3000/callback";
const TICK: Duration = Duration::from_millis(40);

async fn idp(keys: &serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    oauth_mount_oidc_endpoints(&server, keys).await;
    server
}

async fn candidate(name: &str, uri: &str) -> Result<OAuthProviderConfig, OAuthError> {
    OAuthProviderConfig::discover(name, uri, "client", "secret", REDIRECT)
        .await
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

/// Wait up to two seconds, in 20 ms steps, for `check` to hold.
async fn within_two_seconds(what: &str, mut check: impl AsyncFnMut() -> bool) {
    for _ in 0..100 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("did not happen within 2s: {what}");
}

fn service(
    providers: Vec<OAuthProviderConfig>,
    tick: Duration,
) -> AuthnService<MockIdentityStore, MockFactorStore> {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let mut builder = AuthnService::builder(identity, MockFactorStore::new());
    for provider in providers {
        builder = builder.with_oauth_provider(provider);
    }
    builder.with_jwks_refresh(tick).build()
}

#[tokio::test]
async fn after_a_reload_the_loop_fetches_the_new_key_set_and_not_the_old_one() {
    let (_, jwks, _) = oauth_generate_rsa_keypair();
    let old = idp(&jwks).await;
    let new = idp(&jwks).await;
    let service = service(vec![candidate("sso", &old.uri()).await.unwrap()], TICK);

    service
        .reload_oauth_provider("sso", candidate("sso", &new.uri()))
        .await
        .expect("a reachable provider is accepted");
    let old_before = key_set_fetches(&old).await;

    within_two_seconds(
        "the loop fetches the reloaded provider's key set",
        async || key_set_fetches(&new).await > 0,
    )
    .await;
    // Further passes keep going to the new URL only.
    tokio::time::sleep(TICK * 5).await;
    assert_eq!(
        key_set_fetches(&old).await,
        old_before,
        "the replaced provider's key set is no longer polled"
    );
}

/// A key set fetch is debounced for 60 s after the last one, so a provider the
/// loop already polled is not fetched again within a test's window whether or
/// not the loop still holds it. The removal is therefore made before the loop's
/// first pass: a loop that still held the provider would fetch it on that pass
/// (nothing has fetched it yet), a loop that reads the live registry never
/// does.
#[tokio::test]
async fn a_provider_removed_before_the_first_pass_is_never_polled_by_the_loop() {
    let (_, jwks, _) = oauth_generate_rsa_keypair();
    let kept = idp(&jwks).await;
    let gone = idp(&jwks).await;
    let kept_config = candidate("kept", &kept.uri()).await.unwrap();
    let gone_config = candidate("gone", &gone.uri()).await.unwrap();
    // A tick long enough that the removal below lands before the first pass.
    let tick = Duration::from_millis(400);
    let service = service(vec![kept_config, gone_config], tick);

    service.remove_oauth_provider("gone").await.unwrap();
    let gone_baseline = key_set_fetches(&gone).await;
    let kept_baseline = key_set_fetches(&kept).await;

    within_two_seconds("the loop polls the provider that stayed", async || {
        key_set_fetches(&kept).await > kept_baseline
    })
    .await;
    // Two further passes: a removed provider would have been reached by now.
    tokio::time::sleep(tick * 2).await;
    assert_eq!(
        key_set_fetches(&gone).await,
        gone_baseline,
        "a removed provider is not polled by the loop"
    );
}
