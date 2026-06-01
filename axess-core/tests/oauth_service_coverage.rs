//! Mutation-coverage backfill for `oauth_service`: size guards, expiry
//! boundary, revoke, and the JWKS single-flight + min-interval debounce.

#![cfg(feature = "testing-oauth")]

mod common;

use axess_core::{
    authn::service::AuthnService,
    testing::{
        MockClock,
        mock_authn::{MockFactorStore, MockIdentityStore},
        oauth_wiremock::{
            oauth_discovery_document, oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints,
            oauth_setup_provider,
        },
        test_session,
    },
};
use axess_factors::oauth::OAuthLoginOptions;
use common::test_tenant;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// the `MAX_OAUTH_PARAM_BYTES` guard on `finish_oauth_login`
/// must reject a `code` that is exactly **one byte over** the cap with
/// `OAuthError::InvalidParameter`. This pins both the `>` operator
/// (mutating to `==`/`>=` would rephrase the boundary) and the `||`
/// short-circuit (mutating to `&&` would let an oversized `code`
/// through when `state` is small).
#[tokio::test]
async fn finish_oauth_login_rejects_oversized_code() {
    use axess_core::validation::MAX_OAUTH_PARAM_BYTES;
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("size-idp").with_user("u", "u@e.com", vec![], vec![]);
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(mock);
    let session = test_session();

    let oversized_code = "a".repeat(MAX_OAUTH_PARAM_BYTES + 1);
    let result = authn
        .finish_oauth_login(&oversized_code, "any-state", &session)
        .await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::InvalidParameter
    ));
}

/// at the exact `MAX_OAUTH_PARAM_BYTES` byte length, the
/// guard MUST NOT trip; we still expect the request to fail later
/// in the function, but with `NoFlow` (no ceremony in progress)
/// rather than `InvalidParameter`. This boundary differentiates the
/// `>` operator from `>=` and `==`.
#[tokio::test]
async fn finish_oauth_login_accepts_at_boundary() {
    use axess_core::validation::MAX_OAUTH_PARAM_BYTES;
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("size-idp2").with_user("u", "u@e.com", vec![], vec![]);
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(mock);
    let session = test_session();

    let exactly_max = "a".repeat(MAX_OAUTH_PARAM_BYTES);
    let result = authn
        .finish_oauth_login(&exactly_max, &exactly_max, &session)
        .await;
    match result {
        Err(axess_factors::oauth::OAuthError::NoFlow) => {}
        Err(axess_factors::oauth::OAuthError::InvalidParameter) => panic!(
            "code/state of exactly {MAX_OAUTH_PARAM_BYTES} bytes must NOT trip the size guard"
        ),
        other => panic!("expected NoFlow at boundary, got {other:?}"),
    }
}

/// also pin the `state` side of the `||` (mutating it to
/// `&&` would let an oversized `state` through when `code` is small).
#[tokio::test]
async fn finish_oauth_login_rejects_oversized_state() {
    use axess_core::validation::MAX_OAUTH_PARAM_BYTES;
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("size-idp3").with_user("u", "u@e.com", vec![], vec![]);
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(mock);
    let session = test_session();

    let oversized_state = "s".repeat(MAX_OAUTH_PARAM_BYTES + 1);
    let result = authn
        .finish_oauth_login("short-code", &oversized_state, &session)
        .await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::InvalidParameter
    ));
}

/// `is_oauth_expired` boundary: at exactly the configured
/// `ceremony_timeout`, the ceremony is NOT yet expired. Pins the
/// `>` comparison: `>=`/`==`/`<` would all flip the verdict at the
/// boundary.
#[tokio::test]
async fn oauth_ceremony_not_expired_at_exact_boundary() {
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = oauth_setup_provider(&server).await;

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let clock = MockClock::now();
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(provider);

    let session = test_session();
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .unwrap();

    let stored_state = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap();

    // Exactly the 10-minute RFC 6749 cap. `>` says NOT expired; `>=`/`==`
    // would say expired.
    clock.advance_secs(600);

    let result = authn
        .finish_oauth_login("any-code", &stored_state, &session)
        .await;
    // Any non-Expired outcome (CSRF mismatch, token exchange failure, ...)
    // is acceptable; we only care that it didn't trip the expiry guard.
    if let Err(axess_factors::oauth::OAuthError::Expired) = result {
        panic!("ceremony at exactly 600s must NOT be expired (boundary check)");
    }
}

/// `revoke_oauth_token` against an unknown provider must
/// return `OAuthError::UnknownProvider`, not the trait-default
/// `Ok(())` that a `replace -> Ok(())` mutation would silently
/// install. Without this, a token revocation request to a typo'd
/// provider name silently succeeds: the operator's audit trail
/// records "revoked" for tokens still live at the IdP.
#[tokio::test]
async fn revoke_oauth_token_unknown_provider_errors() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new());

    let result = authn
        .revoke_oauth_token("nonexistent", "some-token", Some("access_token"))
        .await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::UnknownProvider(_)
    ));
}

/// N concurrent `refresh_jwks` calls collapse into a single outbound HTTPS
/// GET. Without the single-flight + min-interval debounce, an IdP key
/// rotation that surfaces as N simultaneous unknown-`kid` token validations
/// would fan out to N parallel JWKS fetches and trip the IdP rate-limiter.
#[tokio::test]
async fn jwks_concurrent_refreshes_coalesce_to_single_fetch() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let server = MockServer::start().await;
    let issuer = server.uri();

    // Discovery is mounted normally; only fired once during setup.
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oauth_discovery_document(&issuer)))
        .mount(&server)
        .await;

    // JWKS endpoint counts every hit. Setup itself fires one fetch via
    // `discover()`; we measure refresh fan-out as `count_after - 1`.
    let jwks_hits = Arc::new(AtomicUsize::new(0));
    let jwks_hits_handler = Arc::clone(&jwks_hits);
    let (_priv_der, jwk, _kid) = oauth_generate_rsa_keypair();
    let body = json!({ "keys": [jwk] });
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(move |_: &wiremock::Request| {
            jwks_hits_handler.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(body.clone())
        })
        .mount(&server)
        .await;

    let provider = Arc::new(oauth_setup_provider(&server).await);

    // Setup may fetch JWKS once or twice (OIDC discovery prefetch + the
    // explicit cache prime). Snapshot whatever it landed on as our
    // baseline; the assertion below measures the *delta* from the
    // concurrent refresh fan-out.
    let baseline = jwks_hits.load(Ordering::SeqCst);
    assert!(
        baseline >= 1,
        "setup_provider must fetch JWKS at least once (got {baseline})"
    );

    // Fan out 32 concurrent refresh calls. With coalescing, the first one
    // wins the lock, fetches once, and subsequent waiters short-circuit on
    // the freshly recorded timestamp.
    let mut joins = Vec::new();
    for _ in 0..32 {
        let p = Arc::clone(&provider);
        joins.push(tokio::spawn(async move { p.refresh_jwks().await }));
    }
    for j in joins {
        j.await.expect("task panic").expect("refresh_jwks Ok");
    }

    let after = jwks_hits.load(Ordering::SeqCst);
    let extra_fetches = after - baseline;
    assert_eq!(
        extra_fetches, 1,
        "32 concurrent refresh_jwks must coalesce into 1 outbound fetch (got {extra_fetches})"
    );
}
