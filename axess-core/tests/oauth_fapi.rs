//! FAPI + PAR_INFLIGHT mutation coverage: single-use marker, audit-event emission, logout delegation.

#![cfg(feature = "testing-oauth")]

mod common;

use axess_clock::Clock;
use axess_core::{
    authn::service::AuthnService,
    testing::{
        MockClock,
        mock_authn::{MockFactorStore, MockIdentityStore},
        oauth_wiremock::{
            oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints, oauth_setup_provider,
        },
        test_session,
    },
};
use axess_factors::oauth::OAuthLoginOptions;
use common::test_tenant;
use wiremock::MockServer;

/// Test-only FAPI provider stub. Returns `Some(FapiConfig)` from
/// `fapi_config()` so the PAR_INFLIGHT guard activates, and
/// supplies a working `build_auth_url_par` so the begin path can
/// complete (which is what stamps the `expires_at` we want to inspect).
struct FapiStubProvider {
    name: std::sync::Arc<str>,
    fapi: axess_factors::oauth::FapiConfig,
    scopes: Vec<String>,
    ceremony_timeout: std::time::Duration,
}

impl FapiStubProvider {
    fn new(name: &str) -> Self {
        Self {
            name: std::sync::Arc::from(name),
            fapi: axess_factors::oauth::FapiConfig::default(),
            scopes: vec!["openid".into()],
            ceremony_timeout: std::time::Duration::from_secs(300),
        }
    }
}

impl axess_factors::oauth::OAuthProvider for FapiStubProvider {
    fn name(&self) -> &std::sync::Arc<str> {
        &self.name
    }
    fn scopes(&self) -> &[String] {
        &self.scopes
    }
    fn ceremony_timeout(&self) -> std::time::Duration {
        self.ceremony_timeout
    }
    fn fapi_config(&self) -> Option<&axess_factors::oauth::FapiConfig> {
        Some(&self.fapi)
    }
    fn refresh_token<'a>(
        &'a self,
        refresh_token: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        axess_factors::oauth::OAuthClaims,
                        axess_factors::oauth::OAuthError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let len = refresh_token.len();
        Box::pin(async move {
            Err(axess_factors::oauth::OAuthError::Config(format!(
                "stub (refresh_token {len} bytes)"
            )))
        })
    }
    fn exchange_code<'a>(
        &'a self,
        code: &'a str,
        pkce_verifier: String,
        nonce: String,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        axess_factors::oauth::OAuthClaims,
                        axess_factors::oauth::OAuthError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let code_len = code.len();
        let pkce_len = pkce_verifier.len();
        let nonce_len = nonce.len();
        Box::pin(async move {
            Err(axess_factors::oauth::OAuthError::Config(format!(
                "stub (code {code_len}, pkce {pkce_len}, nonce {nonce_len})"
            )))
        })
    }
    fn fetch_userinfo<'a>(
        &'a self,
        access_token: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        axess_factors::oauth::UserInfoClaims,
                        axess_factors::oauth::OAuthError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let len = access_token.len();
        Box::pin(async move {
            Err(axess_factors::oauth::OAuthError::Config(format!(
                "stub (access_token {len} bytes)"
            )))
        })
    }
    /// Stub `build_end_session_url` so the mutation
    /// `build_end_session_url -> None` flips an observable result.
    fn build_end_session_url(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
    ) -> Option<url::Url> {
        tracing::trace!(
            ?id_token_hint,
            ?state,
            "OAuth provider stub: build_end_session_url",
        );
        let mut u = url::Url::parse("https://idp.example.com/logout").ok()?;
        if let Some(redir) = post_logout_redirect_uri {
            u.query_pairs_mut()
                .append_pair("post_logout_redirect_uri", redir);
        }
        Some(u)
    }

    /// Mint a deterministic auth URL + csrf/nonce/verifier triple so
    /// `begin_oauth_login` can reach the PAR-inflight stash step.
    fn build_auth_url_par<'a>(
        &'a self,
        options: &'a axess_factors::oauth::OAuthLoginOptions,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        axess_factors::oauth::AuthUrlResult,
                        axess_factors::oauth::OAuthError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        tracing::trace!(?options, "OAuth provider stub: build_auth_url_par");
        Box::pin(async move {
            let url = url::Url::parse("https://idp.example.com/authorize?request_uri=urn:ietf:params:oauth:request_uri:stub").unwrap();
            Ok((
                url,
                "stub-csrf-state".to_string(),
                "stub-nonce".to_string(),
                "a".repeat(43),
            ))
        })
    }
}

/// when an active PAR_INFLIGHT has an `expires_at` in the
/// **future**, `begin_oauth_login` MUST refuse with `CsrfMismatch`.
/// Pins the `<` operator on line 114: mutating to `==` or `>` would
/// flip the verdict for "now < future" inputs.
#[tokio::test]
async fn begin_oauth_login_refuses_with_par_inflight_in_future() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let clock = MockClock::now();
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(FapiStubProvider::new("fapi-stub"));
    let session = test_session();

    // Stash a PAR marker that expires 60 s from MockClock's "now".
    let future = clock.now() + chrono::Duration::seconds(60);
    let mut entry = serde_json::Map::new();
    entry.insert(
        "expires_at".to_string(),
        serde_json::Value::String(future.to_rfc3339()),
    );
    session
        .set_custom("axess.oauth.par_inflight", serde_json::Value::Object(entry))
        .await;

    let result = authn
        .begin_oauth_login("fapi-stub", &OAuthLoginOptions::default(), &session)
        .await;
    assert!(matches!(
        result.unwrap_err(),
        axess_factors::oauth::OAuthError::CsrfMismatch
    ));
}

/// when PAR_INFLIGHT `expires_at` is **exactly equal** to
/// the current clock, the ceremony is no longer single-use-blocked:
/// `begin_oauth_login` must SUCCEED. Pins the `<` operator
/// against `<=`: at equality, original false (no refusal), `<=`
/// would flip to true (refusal).
#[tokio::test]
async fn begin_oauth_login_succeeds_with_par_inflight_at_exact_now() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let clock = MockClock::now();
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(FapiStubProvider::new("fapi-stub-eq"));
    let session = test_session();

    let exactly_now = clock.now();
    let mut entry = serde_json::Map::new();
    entry.insert(
        "expires_at".to_string(),
        serde_json::Value::String(exactly_now.to_rfc3339()),
    );
    session
        .set_custom("axess.oauth.par_inflight", serde_json::Value::Object(entry))
        .await;

    let result = authn
        .begin_oauth_login("fapi-stub-eq", &OAuthLoginOptions::default(), &session)
        .await;
    assert!(
        result.is_ok(),
        "at exact equality of now and PAR expires_at, begin must succeed (got {result:?})"
    );
}

/// pins the `+` chrono::Duration arithmetic in the
/// PAR_INFLIGHT stash on line 148. After a successful FAPI begin, the
/// stored `expires_at` must lie **strictly after** the clock; a
/// `+ -> -` mutation would leave the marker in the past, defeating
/// the entire PAR-inflight single-use guard.
#[tokio::test]
async fn par_inflight_expires_at_is_in_the_future() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let clock = MockClock::now();
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(FapiStubProvider::new("fapi-stub-fut"));
    let session = test_session();

    let now = clock.now();
    authn
        .begin_oauth_login("fapi-stub-fut", &OAuthLoginOptions::default(), &session)
        .await
        .expect("FAPI begin should stash a PAR marker");

    let stored = session.get_custom("axess.oauth.par_inflight").await;
    let map = match stored {
        Some(serde_json::Value::Object(m)) => m,
        other => panic!("PAR_INFLIGHT not stored as object, got {other:?}"),
    };
    let expires_at_str = map
        .get("expires_at")
        .and_then(|v| v.as_str())
        .expect("expires_at field");
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at_str)
        .expect("RFC3339 expires_at")
        .with_timezone(&chrono::Utc);
    assert!(
        expires_at > now,
        "PAR_INFLIGHT expires_at ({expires_at}) must lie after clock now ({now})"
    );
}

/// `record_oauth_failure` must actually emit a `Failure`
/// audit event. The mutation `record_oauth_failure -> ()` would
/// silently turn the failure-recording calls into no-ops; every
/// CSRF-mismatch / expired-ceremony / PKCE-invalid would still
/// surface as an `OAuthError` to the caller, but the SOC trail
/// would go dark. This test drives a CSRF mismatch and asserts the
/// audit log carries a Failure event tagged `csrf_mismatch`.
#[tokio::test]
async fn csrf_mismatch_records_failure_audit_event() {
    use axess_core::authn::event::AuthEventStatus;

    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = oauth_setup_provider(&server).await;

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn =
        AuthnService::new(identity.clone(), MockFactorStore::new()).with_oauth_provider(provider);
    let session = test_session();
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .unwrap();

    let _ = authn
        .finish_oauth_login("any-code", "wrong-state", &session)
        .await;

    let events = identity.events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event_status, AuthEventStatus::Failure)
                && e.error.as_deref() == Some("csrf_mismatch")),
        "expected a Failure audit event tagged csrf_mismatch, got {events:?}"
    );
}

/// `build_end_session_url` must delegate to the provider:
/// not return `None` unconditionally. With the FAPI stub providing a
/// `Some(...)` return, calling through `AuthnService` MUST surface
/// the same `Some`. The mutation `build_end_session_url -> None`
/// silently disables RP-Initiated Logout for every caller.
#[tokio::test]
async fn build_end_session_url_delegates_to_provider() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_oauth_provider(FapiStubProvider::new("logout-stub"));

    let url = authn.build_end_session_url(
        "logout-stub",
        Some("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.jwt"),
        Some("https://app.example.com/post-logout"),
        None,
    );

    let url = url.expect("stub returns Some; facade must propagate");
    let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(
        pairs.get("post_logout_redirect_uri").map(String::as_str),
        Some("https://app.example.com/post-logout"),
        "facade must pass through the post_logout_redirect_uri arg"
    );
}

/// `clear_oauth_state` must remove every key the OAuth
/// ceremony writes, including keys that a fresh `begin_oauth_login`
/// does NOT overwrite. `EXPECTED_TENANT` is the canary: only
/// `begin_oauth_login_in_tenant` sets it, so a stale value from a
/// previous tenant-scoped flow would leak into a subsequent
/// non-tenant flow if `clear_oauth_state` were a no-op (the
/// `replace with ()` mutation).
#[tokio::test]
async fn begin_oauth_login_clears_stale_expected_tenant() {
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = oauth_setup_provider(&server).await;

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(provider);
    let session = test_session();

    session
        .set_custom(
            "axess.oauth.expected_tenant",
            serde_json::Value::String("stale-tenant-from-prev-flow".into()),
        )
        .await;

    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin should succeed");

    let after = session.get_custom("axess.oauth.expected_tenant").await;
    assert!(
        after.is_none(),
        "clear_oauth_state must wipe stale EXPECTED_TENANT before new ceremony, got {after:?}"
    );
}
