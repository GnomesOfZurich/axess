//! Each concern of the metrics contract reports the paths it names, to the
//! sink of its own concern and to no other, and an adopter that implements one
//! concern builds without the others.

#![cfg(feature = "testing")]

mod common;

use axess_core::authn::{
    factor::{FactorCredential, ZeroizedString},
    service::{AuthnService, LoginOutcome},
};
use axess_core::blocking::KdfExecutor;
use axess_core::metrics::{AxessMetrics, FactorMetrics, MetricSinks, NoopMetrics};
use axess_core::middleware::csrf::{CsrfConfig, CsrfLayer};
use axess_core::session::{
    binding::UserAgentBinding, layer::SessionLayer, store::MemorySessionStore,
};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::testing::{RecordingMetrics, test_session};
use axess_core::{KeyExtractor, RateLimitConfig, RateLimitLayer};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

fn recorder() -> Arc<RecordingMetrics> {
    Arc::new(RecordingMetrics::default())
}

// ── The authentication flow and the factors ─────────────────────────────────

fn service(sinks: MetricSinks) -> AuthnService<MockIdentityStore, MockFactorStore> {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    AuthnService::builder(identity, factors)
        .with_kdf_executor(Arc::new(KdfExecutor::inline()))
        .with_metrics(sinks)
        .build()
}

async fn login(service: &AuthnService<MockIdentityStore, MockFactorStore>, password: &str) {
    let request = service.with_audit_context(Default::default());
    let session = test_session();
    let begun = request
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    assert!(matches!(begun, LoginOutcome::FactorRequired(_)));
    request
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new(password)),
            &session,
        )
        .await
        .unwrap();
}

/// A login attempt reaches the flow sink, and a wrong password reaches the
/// factor sink as an attempt and a failure.
#[tokio::test]
async fn a_login_and_a_wrong_password_reach_the_flow_and_factor_sinks() {
    let flow = recorder();
    let factors = recorder();
    let svc = service(
        MetricSinks::noop()
            .with_auth_flow(flow.clone())
            .with_factors(factors.clone()),
    );
    login(&svc, "wrong").await;

    assert_eq!(flow.count("auth_attempt"), 1);
    assert_eq!(factors.count("factor_attempt"), 1);
    assert_eq!(factors.count("factor_failure"), 1);
    assert_eq!(
        factors.count("auth_attempt"),
        0,
        "the factor sink hears no flow call"
    );
    assert_eq!(
        flow.count("factor_attempt"),
        0,
        "the flow sink hears no factor call"
    );
}

/// A right password is a factor success and completes the login.
#[tokio::test]
async fn a_right_password_is_a_factor_success_and_an_auth_success() {
    let all = recorder();
    let svc = service(MetricSinks::all(all.clone()));
    login(&svc, "Gnomes2+").await;
    assert_eq!(all.count("factor_attempt"), 1);
    assert_eq!(all.count("factor_success"), 1);
    assert_eq!(all.count("factor_failure"), 0);
}

// ── The session layer ───────────────────────────────────────────────────────

async fn log_in_handler(session: axess_core::session::extractor::AuthSession) -> impl IntoResponse {
    let uid = axess_core::authn::ids::testing::user("user1");
    let tid = axess_core::authn::ids::testing::tenant("tenant1");
    session
        .set_authenticated(uid, tid, chrono::Utc::now())
        .await;
    "logged in"
}

async fn check_handler(session: axess_core::session::extractor::AuthSession) -> impl IntoResponse {
    if session.is_authenticated().await {
        (StatusCode::OK, "authenticated")
    } else {
        (StatusCode::UNAUTHORIZED, "not authenticated")
    }
}

fn cookie_of(response: &axum::http::Response<Body>) -> String {
    response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn bound_app(layer: SessionLayer<MemorySessionStore>) -> Router {
    Router::new()
        .route("/login", post(log_in_handler))
        .route("/check", get(check_handler))
        .layer(layer.with_secure(false).with_binding(UserAgentBinding))
}

async fn send(app: &Router, req: Request<Body>) -> axum::http::Response<Body> {
    app.clone().oneshot(req).await.unwrap()
}

fn check(cookie: &str, agent: &str) -> Request<Body> {
    Request::get("/check")
        .header(header::COOKIE, cookie)
        .header(header::USER_AGENT, agent)
        .body(Body::empty())
        .unwrap()
}

/// A replay from another client is a binding mismatch, counted once; a
/// session created by the login is counted too.
#[tokio::test]
async fn a_replay_from_another_client_is_a_binding_mismatch() {
    let sessions = recorder();
    let key = axess_core::testing::test_key(42);
    let layer = SessionLayer::without_registry_insecure(MemorySessionStore::new(), key)
        .with_metrics(MetricSinks::noop().with_session(sessions.clone()));
    let app = bound_app(layer);
    let login = send(
        &app,
        Request::post("/login")
            .header(header::USER_AGENT, "Owner/1.0")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let cookie = cookie_of(&login);
    assert!(sessions.count("session_created") >= 1);

    assert_eq!(
        send(&app, check(&cookie, "Owner/1.0")).await.status(),
        StatusCode::OK
    );
    assert_eq!(sessions.count("session_binding_mismatch"), 0);
    assert_eq!(
        send(&app, check(&cookie, "Thief/1.0")).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(sessions.count("session_binding_mismatch"), 1);
}

/// A session stored before binding was turned on is bound by its next
/// request, and that is counted as a backfill.
#[tokio::test]
async fn binding_a_session_that_stored_no_fingerprint_is_counted() {
    let sessions = recorder();
    let store = MemorySessionStore::new();
    let key = axess_core::testing::test_key(42);
    let unbound = Router::new()
        .route("/login", post(log_in_handler))
        .layer(SessionLayer::without_registry_insecure(store.clone(), key).with_secure(false));
    let bound = bound_app(
        SessionLayer::without_registry_insecure(store, key)
            .with_metrics(MetricSinks::noop().with_session(sessions.clone())),
    );
    let cookie = cookie_of(
        &unbound
            .oneshot(Request::post("/login").body(Body::empty()).unwrap())
            .await
            .unwrap(),
    );
    send(&bound, check(&cookie, "Owner/1.0")).await;
    assert_eq!(sessions.count("session_fingerprint_backfilled"), 1);
    send(&bound, check(&cookie, "Owner/1.0")).await;
    assert_eq!(
        sessions.count("session_fingerprint_backfilled"),
        1,
        "the second request finds the fingerprint stored"
    );
}

/// A fingerprint stored under the previous signing key is re-keyed on the
/// first request after the rotation, and that fallback is counted once.
#[tokio::test]
async fn a_fingerprint_under_the_previous_signing_key_is_counted_as_a_fallback() {
    let rotation = recorder();
    let store = MemorySessionStore::new();
    let old = axess_core::testing::test_key(42);
    let new = axess_core::testing::test_key(43);
    let before = bound_app(SessionLayer::without_registry_insecure(store.clone(), old));
    let after = bound_app(
        SessionLayer::without_registry_insecure(store, new)
            .with_previous_signing_key(old)
            .with_metrics(MetricSinks::noop().with_rotation(rotation.clone())),
    );
    let login = send(
        &before,
        Request::post("/login")
            .header(header::USER_AGENT, "Owner/1.0")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let cookie = cookie_of(&login);

    assert_eq!(
        send(&after, check(&cookie, "Owner/1.0")).await.status(),
        StatusCode::OK
    );
    assert_eq!(rotation.count("fingerprint_key_fallback"), 1);
}

// ── Rate limiting and CSRF ──────────────────────────────────────────────────

/// The second request inside the window is rejected and counted; the first
/// is counted as allowed.
#[tokio::test]
async fn a_rate_limit_rejection_reaches_the_request_guard_sink() {
    let guard = recorder();
    let layer = RateLimitLayer::new(
        RateLimitConfig::builder()
            .max_requests(1)
            .window(Duration::from_secs(60))
            .key(KeyExtractor::Header("x-client".to_string()))
            .allow_shared_bucket()
            .build(),
    )
    .with_metrics(MetricSinks::noop().with_request_guard(guard.clone()));
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);
    let get_root = || {
        Request::get("/")
            .header("x-client", "one")
            .body(Body::empty())
            .unwrap()
    };

    assert_eq!(send(&app, get_root()).await.status(), StatusCode::OK);
    assert_eq!(
        send(&app, get_root()).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(guard.count("rate_limit_allowed"), 1);
    assert_eq!(guard.count("rate_limit_rejected"), 1);
}

/// A state-changing request with no token is refused and counted with its
/// reason; a safe request is neither.
#[tokio::test]
async fn a_csrf_refusal_reaches_the_request_guard_sink_with_its_reason() {
    let guard = recorder();
    let sinks = MetricSinks::noop().with_request_guard(guard.clone());
    let app = Router::new()
        .route(
            "/form",
            get(|| async { "form" }).post(|| async { "posted" }),
        )
        .layer(CsrfLayer::new(CsrfConfig::new([42u8; 32])).with_metrics(sinks))
        .layer(
            SessionLayer::without_registry_insecure(
                MemorySessionStore::new(),
                axess_core::testing::test_key(42),
            )
            .with_secure(false),
        );

    assert_eq!(
        send(&app, Request::get("/form").body(Body::empty()).unwrap())
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(guard.count("csrf_rejected"), 0);
    assert_eq!(
        send(&app, Request::post("/form").body(Body::empty()).unwrap())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(guard.count("csrf_rejected"), 1);
    assert_eq!(guard.count("csrf_rejected:token_invalid"), 1);
}

// ── The provider registry ───────────────────────────────────────────────────

/// A second provider under one name is reported when the service is built.
/// A debug build then refuses, after the report, so the test reads the
/// recorder either way.
#[cfg(feature = "oauth")]
#[test]
fn a_duplicate_provider_registration_is_reported_at_build() {
    use axess_factors::oauth::MockOAuthProvider;
    let registry = recorder();
    let sinks = MetricSinks::noop().with_provider_registry(registry.clone());
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
            .with_oauth_provider(MockOAuthProvider::new("google"))
            .with_oauth_provider(MockOAuthProvider::new("google"))
            .with_metrics(sinks)
            .build()
    }));
    assert_eq!(registry.count("provider_duplicate_registration"), 1);
    assert_eq!(
        attempt.is_err(),
        cfg!(debug_assertions),
        "a debug build refuses the duplicate, a release build keeps serving"
    );
}

/// A single registration reports nothing.
#[cfg(feature = "oauth")]
#[test]
fn distinct_providers_report_no_duplicate() {
    use axess_factors::oauth::MockOAuthProvider;
    let registry = recorder();
    let _ = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(MockOAuthProvider::new("google"))
        .with_oauth_provider(MockOAuthProvider::new("github"))
        .with_metrics(MetricSinks::noop().with_provider_registry(registry.clone()))
        .build();
    assert_eq!(registry.count("provider_duplicate_registration"), 0);
}

// ── One concern, none of the others ─────────────────────────────────────────

/// An adopter that implements only the factor concern. It names no other
/// trait, and nothing else is required of it.
struct OnlyFactors;

impl FactorMetrics for OnlyFactors {
    fn factor_failure(&self) {}
}

/// The compile-time check: a type with one concern wires to that concern and
/// builds a service; a type with all of them is an `AxessMetrics`.
#[test]
fn an_adopter_implementing_one_concern_builds_without_the_others() {
    fn assert_axess_metrics<M: AxessMetrics>() {}
    assert_axess_metrics::<NoopMetrics>();
    assert_axess_metrics::<RecordingMetrics>();

    let _ = service(MetricSinks::noop().with_factors(Arc::new(OnlyFactors)));
}
