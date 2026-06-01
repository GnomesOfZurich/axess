//! Router construction: SessionLayer + AuthnService in Axum state + routes.

use crate::{
    models::backend::OurBackend,
    web::{auth, protected},
};
use axess::authn::AuthnService;
use axess::session::SessionCrypto;
use axess::{
    AuthSession, AuthnMetrics, CompositeHealthCheck, KeyExtractor, RateLimitConfig, RateLimitLayer,
    SecureRng, SessionLayer, SystemRng, backends::sqlite::SessionStore as SqliteSessionStore,
};
use axum::response::{IntoResponse, Redirect};
use axum::{Router, routing::get, routing::post};
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{sync::Arc, time::Duration};

/// Example metrics implementation using atomic counters.
///
/// In production, replace with Prometheus or OpenTelemetry gauges/counters.
/// This demonstrates the pattern; the `AuthnMetrics` trait has no-op defaults
/// so you only override what you need.
#[derive(Default)]
pub struct AppMetrics {
    pub auth_attempts: AtomicU64,
    pub auth_successes: AtomicU64,
    pub auth_failures: AtomicU64,
    pub rate_limit_rejections: AtomicU64,
}

impl AppMetrics {
    pub fn new() -> Self {
        Self {
            auth_attempts: AtomicU64::new(0),
            auth_successes: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            rate_limit_rejections: AtomicU64::new(0),
        }
    }
}

/// Newtype wrapper to implement `AuthnMetrics` (orphan rule requires a local type).
#[derive(Clone)]
pub struct AppMetricsHandle(pub Arc<AppMetrics>);

impl AuthnMetrics for AppMetricsHandle {
    fn auth_attempt(&self) {
        self.0.auth_attempts.fetch_add(1, Ordering::Relaxed);
    }
    fn auth_success(&self) {
        self.0.auth_successes.fetch_add(1, Ordering::Relaxed);
    }
    fn auth_failure(&self) {
        self.0.auth_failures.fetch_add(1, Ordering::Relaxed);
    }
    fn rate_limit_rejected(&self) {
        self.0.rate_limit_rejections.fetch_add(1, Ordering::Relaxed);
    }
}

/// Application state shared across all handlers.
#[derive(Clone)]
pub struct AppState {
    pub service: Arc<AuthnService<OurBackend, OurBackend>>,
    pub backend: OurBackend,
    pub health: Arc<CompositeHealthCheck>,
    pub metrics: Arc<AppMetrics>,
}

/// Build the top-level Axum [`Router`].
///
/// Call once at startup, after migrations have run.
pub async fn build_router(pool: SqlitePool) -> (Router, SqliteSessionStore) {
    let backend = OurBackend::new(pool.clone());

    // SQLite-backed session store with AES-256-GCM encryption at rest.
    // In production, load both keys from a secrets manager and persist them.
    //
    // Key rotation: pass the previous key so sessions encrypted with the old
    // key can still be read. On next write, data is re-encrypted with the
    // current key. Remove `with_previous_key` after a full TTL cycle.
    // Mint random keys through `axess::SystemRng` (the foundation crate's
    // RNG abstraction) rather than `rand::random()` so the example models
    // the same DST-swappable surface the library uses internally.
    let mut encryption_key = [0u8; 32];
    let mut previous_key = [0u8; 32];
    SystemRng.fill_bytes(&mut encryption_key);
    SystemRng.fill_bytes(&mut previous_key); // In production: the prior key from secrets.
    let session_store = SqliteSessionStore::new(
        pool.clone(),
        SessionCrypto::new(encryption_key).with_previous_key(previous_key),
    );
    session_store
        .init_schema()
        .await
        .expect("failed to create sessions table");

    // HMAC signing key for session cookies; separate from the encryption key.
    // In production, load from a secrets manager and persist across restarts.
    let mut signing_key = [0u8; 32];
    SystemRng.fill_bytes(&mut signing_key);

    let health = Arc::new(CompositeHealthCheck::new().add("session_store", session_store.clone()));

    let session_layer = SessionLayer::new(session_store.clone(), signing_key)
        .with_ttl(Duration::from_secs(86400))
        .with_secure(false); // Allow HTTP in local dev; set true behind TLS in prod.

    let metrics = Arc::new(AppMetrics::new());

    // Rate limiting: 10 requests per minute per IP on authentication endpoints.
    // This is defense-in-depth alongside the per-user lockout policy.
    let auth_rate_limit = RateLimitLayer::new(
        RateLimitConfig::builder()
            .max_requests(10)
            .window(Duration::from_secs(60))
            .key(KeyExtractor::PeerIp)
            .build(),
    )
    .with_metrics(AppMetricsHandle(metrics.clone()));

    let state_backend = backend.clone();
    let service = Arc::new(
        AuthnService::new(backend.clone(), backend).with_metrics(AppMetricsHandle(metrics.clone())),
    );
    let state = AppState {
        service,
        backend: state_backend,
        health,
        metrics,
    };

    // Auth routes; rate-limited.
    let auth_routes = Router::new()
        .route("/login", get(auth::login_page).post(auth::post_login))
        .route("/signup", get(auth::signup_page).post(auth::post_signup))
        .route("/totp", get(auth::totp_page).post(auth::post_totp))
        .route(
            "/forgot-password",
            get(auth::forgot_password_page).post(auth::post_forgot_password),
        )
        .route(
            "/reset-password",
            get(auth::reset_password_page).post(auth::post_reset_password),
        )
        .layer(auth_rate_limit);

    // Non-rate-limited routes.
    let router = Router::new()
        .merge(auth_routes)
        .route("/", get(root))
        .route(
            "/setup-totp",
            get(auth::setup_totp_page).post(auth::post_setup_totp),
        )
        .route("/logout", post(auth::logout))
        .route("/dashboard", get(protected::dashboard))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_endpoint))
        .with_state(state)
        .layer(session_layer);

    (router, session_store)
}

/// Root landing: send authenticated users to their dashboard, everyone
/// else to the login page (which lists the seeded test accounts).
/// Avoids the blank-404 a new visitor would otherwise see at `/`.
async fn root(session: AuthSession) -> Redirect {
    if session.is_authenticated().await {
        Redirect::to("/dashboard")
    } else {
        Redirect::to("/login")
    }
}

/// `GET /healthz`; operational readiness probe for auth-related backends.
///
/// This checks axess components only (session store, etc.). In production,
/// combine with your application's own health checks (database, message
/// queues, external APIs) into a single composite endpoint. The route
/// name is your choice; `/healthz` follows the Kubernetes convention.
async fn healthz(axum::extract::State(state): axum::extract::State<AppState>) -> impl IntoResponse {
    let status = state.health.check_all().await;
    let code = if status.is_healthy() {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    let body = serde_json::json!({
        "status": if status.is_healthy() { "healthy" } else { "unhealthy" },
        "components": status.components.iter().map(|(name, s)| {
            serde_json::json!({ "name": name, "status": format!("{s:?}") })
        }).collect::<Vec<_>>(),
    });
    (code, axum::Json(body))
}

/// `GET /metrics`; expose authentication counters.
///
/// These are axess-specific metrics (auth attempts, failures, rate limit
/// rejections). In production, merge these into your application's metrics
/// endpoint (Prometheus, OpenTelemetry) alongside your own business metrics.
/// The route name follows the Prometheus `/metrics` convention.
async fn metrics_endpoint(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl IntoResponse {
    let m = &state.metrics;
    axum::Json(serde_json::json!({
        "auth_attempts": m.auth_attempts.load(Ordering::Relaxed),
        "auth_successes": m.auth_successes.load(Ordering::Relaxed),
        "auth_failures": m.auth_failures.load(Ordering::Relaxed),
        "rate_limit_rejections": m.rate_limit_rejections.load(Ordering::Relaxed),
    }))
}
