//! Router construction: SessionLayer + AuthnService in Axum state + routes.

use crate::{
    models::backend::OurBackend,
    web::{auth, protected},
};
use axess::authn::{AuthnService, FactorSecretCipher};
use axess::csrf::{CsrfConfig, CsrfLayer};
use axess::session::{LegacyBlobs, SessionCrypto};
use axess::{
    AuthSession, AuthnMetrics, CompositeHealthCheck, KeyExtractor, MemorySessionRegistry,
    RateLimitConfig, RateLimitLayer, SecureRng, SessionLayer, SystemRng,
    backends::sqlite::SessionStore as SqliteSessionStore,
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
    /// Seals TOTP secrets before they are stored; the service holds the same
    /// cipher to open them when a code is checked.
    pub factor_cipher: Arc<FactorSecretCipher>,
}

/// Where the example keeps the key its TOTP secrets are sealed under.
const FACTOR_KEY_FILE: &str = "db/factor-secret.key";

/// How long a TOTP secret still stored in plain text is read, from the start
/// of this run. Each such secret is sealed by the login that verifies it, so
/// the window only has to outlast the users who have not signed in yet. A
/// real deployment writes a fixed date here, so that a restart does not
/// extend it.
const PLAIN_SECRET_WINDOW_DAYS: i64 = 30;

/// The key TOTP secrets are sealed under: 32 bytes, hex encoded, in a file
/// that is created on first use and read on every later start. Secrets sealed
/// under a key that is lost cannot be opened, so unlike the session keys this
/// one must survive a restart. In production, load it from a secrets manager.
fn factor_secret_key() -> [u8; 32] {
    let path = std::env::current_dir().map(|dir| dir.join(FACTOR_KEY_FILE));
    if let Ok(path) = &path
        && let Ok(text) = std::fs::read_to_string(path)
    {
        let text = text.trim();
        let bytes: Option<Vec<u8>> = (text.len() == 64)
            .then(|| {
                (0..32)
                    .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
                    .collect()
            })
            .flatten();
        if let Some(key) = bytes.and_then(|b| <[u8; 32]>::try_from(b).ok()) {
            return key;
        }
        tracing::warn!(path = %path.display(), "factor secret key file is unreadable; making a new key");
    }
    let mut key = [0u8; 32];
    SystemRng.fill_bytes(&mut key);
    if let Ok(path) = &path {
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        let written = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::write(path, hex));
        if let Err(e) = written {
            tracing::warn!(error = %e, "could not keep the factor secret key; TOTP secrets sealed this run will not open after a restart");
        }
    }
    key
}

/// The example's cipher: sealed under `factor_secret_key`, and reading a
/// plain secret for `PLAIN_SECRET_WINDOW_DAYS` so rows written before the
/// cipher existed (Bob's seeded TOTP) are moved by their owner's next login.
pub fn factor_secret_cipher() -> Arc<FactorSecretCipher> {
    let until =
        axess::Clock::now(&axess::SystemClock) + chrono::Duration::days(PLAIN_SECRET_WINDOW_DAYS);
    Arc::new(
        FactorSecretCipher::new(factor_secret_key())
            .with_plain_secrets(LegacyBlobs::AcceptUntil(until)),
    )
}

/// Environment variable that lets the example's cookies travel over plain
/// HTTP. Cookies are `Secure` unless it is set to `1`, because a session
/// cookie sent over HTTP can be read by anyone on the path. Browsers treat
/// `localhost` as a secure context in most cases; set this only for a
/// browser or host name that refuses `Secure` cookies over HTTP.
pub const INSECURE_COOKIES_ENV: &str = "AXESS_DEV_INSECURE_COOKIES";

/// Whether the operator asked for cookies without the `Secure` attribute.
/// Prints a banner when they did, so the setting cannot go unnoticed.
fn secure_cookies() -> bool {
    let insecure = std::env::var(INSECURE_COOKIES_ENV).is_ok_and(|v| v == "1");
    if insecure {
        tracing::warn!(
            "{INSECURE_COOKIES_ENV}=1: session and CSRF cookies are sent WITHOUT the Secure \
             attribute. Local development only; never set this behind a real host name."
        );
    }
    !insecure
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

    let health = Arc::new(
        CompositeHealthCheck::new()
            .add("session_store", session_store.clone())
            .add("identity_store", backend.clone()),
    );

    // The registry is what a password reset, a suspension or an admin kick
    // revokes against. The layer consults it on every request, so a revoked
    // session is ended whatever guards the route, and the authentication
    // service deletes the stored rows of the sessions it revokes.
    //
    // The in-memory registry is per process and empty after a restart; use
    // the Valkey registry for more than one instance.
    let registry = MemorySessionRegistry::default();

    let secure = secure_cookies();
    let session_layer = SessionLayer::new(session_store.clone(), signing_key)
        .with_ttl(Duration::from_secs(86400))
        .with_secure(secure)
        .with_registry(Arc::new(axess::SessionRegistryAdapter(registry.clone())));

    // CSRF layer: signed double-submit cookie bound to the session id.
    // The key is a purpose-bound subkey of the session layer's master key
    // (HKDF, label `axess.v1.csrf`), so a leak of one derived key does not
    // give the other, and rotating the session master key rotates this key
    // with it. Sits INSIDE the session layer so its handler runs after
    // `SessionLayer` has injected the session handle into the request
    // extension. In production, load the master key from a secrets
    // manager so both survive a restart.
    let csrf_key = session_layer.derive_subkey(b"axess.v1.csrf");
    let csrf_layer = CsrfLayer::new(CsrfConfig::new(*csrf_key).secure(secure));

    let metrics = Arc::new(AppMetrics::new());

    // Rate limiting: 10 requests per minute per client IP on authentication
    // endpoints, where the client IP is the one the `client_ip` layer below
    // resolved (the socket peer, or the forwarded address when it came
    // through a trusted proxy). `PeerIp` would put every client behind one
    // proxy into a single bucket. Defense-in-depth alongside the per-user
    // lockout policy.
    let auth_rate_limit = RateLimitLayer::new(
        RateLimitConfig::builder()
            .max_requests(10)
            .window(Duration::from_secs(60))
            .key(KeyExtractor::ClientIp)
            .build(),
    )
    .with_metrics(AppMetricsHandle(metrics.clone()));

    let state_backend = backend.clone();
    let factor_cipher = factor_secret_cipher();
    let service = Arc::new(
        AuthnService::builder(backend.clone(), backend)
            // TOTP secrets are opened to check a code and kept sealed at rest.
            .with_factor_secret_cipher(factor_cipher.clone())
            .with_metrics(AppMetricsHandle(metrics.clone()))
            // Registered sessions are what a password reset or an admin
            // action can revoke; handing over the session store lets the
            // revocation delete the rows as well.
            .with_registry(registry)
            .with_session_store(session_store.clone())
            .build(),
    );
    let state = AppState {
        service,
        backend: state_backend,
        health,
        metrics,
        factor_cipher,
    };

    // Auth routes; rate-limited.
    let auth_routes = Router::new()
        .route("/login", get(auth::login_page).post(auth::post_login))
        .route("/signup", get(auth::signup_page).post(auth::post_signup))
        .route("/totp", get(auth::totp_page).post(auth::post_totp))
        .route("/recovery-code", post(auth::post_recovery_code))
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
        // Every route that needs a signed-in user goes through
        // `protected::router`, which guards them with `require_authn!`. A
        // handler registered here directly runs for guests too.
        .merge(protected::router())
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_endpoint))
        .with_state(state)
        // Layer order: CSRF inner, session outer. `session_layer` runs
        // FIRST on request entry (injecting the session handle) so that
        // `csrf_layer` (running SECOND) sees the handle and can bind
        // tokens to the current session id. See CsrfLayer's module docs.
        .layer(csrf_layer)
        .layer(session_layer);

    // Outermost, so it runs before anything that reads an address and
    // while `ConnectInfo` is still the nearest thing to the socket. It
    // resolves once and every handler below reads a `ClientIp`.
    //
    // `loopback_only` suits this example, reached directly or through a
    // same-host proxy. A deployment behind a load balancer names its
    // egress ranges with `TrustedProxies::from_cidrs` instead; get that
    // set wrong and the walk believes a header it should not.
    let router = axess::client_ip::layer(router, axess::client_ip::TrustedProxies::loopback_only());

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
/// The public answer is the aggregate only; per-component detail is logged.
/// Serve a detailed probe on an internal-only listener if operators need it.
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
        // Backend error text can carry connection strings and paths: it goes
        // to the log, never to an unauthenticated caller.
        tracing::warn!(components = ?status.components, "health check failed");
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    let body = serde_json::json!({
        "status": if status.is_healthy() { "healthy" } else { "unhealthy" },
    });
    (code, axum::Json(body))
}

/// `GET /metrics`; expose authentication counters.
///
/// Unauthenticated here so the example can be curled. Serve it on an
/// internal-only listener or behind the operator's network policy, not on the
/// public port: the counters tell an attacker how hard the rate limiter and
/// lockout are being hit.
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
