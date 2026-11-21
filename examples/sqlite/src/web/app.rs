//! Router construction: SessionLayer + AuthnService in Axum state + routes.

use crate::{
    models::backend::OurBackend,
    web::{auth, protected},
};
use axess::authn::BreachedPasswordList;
use axess::authn::{AuthnService, FactorSecretCipher};
use axess::csrf::{CsrfConfig, CsrfLayer};
use axess::profile::SecurityProfile;
use axess::session::{LegacyBlobs, SessionCrypto};
use axess::{
    AuditMetrics, AuthFlowMetrics, AuthSession, AuthzCacheMetrics, CompositeHealthCheck,
    CsrfRefusal, DeviceKeyMetrics, FactorMetrics, KeyExtractor, MemorySessionRegistry, MetricSinks,
    ProviderCategory, ProviderRegistryMetrics, RateLimitConfig, RateLimitLayer,
    RequestGuardMetrics, RotationMetrics, SecureRng, SessionLayer, SessionMetrics, SystemClock,
    SystemRng, backends::sqlite::SessionStore as SqliteSessionStore,
};
use axum::response::{IntoResponse, Redirect};
use axum::{Router, routing::get, routing::post};
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{sync::Arc, time::Duration};

/// Example metrics implementation using atomic counters.
///
/// In production, replace with Prometheus or OpenTelemetry counters. The
/// example implements the concerns it exports and leaves the rest empty:
/// each concern is its own trait, so a counter added to one concern in a
/// later release does not touch this type's other impls. Names follow the
/// scheme in the observability page: `axess_` prefix, snake_case, `_total`
/// for counters.
#[derive(Default)]
pub struct AppMetrics {
    pub auth_attempts: AtomicU64,
    pub auth_successes: AtomicU64,
    pub auth_failures: AtomicU64,
    pub account_locked: AtomicU64,
    pub factor_failures: AtomicU64,
    pub sessions_created: AtomicU64,
    pub session_binding_mismatches: AtomicU64,
    pub rate_limit_rejections: AtomicU64,
    pub csrf_rejections: AtomicU64,
    pub encryption_key_fallbacks: AtomicU64,
    pub fingerprint_key_fallbacks: AtomicU64,
    pub sid_map_evictions: AtomicU64,
    pub provider_duplicates: AtomicU64,
    pub provider_reloads: AtomicU64,
    pub provider_removals: AtomicU64,
    pub provider_reload_refusals: AtomicU64,
    pub policy_reloads: AtomicU64,
    pub policy_reload_refusals: AtomicU64,
    pub device_keys_offered: AtomicU64,
    pub device_keys_registered: AtomicU64,
    pub device_key_proofs_refused: AtomicU64,
    pub bound_sessions_unproven: AtomicU64,
}

impl AppMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every counter under its exported name.
    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        vec![
            ("axess_auth_attempts_total", get(&self.auth_attempts)),
            ("axess_auth_successes_total", get(&self.auth_successes)),
            ("axess_auth_failures_total", get(&self.auth_failures)),
            ("axess_account_locked_total", get(&self.account_locked)),
            ("axess_factor_failures_total", get(&self.factor_failures)),
            ("axess_sessions_created_total", get(&self.sessions_created)),
            (
                "axess_session_binding_mismatches_total",
                get(&self.session_binding_mismatches),
            ),
            (
                "axess_rate_limit_rejected_total",
                get(&self.rate_limit_rejections),
            ),
            ("axess_csrf_rejected_total", get(&self.csrf_rejections)),
            (
                "axess_encryption_key_fallback_total",
                get(&self.encryption_key_fallbacks),
            ),
            (
                "axess_fingerprint_key_fallback_total",
                get(&self.fingerprint_key_fallbacks),
            ),
            ("axess_sid_map_evicted_total", get(&self.sid_map_evictions)),
            (
                "axess_provider_duplicate_registration_total",
                get(&self.provider_duplicates),
            ),
            ("axess_provider_reloads_total", get(&self.provider_reloads)),
            (
                "axess_provider_removals_total",
                get(&self.provider_removals),
            ),
            (
                "axess_provider_reload_refusals_total",
                get(&self.provider_reload_refusals),
            ),
            (
                "axess_authz_policy_reloads_total",
                get(&self.policy_reloads),
            ),
            (
                "axess_authz_policy_reload_refusals_total",
                get(&self.policy_reload_refusals),
            ),
            (
                "axess_device_keys_offered_total",
                get(&self.device_keys_offered),
            ),
            (
                "axess_device_keys_registered_total",
                get(&self.device_keys_registered),
            ),
            (
                "axess_device_key_proofs_refused_total",
                get(&self.device_key_proofs_refused),
            ),
            (
                "axess_bound_sessions_unproven_total",
                get(&self.bound_sessions_unproven),
            ),
        ]
    }
}

impl AuthFlowMetrics for AppMetrics {
    fn auth_attempt(&self) {
        self.auth_attempts.fetch_add(1, Ordering::Relaxed);
    }
    fn auth_success(&self) {
        self.auth_successes.fetch_add(1, Ordering::Relaxed);
    }
    fn auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }
    fn account_locked(&self) {
        self.account_locked.fetch_add(1, Ordering::Relaxed);
    }
}

impl FactorMetrics for AppMetrics {
    fn factor_failure(&self) {
        self.factor_failures.fetch_add(1, Ordering::Relaxed);
    }
}

impl SessionMetrics for AppMetrics {
    fn session_created(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
    }
    fn session_binding_mismatch(&self) {
        self.session_binding_mismatches
            .fetch_add(1, Ordering::Relaxed);
    }
    fn sid_map_evicted(&self, count: u64) {
        self.sid_map_evictions.fetch_add(count, Ordering::Relaxed);
    }
}

impl RotationMetrics for AppMetrics {
    fn encryption_key_fallback(&self) {
        self.encryption_key_fallbacks
            .fetch_add(1, Ordering::Relaxed);
    }
    fn fingerprint_key_fallback(&self) {
        self.fingerprint_key_fallbacks
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl ProviderRegistryMetrics for AppMetrics {
    fn provider_duplicate_registration(&self) {
        self.provider_duplicates.fetch_add(1, Ordering::Relaxed);
    }
    fn provider_reloaded(&self, _: ProviderCategory) {
        self.provider_reloads.fetch_add(1, Ordering::Relaxed);
    }
    fn provider_removed(&self, _: ProviderCategory) {
        self.provider_removals.fetch_add(1, Ordering::Relaxed);
    }
    fn provider_reload_refused(&self, _: ProviderCategory) {
        self.provider_reload_refusals
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl RequestGuardMetrics for AppMetrics {
    fn rate_limit_rejected(&self) {
        self.rate_limit_rejections.fetch_add(1, Ordering::Relaxed);
    }
    fn csrf_rejected(&self, _: CsrfRefusal) {
        self.csrf_rejections.fetch_add(1, Ordering::Relaxed);
    }
}

impl AuthzCacheMetrics for AppMetrics {
    fn authz_policy_reloaded(&self) {
        self.policy_reloads.fetch_add(1, Ordering::Relaxed);
    }
    fn authz_policy_reload_refused(&self) {
        self.policy_reload_refusals.fetch_add(1, Ordering::Relaxed);
    }
}

// The device-key counters an operator watches first: keys offered and keys
// taken, read against each other before keys are required, proofs that were
// not the key's, and requests of a bound session that came without its key
// (a copied session cookie is one).
impl DeviceKeyMetrics for AppMetrics {
    fn key_offered(&self) {
        self.device_keys_offered.fetch_add(1, Ordering::Relaxed);
    }
    fn key_registered(&self) {
        self.device_keys_registered.fetch_add(1, Ordering::Relaxed);
    }
    fn key_proof_refused(&self) {
        self.device_key_proofs_refused
            .fetch_add(1, Ordering::Relaxed);
    }
    fn bound_session_unproven(&self) {
        self.bound_sessions_unproven.fetch_add(1, Ordering::Relaxed);
    }
}

// The concerns this example does not export. An empty impl is all it takes
// for `AppMetrics` to satisfy `AxessMetrics` and wire to every concern.
impl AuditMetrics for AppMetrics {}

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

/// Session limits tighter than the library's defaults (24 hours idle, 7 days
/// in all), as a bank would set them; the README says why.
const STRICT_IDLE_TTL: Duration = Duration::from_secs(15 * 60);
const STRICT_MAX_SESSION_AGE: Duration = Duration::from_secs(10 * 60 * 60);

/// Where the example keeps the key its TOTP secrets are sealed under.
const FACTOR_KEY_FILE: &str = "db/factor-secret.key";

/// The passwords this example treats as breached. Each meets the default
/// rules, so the refusal a visitor sees on the signup page is the breach
/// check's and not the rules'. A real corpus holds hundreds of millions of
/// entries and is consulted through the range protocol; see the README.
const BREACHED_PASSWORDS: [&str; 6] = [
    "Password1234",
    "Password123!",
    "Qwerty123456",
    "Welcome12345",
    "Iloveyou1234",
    "Letmein12345",
];

/// The day after which a TOTP secret still stored in plain text is no longer
/// read. Each such secret is sealed by the login that verifies it, so the date
/// only has to outlast the users who have not signed in yet. It is a fixed
/// date, not a span from the start of the run, so a restart does not move it.
pub fn plain_secret_cutoff() -> axess::Timestamp {
    axess::Timestamp::parse_rfc3339("2027-01-31T00:00:00Z").expect("a fixed RFC 3339 date")
}

/// The key TOTP secrets are sealed under: 32 bytes, hex encoded, in a file
/// that is created on first use and read on every later start. Secrets sealed
/// under a key that is lost cannot be opened, so unlike the session keys this
/// one must survive a restart. In production, load it from a secrets manager.
fn factor_secret_key() -> std::io::Result<[u8; 32]> {
    let path = std::env::current_dir()?.join(FACTOR_KEY_FILE);
    factor_secret_key_at(&path)
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    SystemRng.fill_bytes(&mut key);
    key
}

/// Creates `path` holding `contents`, readable by the owner only, if no file
/// is there. The contents are written to a private file beside it first and
/// linked into place, so the file at `path` is never seen empty or partly
/// written, and two creators cannot both win: the loser gets `AlreadyExists`.
fn create_private(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}.tmp", hex_of(&random_key()[..8])));
    let staged = std::path::PathBuf::from(name);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = options
        .open(&staged)
        .and_then(|mut file| {
            file.write_all(contents.as_bytes())
                .and_then(|()| file.sync_all())
        })
        .and_then(|()| std::fs::hard_link(&staged, path));
    let _ = std::fs::remove_file(&staged);
    result
}

/// Narrows an existing key file to the owner. It never rewrites the file.
fn narrow_to_owner(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_key(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    let bytes: Vec<u8> = (text.len() == 64)
        .then(|| {
            (0..32)
                .map(|i| u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()
        })
        .flatten()?;
    <[u8; 32]>::try_from(bytes).ok()
}

/// The TOTP sealing key, read from the key file at `path`, or created there
/// (mode 0600) on first use.
///
/// An existing file is only read and narrowed to the owner, never rewritten.
/// A new file appears whole or not at all, and a start that loses the race to
/// create it reads the winner's key.
///
/// # Errors
///
/// The file cannot be created, read or narrowed to the owner, or holds
/// something other than a key: replacing it would lose every secret sealed
/// under the old key, so the start fails and the file is left for you to
/// look at.
pub fn factor_secret_key_at(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let fresh = random_key();
    match create_private(path, &hex_of(&fresh)) {
        Ok(()) => return Ok(fresh),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let key = parse_key(&std::fs::read_to_string(path)?).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} does not hold a 64 character hex key; remove it only if no secret is sealed under it",
                path.display()
            ),
        )
    })?;
    narrow_to_owner(path)?;
    Ok(key)
}

/// The example's cipher: sealed under `factor_secret_key`, and reading a
/// plain secret until `plain_secret_cutoff` so rows written before the
/// cipher existed are moved by their owner's next login.
pub fn factor_secret_cipher() -> Arc<FactorSecretCipher> {
    factor_secret_cipher_on(Arc::new(SystemClock))
}

/// [`factor_secret_cipher`], reading the plain-secret cutoff against `clock`.
pub fn factor_secret_cipher_on(clock: Arc<dyn axess::Clock>) -> Arc<FactorSecretCipher> {
    Arc::new(
        FactorSecretCipher::new(
            factor_secret_key()
                .expect("the factor secret key file must be readable by its owner only"),
        )
        .with_clock(clock)
        .with_plain_secrets(LegacyBlobs::AcceptUntil(plain_secret_cutoff())),
    )
}

/// Environment variable that lets the example's cookies travel over plain
/// HTTP. Cookies are `Secure` unless it is set to `1`, because a session
/// cookie sent over HTTP can be read by anyone on the path. Browsers treat
/// `localhost` as a secure context in most cases; set this only for a
/// browser or host name that refuses `Secure` cookies over HTTP.
pub const INSECURE_COOKIES_ENV: &str = "AXESS_DEV_INSECURE_COOKIES";

/// The address the binary listens on, over plain HTTP.
pub const LISTEN_ADDR: &str = "127.0.0.1:3000";

/// The variable naming the origin the application is reached at when it is
/// served over HTTPS, such as `https://app.example`. Device keys
/// (`--features device-keys`) need it: every key proof is made for it.
pub const ORIGIN_ENV: &str = "AXESS_ORIGIN";

/// How the application is reached: what the cookies and the device keys are
/// built for.
#[derive(Debug, Clone)]
pub struct Serving {
    /// Whether cookies carry `Secure`.
    pub secure: bool,
    /// The origin the application is reached at, when it is known. Read by
    /// the device keys of `--features device-keys`.
    pub origin: Option<String>,
}

impl Serving {
    /// From the environment: [`INSECURE_COOKIES_ENV`] and [`ORIGIN_ENV`].
    pub fn from_env() -> Self {
        Self {
            secure: secure_cookies(),
            origin: std::env::var(ORIGIN_ENV).ok(),
        }
    }
}

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
    build_router_on(pool, Arc::new(SystemClock)).await
}

/// [`build_router`], with every time-bound part of the application on
/// `clock`: the backend, the authentication service and its factor cipher,
/// the session layer and its stores, and the rate limits. A test passes a
/// mock set to the instant it plays the user's authenticator at.
pub async fn build_router_on(
    pool: SqlitePool,
    clock: Arc<dyn axess::Clock>,
) -> (Router, SqliteSessionStore) {
    build_router_serving(pool, clock, Serving::from_env()).await
}

/// [`build_router_on`], reached as `serving` says rather than as the
/// environment does: a test names the origin its device keys are held to.
pub async fn build_router_serving(
    pool: SqlitePool,
    clock: Arc<dyn axess::Clock>,
    serving: Serving,
) -> (Router, SqliteSessionStore) {
    let backend = OurBackend::new(pool.clone()).with_clock(clock.clone());
    // The lockout policy is checked where it is loaded, so a value past a
    // bound stops the start-up by name instead of being clamped on every
    // login; a deployment that reads the policy from a tenant table makes
    // the same call where it reads the row.
    if let Err(fault) = backend.lockout_policy().validate() {
        panic!("the lockout policy is refused: {fault}");
    }

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
    // One exporter, wired to every concern. The session crypto is built first
    // and takes the rotation sink directly.
    let metrics = Arc::new(AppMetrics::new());
    let sinks = MetricSinks::all(metrics.clone());
    let session_store = SqliteSessionStore::new(
        pool.clone(),
        SessionCrypto::new(encryption_key)
            .with_clock(clock.clone())
            .with_previous_key(previous_key)
            .with_metrics(sinks.rotation()),
    )
    .with_clock(clock.clone());
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
    let registry = MemorySessionRegistry::default().with_clock(clock.clone());

    let state_backend = backend.clone();
    let factor_cipher = factor_secret_cipher_on(clock.clone());
    // The strict profile: the Argon2id cost, the password-reset lifetime and
    // cap and the impersonation recency a deployment that holds money or
    // regulated data runs with, as named values. Applied first, so every
    // setting below it (the cipher, the breach check, the stores) stays as
    // written here. Applying never loosens: a looser value of a setting the
    // profile names is written after it, on the builder it returns.
    let strict = SecurityProfile::Strict.values();
    let service = Arc::new(
        strict
            .authn_service_builder(AuthnService::builder(backend.clone(), backend))
            .with_clock(clock.clone())
            // TOTP secrets are opened to check a code and kept sealed at rest.
            .with_factor_secret_cipher(factor_cipher.clone())
            .with_metrics(sinks.clone())
            // Registered sessions are what a password reset or an admin
            // action can revoke; handing over the session store lets the
            // revocation delete the rows as well.
            // One reset token per account a minute: the form cannot be used to
            // flood an inbox, or to spend the reset budget of another user.
            .with_password_reset_cooldown(Duration::from_secs(60))
            // Every chosen password (signup, reset) is screened against a
            // breach corpus and refused by name when found. This is a short
            // fixed list so the refusal can be seen; a deployment implements
            // `BreachedPasswordCheck` over the k-anonymity range protocol
            // (see the README). The default refuses a password the check
            // could not screen; `allow_unchecked_when_breach_check_unavailable`
            // is the opt-out.
            .with_breached_password_check(BreachedPasswordList::new(BREACHED_PASSWORDS))
            .with_registry(registry.clone())
            .with_session_store(session_store.clone())
            .build(),
    );

    let secure = serving.secure;
    let session_layer = SessionLayer::new(
        session_store.clone(),
        signing_key,
        Arc::new(axess::SessionRegistryAdapter(registry)),
        // The service's sink writes an audit row for each session the
        // layer ends by itself: one past an age cap, one the registry no
        // longer holds.
        service.session_end_audit(),
    )
    .with_clock(clock.clone())
    .with_ttl(STRICT_IDLE_TTL)
    .with_max_session_age(Some(STRICT_MAX_SESSION_AGE))
    .with_secure(secure)
    .with_metrics(sinks.clone());
    // Device keys, with `--features device-keys` (`web::device_keys` says
    // what they add). Their routes are merged below.
    #[cfg(feature = "device-keys")]
    let (session_layer, device_keys) = crate::web::device_keys::with_device_keys(
        session_layer,
        crate::web::device_keys::Wiring {
            pool: &pool,
            clock: clock.clone(),
            serving: &serving,
            sinks: &sinks,
            audit: state_backend.clone(),
        },
    )
    .await;

    // CSRF layer: signed double-submit cookie bound to the session id.
    // The key is a purpose-bound subkey of the session layer's master key
    // (HKDF, label `axess.v1.csrf`), so a leak of one derived key does not
    // give the other, and rotating the session master key rotates this key
    // with it. Sits INSIDE the session layer so its handler runs after
    // `SessionLayer` has injected the session handle into the request
    // extension. In production, load the master key from a secrets
    // manager so both survive a restart.
    let csrf_key = session_layer.derive_subkey(b"axess.v1.csrf");
    let csrf_layer =
        CsrfLayer::new(CsrfConfig::new(*csrf_key).secure(secure)).with_metrics(sinks.clone());

    // Rate limiting: per client IP, where the client IP is the one the
    // `client_ip` layer below resolved (the socket peer, or the forwarded
    // address when it came through a trusted proxy). `PeerIp` would put
    // every client behind one proxy into a single bucket. Defense-in-depth
    // alongside the per-user lockout policy.
    //
    // Only submissions are counted, never the GET that shows a form, and
    // each sensitive form has a bucket of its own: a run of failed logins
    // does not stop the same address asking for a reset, nor the reverse.
    let limiter = |max_requests: u32| {
        RateLimitLayer::new(
            RateLimitConfig::builder()
                .max_requests(max_requests)
                .window(Duration::from_secs(60))
                .key(KeyExtractor::ClientIp)
                .clock(clock.clone())
                .build(),
        )
        .with_metrics(sinks.clone())
    };
    let login_limit = limiter(10);
    let forgot_limit = limiter(5);
    // Every other form gets a `limiter(10)` of its own where it is routed
    // below. Cloning one limiter onto several routes would share its bucket
    // (the clones keep one store), and the forms would spend one budget.

    let state = AppState {
        service,
        backend: state_backend,
        health,
        metrics,
        factor_cipher,
    };

    // Auth routes: the POSTs, and the mail link, are rate-limited.
    let auth_routes = Router::new()
        .route(
            "/login",
            get(auth::login_page).merge(post(auth::post_login).layer(login_limit)),
        )
        .route(
            "/signup",
            get(auth::signup_page).merge(post(auth::post_signup).layer(limiter(10))),
        )
        .route("/verify-email", get(auth::verify_email).layer(limiter(10)))
        .route(
            "/totp",
            get(auth::totp_page).merge(post(auth::post_totp).layer(limiter(10))),
        )
        .route(
            "/recovery-code",
            post(auth::post_recovery_code).layer(limiter(10)),
        )
        .route(
            "/forgot-password",
            get(auth::forgot_password_page)
                .merge(post(auth::post_forgot_password).layer(forgot_limit)),
        )
        .route(
            "/reset-password",
            get(auth::reset_password_page)
                .merge(post(auth::post_reset_password).layer(limiter(10))),
        );

    // The rest.
    let router = Router::new()
        .merge(auth_routes)
        .route("/", get(root))
        .route("/logout", post(auth::logout))
        // Every route that needs a signed-in user goes through
        // `protected::router`, which guards them with `require_authn!`. A
        // handler registered here directly runs for guests too.
        .merge(protected::router(limiter(10)))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_endpoint));
    // The two device-key paths. The browser posts to them itself, with no
    // form token: the session layer marks a request to either, and the CSRF
    // layer lets a marked request through, as the key's signature over a
    // server challenge is what authenticates it. Anybody can post to them,
    // and each post costs a signature check and a device read, so they are
    // limited per client address like the forms: a browser refreshes once
    // per proof lifetime.
    #[cfg(feature = "device-keys")]
    let router = match &device_keys {
        Some(keys) => router.merge(keys.router().layer(limiter(60))),
        None => router,
    };
    let router = router
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

    // Every page here is account state or a secret (the TOTP secret, the
    // recovery codes): nothing is cached, framed or allowed to load anything
    // from elsewhere.
    let router = router.layer(axum::middleware::from_fn(security_headers));

    (router, session_store)
}

/// The content security policy of the example's pages: they are static HTML
/// with inline styles, no script, no external resources and one form target.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; \
     img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// Adds `Cache-Control: no-store`, `X-Frame-Options: DENY` and a CSP to every
/// response, without overriding a header a handler set itself.
async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::{HeaderValue, header};
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
    ] {
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    }
    response
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
/// The counters are named `axess_<what>_total`; see the observability page
/// for the scheme. In production, export them through your Prometheus or
/// OpenTelemetry registry alongside your own business metrics. The route name
/// follows the Prometheus `/metrics` convention.
async fn metrics_endpoint(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl IntoResponse {
    axum::Json(serde_json::Value::Object(
        state
            .metrics
            .snapshot()
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.into()))
            .collect(),
    ))
}
