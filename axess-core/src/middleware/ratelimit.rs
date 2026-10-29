//! Composable tower layer for sliding-window rate limiting.
//!
//! Provides defense-in-depth rate limiting that complements any external API
//! gateway. Buckets are keyed per IP, user, tenant, or arbitrary header value.
//!
//! # Key extractors
//!
//! | Extractor | Source | Use case |
//! |-----------|--------|----------|
//! | `KeyExtractor::PeerIp` | `SocketAddr` from `ConnectInfo` | **Default.** Safe for direct connections. |
//! | `KeyExtractor::ClientIp` | the `ClientIp` resolved by `client_ip::layer` | Behind a reverse proxy. Needs the layer installed. |
//! | `KeyExtractor::UserId` | `RateLimitUserId` request extension | Per-user limits (set after authentication). |
//! | `KeyExtractor::TenantId` | `RateLimitTenantId` request extension | Per-tenant limits. |
//! | `KeyExtractor::LoginIdentifier` | `RateLimitLoginIdentifier` request extension | **Required for login routes** to mitigate per-username lockout DoS. |
//! | `KeyExtractor::Header(name)` | Header value within the `RateLimitUserId` identity | Sub-buckets per authenticated user; peer address when unauthenticated. |
//!
//! # Login routes: required pairing
//!
//! Per-IP rate limiting alone (`KeyExtractor::PeerIp`) does NOT defend
//! against a per-username lockout DoS: an attacker rotating IPs (or a
//! botnet) can issue 5 wrong-password POSTs per known username and lock
//! the legitimate user out. Always pair `PeerIp` with
//! [`KeyExtractor::LoginIdentifier`](crate::middleware::ratelimit::KeyExtractor::LoginIdentifier) on `/login`-class routes:
//!
//! ```rust,ignore
//! use axess_core::middleware::ratelimit::{KeyExtractor, RateLimitConfig, RateLimitLayer, RateLimitLoginIdentifier};
//! use std::time::Duration;
//!
//! // The application parses the login form, then injects the identifier
//! // into request extensions BEFORE the rate-limit layer runs.
//! let per_username = RateLimitLayer::new(
//!     RateLimitConfig::builder()
//!         .max_requests(10)
//!         .window(Duration::from_secs(60))
//!         .key(KeyExtractor::LoginIdentifier)
//!         .build(),
//! );
//! let per_ip = RateLimitLayer::new(
//!     RateLimitConfig::builder()
//!         .max_requests(60)
//!         .window(Duration::from_secs(60))
//!         .key(KeyExtractor::PeerIp)
//!         .build(),
//! );
//! let login_route = axum::Router::new()
//!     .route("/login", axum::routing::post(login_handler))
//!     .layer(per_username)
//!     .layer(per_ip);
//! ```
//!
//! The identifier is normalised before keying (Unicode NFKC, lowercase,
//! invisible format characters removed) so `Alice`, `alice` and a spelling
//! with a zero-width character share a bucket. A store may fold even more than
//! this (a case-insensitive collation, a dotted local part), so pair the
//! per-identifier limit with one on the resolved user id where that matters.
//!
//! In a multi-tenant application build the extension with
//! [`RateLimitLoginIdentifier::new_in_tenant`](crate::middleware::ratelimit::RateLimitLoginIdentifier::new_in_tenant), so the same address in two
//! tenants is two buckets and an attacker cannot exhaust a victim's budget
//! in another tenant by naming it.
//!
//! Every bucket key starts with its kind (`ip:`, `user:`, `login:`), so an
//! identifier that spells a sentinel such as `anon` or `unknown` gets its own
//! bucket and cannot share the one unattributable requests land in.
//!
//! # Memory bound
//!
//! Bucket keys are bounded to a fixed length (a longer key is cut and ends
//! in a digest of the whole, so long identifiers sharing a prefix keep
//! separate buckets), an IPv6 client is keyed by its /64 prefix, and a
//! header value only selects one of 16 sub-buckets of its user, so no one
//! identity can create more than a handful of buckets. A bucket is dropped
//! once two windows have passed since its window began, because until then
//! the previous window still counts. Expired buckets are swept
//! once per sweep interval (an eighth of the window, at least one second)
//! by whichever request first sees the interval elapsed, and the table
//! holds at most 262,144 buckets. A request whose key has no bucket yet is
//! answered 429 while the table is full; keys that already have a bucket
//! are unaffected, and no live bucket is evicted to make room.
//!
//! Two further bounds keep one source from filling the table. Each IPv4 /24
//! and IPv6 /48 may hold 1,024 live buckets; a new client of that prefix past
//! the budget shares the prefix's overflow bucket (limited together), so an
//! allocation holding millions of /64s cannot starve a client elsewhere.
//! And once the table is three quarters full, a login identifier with no
//! bucket yet is folded into an overflow bucket of its origin (the IPv4
//! address or IPv6 /48), so unauthenticated callers inventing identifiers
//! cannot take the remaining room. Neither bound uses wall-clock time beyond
//! the sweep: a bucket whose window starts in the future (the clock stepped
//! back) is re-anchored at the next sweep and ages out normally.
//!
//! The remaining-requests header (`x-ratelimit-remaining`) is sent only for
//! buckets one caller owns (address, user, header); a login-identifier,
//! tenant or shared bucket would tell the caller how many attempts others
//! made.
//!
//! # Window
//!
//! Each key keeps a count for the current fixed window and the one before.
//! A request is admitted when the previous count, weighted by how much of it
//! still overlaps the trailing window, plus the current count leaves room, so
//! a burst split across a window boundary is counted once and not twice.
//!
//! # Time
//!
//! Window starts and sweeps read [`RateLimitConfig::clock`](crate::middleware::ratelimit::RateLimitConfig::clock), so a test
//! advances a mock clock past the window instead of sleeping.
//!
//! # Layered rate limiting
//!
//! In production, layer per-IP (volumetric), per-user (brute-force), and
//! an external gateway (distributed). This library provides only the
//! in-process buckets; distributed rate limiting belongs at the gateway
//! with a shared store (Valkey / Redis).

use axess_clock::{Clock, SystemClock};
use axess_rng::{SecureRng, SystemRng};
use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use zeroize::Zeroizing;

#[cfg(test)]
use chrono::{DateTime, Utc};
use tower::{Layer, Service};

mod keys;
mod store;
use keys::resolve_target;
use store::{Acquire, BucketStore};

// ── Configuration ────────────────────────────────────────────────────────────

/// What to use as the rate-limit bucket key.
#[derive(Clone, Debug)]
pub enum KeyExtractor {
    /// Rate limit by the address [`client_ip::layer`](crate::client_ip::layer)
    /// resolved for this request.
    ///
    /// The layer walks the forwarded chain against the peer the server
    /// accepted and the proxies you named, so a caller cannot pick its own
    /// bucket by writing a header. Requires the layer to be installed
    /// outside this one; without it every request resolves to `None` and
    /// shares one bucket, which limits harder rather than less.
    ///
    /// Replaces `ForwardedIp`, which read `X-Real-IP` and then the first
    /// `X-Forwarded-For` entry and believed both. Both are caller-writable:
    /// rotating either bought a fresh bucket per request, which is the
    /// whole of what a rate limiter exists to prevent.
    ClientIp,
    /// Rate limit by TCP peer address via axum's `ConnectInfo`.
    ///
    /// Requires `Router::into_make_service_with_connect_info::<SocketAddr>()`
    /// on your axum server. Falls back to a shared bucket (`"unknown"`) if
    /// `ConnectInfo` is not available; this is fail-closed (all requests
    /// share one bucket = stricter limiting).
    PeerIp,
    /// Rate limit by authenticated user (reads the [`RateLimitUserId`]
    /// request extension the auth layer injects). Falls back to a
    /// shared anonymous bucket if the extension is absent; unauthenticated
    /// callers cannot select their own bucket.
    UserId,
    /// Rate limit by tenant (reads the [`RateLimitTenantId`] request
    /// extension the auth layer injects). Falls back to a shared
    /// anonymous bucket if the extension is absent.
    TenantId,
    /// Rate limit by the **login identifier** (username/email submitted to a
    /// login route). Reads the [`RateLimitLoginIdentifier`] request extension
    /// that the application sets after parsing the login form.
    ///
    /// # Why it exists
    ///
    /// `PeerIp` rate-limits the source. `LoginIdentifier` rate-limits the
    /// *target*. Without this layer, an attacker rotating IPs (or simply
    /// using a botnet) can issue 5 wrong-password POSTs per known username
    /// and lock the legitimate user out of their account: a per-account
    /// denial-of-service that needs no compromised credentials.
    ///
    /// Always pair this with `PeerIp` on login routes; see the module-level
    /// example.
    ///
    /// Falls back to a shared anonymous-bucket sentinel when no extension is
    /// present, so a misconfigured route fails closed (one shared bucket)
    /// rather than evading the limit.
    LoginIdentifier,
    /// Rate limit by a header value, **within an authenticated identity**.
    ///
    /// A header is whatever the caller writes. Keyed on its raw value, a
    /// client sending a new value per request would get a fresh bucket each
    /// time and no limit at all. So the header only subdivides a bucket the
    /// caller cannot choose: when the request carries a [`RateLimitUserId`]
    /// extension (set after authentication) and the header, the key is the
    /// user id plus a slot derived from the header value. Otherwise the key is
    /// the TCP peer
    /// address, exactly as for [`KeyExtractor::PeerIp`], so an unauthenticated
    /// caller cannot select its own bucket by choosing a header.
    ///
    /// The header value selects one of 16 sub-buckets of the user by digest,
    /// so a user sending any number of distinct values holds at most 16
    /// buckets and cannot fill the shared table; two values can land in the
    /// same sub-bucket. An authenticated user can still spread their own
    /// traffic over those 16. Pair this with a [`KeyExtractor::UserId`]
    /// layer when that matters. Install the layer after authentication so the
    /// extension is present.
    Header(String),
}

/// Rate-limit configuration for a single layer instance.
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed within the window.
    pub max_requests: u32,
    /// Length of the trailing window `max_requests` applies to.
    pub window: Duration,
    /// Strategy for deriving the bucket key from each request.
    pub key_extractor: KeyExtractor,
    /// When `true`, 429 responses include a `Retry-After` header (seconds).
    pub retry_after: bool,
    /// Time source for window starts and expiry sweeps. Defaults to
    /// [`SystemClock`]; tests inject a mock clock and advance it past the
    /// window instead of sleeping.
    pub clock: Arc<dyn Clock>,
    /// Randomness for the per-instance key that fingerprints bucket keys in
    /// the debug log. Defaults to [`SystemRng`]; tests inject a seeded RNG.
    pub rng: Arc<dyn SecureRng>,
}

impl std::fmt::Debug for RateLimitConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitConfig")
            .field("max_requests", &self.max_requests)
            .field("window", &self.window)
            .field("key_extractor", &self.key_extractor)
            .field("retry_after", &self.retry_after)
            .finish_non_exhaustive()
    }
}

/// Builder for [`RateLimitConfig`].
pub struct RateLimitConfigBuilder {
    max_requests: u32,
    window: Duration,
    key_extractor: KeyExtractor,
    retry_after: bool,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn SecureRng>,
}

impl RateLimitConfig {
    /// Start building a new configuration.
    pub fn builder() -> RateLimitConfigBuilder {
        RateLimitConfigBuilder {
            max_requests: 100,
            window: Duration::from_secs(60),
            key_extractor: KeyExtractor::PeerIp,
            retry_after: true,
            clock: Arc::new(SystemClock),
            rng: Arc::new(SystemRng),
        }
    }
}

impl RateLimitConfigBuilder {
    /// Maximum requests per window (default: 100).
    pub fn max_requests(mut self, n: u32) -> Self {
        self.max_requests = n;
        self
    }

    /// Window duration (default: 60 s).
    pub fn window(mut self, d: Duration) -> Self {
        self.window = d;
        self
    }

    /// Bucket key strategy (default: [`KeyExtractor::PeerIp`]).
    pub fn key(mut self, k: KeyExtractor) -> Self {
        self.key_extractor = k;
        self
    }

    /// Include `Retry-After` header in 429 responses (default: `true`).
    pub fn retry_after(mut self, enabled: bool) -> Self {
        self.retry_after = enabled;
        self
    }

    /// Time source (default: [`SystemClock`]).
    pub fn clock(mut self, clock: impl Clock) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Random source for the log-fingerprint key (default: [`SystemRng`]).
    pub fn rng(mut self, rng: impl SecureRng) -> Self {
        self.rng = Arc::new(rng);
        self
    }

    /// Consume the builder and produce a [`RateLimitConfig`].
    ///
    /// # Panics
    ///
    /// Panics if `max_requests` is zero or `window` is zero.
    pub fn build(self) -> RateLimitConfig {
        assert!(
            self.max_requests > 0,
            "RateLimitConfig: max_requests must be > 0"
        );
        assert!(
            !self.window.is_zero(),
            "RateLimitConfig: window must be > 0"
        );
        // Warn on suspicious configurations that are unlikely to be intentional.
        if should_warn_very_low_max_requests(self.max_requests) {
            tracing::warn!(
                max_requests = self.max_requests,
                "RateLimitConfig: very low max_requests; consider at least 5 to avoid blocking legitimate users"
            );
        }
        if should_warn_very_long_window(self.window) {
            tracing::warn!(
                window_secs = self.window.as_secs(),
                "RateLimitConfig: window exceeds 1 hour; long windows increase memory usage per bucket"
            );
        }
        RateLimitConfig {
            max_requests: self.max_requests,
            window: self.window,
            key_extractor: self.key_extractor,
            retry_after: self.retry_after,
            clock: self.clock,
            rng: self.rng,
        }
    }
}

// ── Key extraction ───────────────────────────────────────────────────────────

/// Request extension carrying a user ID (set by upstream authn middleware).
///
/// Wraps the validated [`UserId`](axess_identity::UserId) newtype rather
/// than a raw `String`, so an upstream extractor cannot accidentally write
/// an unvalidated identifier into the rate-limit key space.
#[derive(Clone, Debug)]
pub struct RateLimitUserId(pub axess_identity::UserId);

/// Request extension carrying a tenant ID (set by upstream authn middleware).
///
/// Wraps the validated [`TenantId`](axess_identity::TenantId) newtype.
#[derive(Clone, Debug)]
pub struct RateLimitTenantId(pub axess_identity::TenantId);

/// Request extension carrying the **login identifier** (username/email) for
/// per-target rate limiting on login routes.
///
/// The application is responsible for parsing the login form body and
/// inserting this extension into the request before the rate-limit layer
/// runs. The identifier is normalised on construction (Unicode NFKC,
/// lowercase, format characters such as zero-width spaces removed) so case
/// and look-alike variation can't trivially evade the limit.
///
/// A multi-tenant application must use [`new_in_tenant`](Self::new_in_tenant):
/// [`new`](Self::new) keys on the identifier alone, so the same address in two
/// tenants shares one bucket.
///
/// See [`KeyExtractor::LoginIdentifier`] and the module-level example
///
#[derive(Clone, Debug)]
pub struct RateLimitLoginIdentifier {
    identifier: String,
    /// `Some(tenant)` for a tenant-scoped key.
    tenant: Option<String>,
}

/// NFKC, lowercase, and without invisible format characters (the `Cf`
/// category: zero-width spaces and joiners, bidi controls, the soft hyphen,
/// the byte-order mark). `None` when nothing is left.
fn normalise_identifier(raw: &str) -> Option<String> {
    use unicode_normalization::UnicodeNormalization as _;
    let folded: String = raw
        .nfkc()
        .filter(|c| !is_format_char(*c))
        .collect::<String>()
        .to_lowercase();
    let trimmed = folded.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Characters of Unicode category `Cf` that render as nothing.
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

impl RateLimitLoginIdentifier {
    /// Build a normalised login-identifier key. Trims whitespace, applies
    /// Unicode NFKC, lowercases, drops invisible format characters, and
    /// rejects input that is empty after that by returning `None`; the caller
    /// should treat that as the anonymous bucket.
    ///
    /// The key is the identifier alone. In a multi-tenant application use
    /// [`new_in_tenant`](Self::new_in_tenant).
    pub fn new(identifier: impl AsRef<str>) -> Option<Self> {
        Some(Self {
            identifier: normalise_identifier(identifier.as_ref())?,
            tenant: None,
        })
    }

    /// Like [`new`](Self::new), scoped to `tenant`: the same identifier in two
    /// tenants gets two buckets, so repeated logins naming `ceo@victim.com`
    /// against another tenant cannot exhaust the victim tenant's budget. The
    /// tenant is length-prefixed in the key, so no tenant and identifier pair
    /// can spell another's. Does not combine with `RateLimitTenantId`; the
    /// two extractors are separate layers.
    pub fn new_in_tenant(
        tenant: &axess_identity::TenantId,
        identifier: impl AsRef<str>,
    ) -> Option<Self> {
        Some(Self {
            identifier: normalise_identifier(identifier.as_ref())?,
            tenant: Some(tenant.to_string()),
        })
    }

    /// The normalised identifier (without any tenant scope).
    pub fn as_str(&self) -> &str {
        &self.identifier
    }

    /// The key this identifier occupies, kind-tagged so an unscoped
    /// identifier can never equal a scoped one: `u:{identifier}` or
    /// `t:{len}:{tenant}:{identifier}`.
    pub(super) fn bucket_key(&self) -> String {
        match &self.tenant {
            None => format!("u:{}", self.identifier),
            Some(tenant) => format!("t:{}:{tenant}:{}", tenant.len(), self.identifier),
        }
    }
}

/// Whether the builder should emit the "very low max_requests" warning.
fn should_warn_very_low_max_requests(max_requests: u32) -> bool {
    max_requests < 5
}

/// Whether the builder should emit the "window exceeds 1 hour" warning.
fn should_warn_very_long_window(window: std::time::Duration) -> bool {
    window > std::time::Duration::from_secs(3600)
}

// ── Tower Layer / Service ────────────────────────────────────────────────────

/// Tower layer that adds token-bucket rate limiting.
#[derive(Clone)]
pub struct RateLimitLayer {
    store: BucketStore,
    key_extractor: KeyExtractor,
    retry_after: bool,
    /// Key for the debug-log fingerprints: random per layer instance.
    log_key: Arc<Zeroizing<[u8; 32]>>,
    metrics: Option<Arc<dyn crate::metrics::AuthnMetrics>>,
}

impl RateLimitLayer {
    /// Create a new rate-limit layer from the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        let mut log_key = Zeroizing::new([0u8; 32]);
        config.rng.fill_bytes(&mut *log_key);
        Self {
            store: BucketStore::new(config.max_requests, config.window, config.clock),
            key_extractor: config.key_extractor,
            retry_after: config.retry_after,
            log_key: Arc::new(log_key),
            metrics: None,
        }
    }

    /// The fingerprint this instance logs for `key` (test hook).
    #[cfg(test)]
    fn log_fingerprint(&self, key: &str) -> String {
        keys::fingerprint(&**self.log_key, key)
    }

    /// Attach a metrics hook for rate-limit observability.
    pub fn with_metrics(mut self, metrics: impl crate::metrics::AuthnMetrics) -> Self {
        self.metrics = Some(Arc::new(metrics));
        self
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            store: self.store.clone(),
            key_extractor: self.key_extractor.clone(),
            retry_after: self.retry_after,
            log_key: self.log_key.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

/// Tower service that enforces per-key rate limits before forwarding requests.
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    store: BucketStore,
    key_extractor: KeyExtractor,
    retry_after: bool,
    log_key: Arc<Zeroizing<[u8; 32]>>,
    metrics: Option<Arc<dyn crate::metrics::AuthnMetrics>>,
}

impl<S, ResBody> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let target = resolve_target(&req, &self.key_extractor);
        let retry_after_enabled = self.retry_after;

        let metrics = self.metrics.clone();
        match self.store.try_acquire_target(&target, self.store.now()) {
            Acquire::Allowed { remaining } => {
                // The count left in a bucket other callers draw on says how
                // many attempts they made, so only a caller's own bucket
                // reports it.
                let report_remaining = !target.shared;
                if let Some(ref m) = metrics {
                    m.rate_limit_allowed();
                }
                // Clone inner *before* the async block; required by tower's contract.
                let mut inner = self.inner.clone();
                std::mem::swap(&mut inner, &mut self.inner);
                Box::pin(async move {
                    let mut resp = inner.call(req).await?;
                    if report_remaining
                        && let Ok(val) = axum::http::HeaderValue::from_str(&remaining.to_string())
                    {
                        resp.headers_mut().insert("x-ratelimit-remaining", val);
                    }
                    Ok(resp)
                })
            }
            Acquire::Limited { retry_after_secs } | Acquire::Saturated { retry_after_secs } => {
                if let Some(ref m) = metrics {
                    m.rate_limit_rejected();
                }
                tracing::debug!(
                    key_fingerprint = %keys::fingerprint(&**self.log_key, &target.key),
                    retry_after = retry_after_secs,
                    "rate limit exceeded"
                );
                Box::pin(async move {
                    let mut response = Response::new(ResBody::default());
                    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                    if retry_after_enabled
                        && let Ok(val) =
                            axum::http::HeaderValue::from_str(&retry_after_secs.to_string())
                    {
                        response.headers_mut().insert("retry-after", val);
                    }
                    Ok(response)
                })
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
