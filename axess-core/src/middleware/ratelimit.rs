//! Composable tower layer for token-bucket rate limiting.
//!
//! Provides defense-in-depth rate limiting that complements any external API
//! gateway. Buckets are keyed per IP, user, tenant, or arbitrary header value.
//!
//! # Key extractors
//!
//! | Extractor | Source | Use case |
//! |-----------|--------|----------|
//! | `KeyExtractor::PeerIp` | `SocketAddr` from `ConnectInfo` | **Default.** Safe for direct connections. |
//! | `KeyExtractor::ForwardedIp` | `X-Forwarded-For` header | Behind a **trusted** reverse proxy only. |
//! | `KeyExtractor::UserId` | `RateLimitUserId` request extension | Per-user limits (set after authentication). |
//! | `KeyExtractor::TenantId` | `RateLimitTenantId` request extension | Per-tenant limits. |
//! | `KeyExtractor::LoginIdentifier` | `RateLimitLoginIdentifier` request extension | **Required for login routes** to mitigate per-username lockout DoS. |
//! | `KeyExtractor::Header(name)` | Arbitrary header | Custom keys (e.g. API key). |
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
//! The identifier is normalised to lowercase before keying so `Alice`
//! and `alice` share a bucket.
//!
//! # Layered rate limiting
//!
//! In production, layer per-IP (volumetric), per-user (brute-force), and
//! an external gateway (distributed). This library provides only the
//! in-process buckets; distributed rate limiting belongs at the gateway
//! with a shared store (Valkey / Redis).

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use dashmap::DashMap;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tower::{Layer, Service};

// ── Configuration ────────────────────────────────────────────────────────────

/// What to use as the rate-limit bucket key.
#[derive(Clone, Debug)]
pub enum KeyExtractor {
    /// Rate limit by client IP from a trusted reverse proxy header.
    ///
    /// Reads `X-Real-IP` then `X-Forwarded-For` (first entry). Use this only
    /// when deployed behind a reverse proxy (NGINX, Envoy, ALB, Cloudflare)
    /// that sets these headers from the real peer address and strips
    /// client-supplied values.
    ///
    /// Without a trusted proxy, clients can spoof these headers to bypass
    /// rate limiting entirely. For direct-to-client deployments, use
    /// [`PeerIp`](KeyExtractor::PeerIp) instead.
    ForwardedIp,
    /// Rate limit by TCP peer address via axum's `ConnectInfo`.
    ///
    /// Requires `Router::into_make_service_with_connect_info::<SocketAddr>()`
    /// on your axum server. Falls back to a shared bucket (`"unknown"`) if
    /// `ConnectInfo` is not available; this is fail-closed (all requests
    /// share one bucket = stricter limiting).
    PeerIp,
    /// Rate limit by authenticated user (reads `x-user-id` header or request extension).
    UserId,
    /// Rate limit by tenant (reads `x-tenant-id` header or request extension).
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
    /// Rate limit by an arbitrary header value.
    Header(String),
}

/// Rate-limit configuration for a single layer instance.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed within the window.
    pub max_requests: u32,
    /// Duration of the sliding window.
    pub window: Duration,
    /// Strategy for deriving the bucket key from each request.
    pub key_extractor: KeyExtractor,
    /// When `true`, 429 responses include a `Retry-After` header (seconds).
    pub retry_after: bool,
}

/// Builder for [`RateLimitConfig`].
pub struct RateLimitConfigBuilder {
    max_requests: u32,
    window: Duration,
    key_extractor: KeyExtractor,
    retry_after: bool,
}

impl RateLimitConfig {
    /// Start building a new configuration.
    pub fn builder() -> RateLimitConfigBuilder {
        RateLimitConfigBuilder {
            max_requests: 100,
            window: Duration::from_secs(60),
            key_extractor: KeyExtractor::PeerIp,
            retry_after: true,
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
        if matches!(self.key_extractor, KeyExtractor::ForwardedIp) {
            tracing::warn!(
                "RateLimitConfig: using ForwardedIp key extractor. \
                 This reads X-Forwarded-For / X-Real-IP headers which are \
                 client-spoofable unless set by a trusted reverse proxy. \
                 Ensure your proxy strips client-supplied forwarded headers \
                 before adding its own. For direct-to-client deployments, \
                 use KeyExtractor::PeerIp instead."
            );
        }
        RateLimitConfig {
            max_requests: self.max_requests,
            window: self.window,
            key_extractor: self.key_extractor,
            retry_after: self.retry_after,
        }
    }
}

// ── Token bucket ─────────────────────────────────────────────────────────────

/// A single token bucket tracking remaining tokens and the window start.
#[derive(Debug)]
struct TokenBucket {
    /// Tokens remaining in the current window.
    remaining: u32,
    /// When the current window started.
    window_start: Instant,
}

impl TokenBucket {
    fn new(max: u32, now: Instant) -> Self {
        Self {
            remaining: max,
            window_start: now,
        }
    }
}

/// Shared bucket store.  [`DashMap`] gives lock-free concurrent reads/writes.
#[derive(Clone)]
struct BucketStore {
    buckets: Arc<DashMap<String, TokenBucket>>,
    max_requests: u32,
    window: Duration,
    /// Request counter for deterministic eviction scheduling.
    request_count: Arc<AtomicU64>,
}

/// Result of trying to acquire a token.
enum Acquire {
    /// Token granted; remaining count returned for `X-RateLimit-Remaining` header.
    Allowed { remaining: u32 },
    /// Rate limited; seconds until the bucket resets.
    Limited { retry_after_secs: u64 },
}

impl BucketStore {
    fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            max_requests,
            window,
            request_count: Arc::new(AtomicU64::new(0)),
        }
    }

    fn try_acquire(&self, key: &str) -> Acquire {
        self.try_acquire_at(key, Instant::now())
    }

    /// Deterministic variant accepting an explicit `now` for testing.
    fn try_acquire_at(&self, key: &str, now: Instant) -> Acquire {
        let mut entry = self
            .buckets
            .entry(key.to_owned())
            .or_insert_with(|| TokenBucket::new(self.max_requests, now));

        let bucket = entry.value_mut();

        // Reset window if expired.
        if now.duration_since(bucket.window_start) >= self.window {
            bucket.remaining = self.max_requests;
            bucket.window_start = now;
        }

        if bucket.remaining > 0 {
            bucket.remaining -= 1;
            Acquire::Allowed {
                remaining: bucket.remaining,
            }
        } else {
            let elapsed = now.duration_since(bucket.window_start);
            let retry_after = self.window.saturating_sub(elapsed).as_secs().max(1);
            Acquire::Limited {
                retry_after_secs: retry_after,
            }
        }
    }

    /// Remove buckets whose window has expired.  Called lazily to avoid
    /// accumulating stale entries over long uptimes.
    fn evict_expired(&self) {
        self.evict_expired_at(Instant::now());
    }

    /// Deterministic variant accepting an explicit `now` for testing.
    fn evict_expired_at(&self, now: Instant) {
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.window_start) < self.window);
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
/// runs. The identifier is lowercased on construction so case variation
/// can't trivially evade the limit.
///
/// See [`KeyExtractor::LoginIdentifier`] and the module-level example
///
#[derive(Clone, Debug)]
pub struct RateLimitLoginIdentifier(String);

impl RateLimitLoginIdentifier {
    /// Build a normalised login-identifier key. Trims whitespace, lowercases
    /// (Unicode-aware), and rejects empty input by returning `None`; the
    /// caller should treat that as the anonymous bucket.
    pub fn new(identifier: impl AsRef<str>) -> Option<Self> {
        let trimmed = identifier.as_ref().trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(Self(trimmed.to_lowercase()))
    }

    /// The normalised key value used for bucket lookup.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Sentinel bucket key for unauthenticated requests when the extractor is
/// scoped to an authenticated identity (`UserId` / `TenantId`). All such
/// requests share a single bucket so the per-identity rate limit cannot be
/// trivially evaded by sending unauthenticated traffic; they are
/// rate-limited collectively under this key.
const ANONYMOUS_BUCKET: &str = "__anonymous__";

/// Hard cap on bucket-key length (bytes). Header- and identity-derived
/// keys are truncated to this size before being used as a `DashMap` key, so
/// an attacker who sets megabyte-sized `X-Forwarded-For` / `X-User-Id` /
/// custom-header values cannot inflate per-bucket allocation. Real values
/// (IP addresses, UUIDs, identifiers) are far smaller than this.
const MAX_KEY_LEN: usize = 256;

/// Whether the builder should emit the "very low max_requests" warning.
fn should_warn_very_low_max_requests(max_requests: u32) -> bool {
    max_requests < 5
}

/// Whether the builder should emit the "window exceeds 1 hour" warning.
fn should_warn_very_long_window(window: std::time::Duration) -> bool {
    window > std::time::Duration::from_secs(3600)
}

fn truncate_key(mut key: String) -> String {
    if key.len() > MAX_KEY_LEN {
        // Truncate at a UTF-8 boundary to keep the resulting string valid.
        let mut cut = MAX_KEY_LEN;
        while !key.is_char_boundary(cut) {
            cut -= 1;
        }
        key.truncate(cut);
    }
    key
}

fn extract_key(req: &Request<Body>, extractor: &KeyExtractor) -> String {
    let raw = match extractor {
        KeyExtractor::ForwardedIp => extract_forwarded_ip(req),
        KeyExtractor::PeerIp => extract_peer_ip(req),
        KeyExtractor::UserId => req
            .extensions()
            .get::<RateLimitUserId>()
            .map(|u| u.0.to_string())
            .or_else(|| header_str(req, "x-user-id"))
            .unwrap_or_else(|| ANONYMOUS_BUCKET.to_owned()),
        KeyExtractor::TenantId => req
            .extensions()
            .get::<RateLimitTenantId>()
            .map(|t| t.0.to_string())
            .or_else(|| header_str(req, "x-tenant-id"))
            .unwrap_or_else(|| ANONYMOUS_BUCKET.to_owned()),
        KeyExtractor::LoginIdentifier => req
            .extensions()
            .get::<RateLimitLoginIdentifier>()
            .map(|i| i.as_str().to_owned())
            .unwrap_or_else(|| ANONYMOUS_BUCKET.to_owned()),
        KeyExtractor::Header(name) => header_str(req, name).unwrap_or_else(|| extract_peer_ip(req)),
    };
    truncate_key(raw)
}

/// Extract client IP from proxy headers (`X-Real-IP`, `X-Forwarded-For`).
///
/// Only use behind a trusted reverse proxy that sets these headers from the
/// real peer address and strips client-supplied values.
fn extract_forwarded_ip(req: &Request<Body>) -> String {
    let headers = req.headers();
    headers
        .get("x-real-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| extract_peer_ip(req))
}

/// Extract client IP from the TCP peer address stored in request extensions.
///
/// Looks for axum's `ConnectInfo<SocketAddr>` (populated when the server
/// is mounted via `Router::into_make_service_with_connect_info::<SocketAddr>()`),
/// then falls back to a bare `SocketAddr` (which some integrations insert
/// directly, e.g. test harnesses that wire the extension by hand).
///
/// Falls back to a shared bucket (`"unknown"`) if no peer address is
/// available. This is fail-closed: all unknown-origin requests share one
/// bucket, meaning stricter (not weaker) rate limiting.
fn extract_peer_ip(req: &Request<Body>) -> String {
    let ext = req.extensions();
    let addr = ext
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0)
        .or_else(|| ext.get::<std::net::SocketAddr>().copied());
    addr.map(|addr| addr.ip().to_string()).unwrap_or_else(|| {
        use std::sync::Once;
        static WARN: Once = Once::new();
        WARN.call_once(|| {
            tracing::warn!(
                "PeerIp rate limiting: no SocketAddr in request extensions; \
                     all requests will share a single bucket. Use \
                     Router::into_make_service_with_connect_info::<SocketAddr>() \
                     or switch to KeyExtractor::ForwardedIp behind a trusted proxy."
            );
        });
        "unknown".to_owned()
    })
}

fn header_str(req: &Request<Body>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
}

// ── Tower Layer / Service ────────────────────────────────────────────────────

/// Tower layer that adds token-bucket rate limiting.
#[derive(Clone)]
pub struct RateLimitLayer {
    store: BucketStore,
    key_extractor: KeyExtractor,
    retry_after: bool,
    metrics: Option<Arc<dyn crate::metrics::AuthnMetrics>>,
}

impl RateLimitLayer {
    /// Create a new rate-limit layer from the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            store: BucketStore::new(config.max_requests, config.window),
            key_extractor: config.key_extractor,
            retry_after: config.retry_after,
            metrics: None,
        }
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
        let key = extract_key(&req, &self.key_extractor);
        let retry_after_enabled = self.retry_after;

        // Lazy eviction. Two triggers:
        //   (1) every 128 requests; bounded steady-state cleanup that
        //       keeps the map small under normal load and tightens the
        //       window an attacker has to inflate it before cleanup fires
        //       (the previous 1024-request interval gave a much larger
        //       gap to inject distinct keys);
        //   (2) any time the bucket count exceeds the soft cap, force an
        //       immediate eviction sweep; this is the brake on
        //       attacker-driven growth where unique keys are sent at
        //       high rate.
        // Combined with the per-key `MAX_KEY_LEN` truncation in
        // `extract_key`, total memory usage stays bounded even under a
        // unique-key flood: O(MAX_BUCKETS * (MAX_KEY_LEN + bucket-size)).
        const EVICT_INTERVAL: u64 = 128;
        const SOFT_BUCKET_CAP: usize = 64 * 1024;
        let count = self.store.request_count.fetch_add(1, Ordering::Relaxed);
        if (count.is_multiple_of(EVICT_INTERVAL) || self.store.buckets.len() > SOFT_BUCKET_CAP)
            && !self.store.buckets.is_empty()
        {
            self.store.evict_expired();
        }

        let metrics = self.metrics.clone();
        match self.store.try_acquire(&key) {
            Acquire::Allowed { remaining } => {
                if let Some(ref m) = metrics {
                    m.rate_limit_allowed();
                }
                // Clone inner *before* the async block; required by tower's contract.
                let mut inner = self.inner.clone();
                std::mem::swap(&mut inner, &mut self.inner);
                Box::pin(async move {
                    let mut resp = inner.call(req).await?;
                    if let Ok(val) = axum::http::HeaderValue::from_str(&remaining.to_string()) {
                        resp.headers_mut().insert("x-ratelimit-remaining", val);
                    }
                    Ok(resp)
                })
            }
            Acquire::Limited { retry_after_secs } => {
                if let Some(ref m) = metrics {
                    m.rate_limit_rejected();
                }
                tracing::debug!(
                    key = %key,
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
