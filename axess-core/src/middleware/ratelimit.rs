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
//! The identifier is normalised to lowercase before keying so `Alice`
//! and `alice` share a bucket.
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
use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use chrono::{DateTime, Utc};
use dashmap::{DashMap, mapref::entry::Entry};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tower::{Layer, Service};

mod keys;
use keys::extract_key;

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
        }
    }
}

// ── Token bucket ─────────────────────────────────────────────────────────────

/// Number of buckets at which a request for a key with no bucket is refused.
/// Live buckets are never evicted to make room: a flood of distinct keys
/// cannot push a real client's bucket out and reset its count, so the
/// limiter answers the flood with 429 until the next expiry sweep frees room.
const HARD_BUCKET_CAP: usize = 256 * 1024;

/// Smallest gap between two expiry sweeps.
const MIN_SWEEP_INTERVAL_MS: u64 = 1_000;

/// Milliseconds since the Unix epoch, floored at zero.
fn epoch_millis(now: DateTime<Utc>) -> u64 {
    u64::try_from(now.timestamp_millis()).unwrap_or(0)
}

/// One key's sliding-window counter: the requests admitted in the current
/// fixed window and in the one before it.
///
/// The estimate of requests in the trailing window is the previous window's
/// count weighted by how much of it still overlaps, plus the current count,
/// all in integer arithmetic. It never undercounts a burst that straddles a
/// window boundary, so about `max_requests` pass in any trailing window and
/// not twice that.
#[derive(Debug)]
struct TokenBucket {
    /// Requests admitted in the window that began at `window_start_ms`.
    curr: u32,
    /// Requests admitted in the window before it.
    prev: u32,
    /// When the current window started, in epoch milliseconds from the
    /// injected clock.
    window_start_ms: u64,
}

impl TokenBucket {
    fn new(now_ms: u64) -> Self {
        Self {
            curr: 0,
            prev: 0,
            window_start_ms: now_ms,
        }
    }
}

/// Shared bucket store.  [`DashMap`] gives lock-free concurrent reads/writes.
#[derive(Clone)]
struct BucketStore {
    buckets: Arc<DashMap<String, TokenBucket>>,
    max_requests: u32,
    window_ms: u64,
    clock: Arc<dyn Clock>,
    /// Number of entries in `buckets`, kept beside the map so the per-request
    /// cap check does not read-lock every shard the way `DashMap::len` does.
    bucket_count: Arc<AtomicUsize>,
    /// Clock time (epoch milliseconds) of the last expiry sweep. The caller
    /// that wins the compare-exchange on it runs the sweep; the rest carry on.
    last_sweep_ms: Arc<AtomicU64>,
}

/// Result of trying to acquire a token.
enum Acquire {
    /// Token granted; remaining count returned for `X-RateLimit-Remaining` header.
    Allowed { remaining: u32 },
    /// Rate limited; seconds until the bucket resets.
    Limited { retry_after_secs: u64 },
    /// The bucket table is at its hard cap and this key has no bucket yet;
    /// refused until a sweep frees room.
    Saturated { retry_after_secs: u64 },
}

impl BucketStore {
    fn new(max_requests: u32, window: Duration, clock: Arc<dyn Clock>) -> Self {
        let now_ms = epoch_millis(clock.now());
        Self {
            buckets: Arc::new(DashMap::new()),
            max_requests,
            window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            clock,
            bucket_count: Arc::new(AtomicUsize::new(0)),
            last_sweep_ms: Arc::new(AtomicU64::new(now_ms)),
        }
    }

    /// Gap between sweeps: an eighth of the window, never under a second.
    fn sweep_interval_ms(&self) -> u64 {
        (self.window_ms / 8).max(MIN_SWEEP_INTERVAL_MS)
    }

    fn try_acquire(&self, key: &str) -> Acquire {
        self.try_acquire_at(key, self.clock.now())
    }

    /// Take a token for `key` at an explicit `now`.
    fn try_acquire_at(&self, key: &str, now: DateTime<Utc>) -> Acquire {
        let now_ms = epoch_millis(now);
        self.sweep_if_due(now_ms);

        // A key that already has a bucket is never refused for capacity.
        if let Some(mut bucket) = self.buckets.get_mut(key) {
            return self.take(&mut bucket, now_ms);
        }

        // Reserve a slot before inserting so concurrent first requests for
        // distinct keys cannot overshoot the cap.
        if self.bucket_count.fetch_add(1, Ordering::AcqRel) >= HARD_BUCKET_CAP {
            self.bucket_count.fetch_sub(1, Ordering::AcqRel);
            return Acquire::Saturated {
                retry_after_secs: (self.sweep_interval_ms() / 1_000).max(1),
            };
        }
        match self.buckets.entry(key.to_owned()) {
            Entry::Occupied(mut occupied) => {
                self.bucket_count.fetch_sub(1, Ordering::AcqRel);
                self.take(occupied.get_mut(), now_ms)
            }
            Entry::Vacant(vacant) => {
                let mut bucket = vacant.insert(TokenBucket::new(now_ms));
                self.take(&mut bucket, now_ms)
            }
        }
    }

    fn take(&self, bucket: &mut TokenBucket, now_ms: u64) -> Acquire {
        self.roll(bucket, now_ms);
        let estimate = self.estimate(bucket, now_ms);
        if estimate < u128::from(self.max_requests) {
            bucket.curr += 1;
            let remaining = u128::from(self.max_requests) - estimate - 1;
            Acquire::Allowed {
                remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
            }
        } else {
            Acquire::Limited {
                retry_after_secs: self.wait_ms(bucket, now_ms).div_ceil(1_000).max(1),
            }
        }
    }

    /// Advance `bucket` to the window containing `now_ms`.
    ///
    /// One window on, the current count becomes the previous one; two or
    /// more on, both are zero. A clock that steps backwards re-anchors the
    /// window at the earlier time and keeps the counts, so the bucket does
    /// not stay limited until the clock catches up with a future start.
    fn roll(&self, bucket: &mut TokenBucket, now_ms: u64) {
        if now_ms < bucket.window_start_ms {
            bucket.window_start_ms = now_ms;
            return;
        }
        let windows = (now_ms - bucket.window_start_ms) / self.window_ms;
        match windows {
            0 => {}
            1 => {
                bucket.prev = bucket.curr;
                bucket.curr = 0;
                bucket.window_start_ms += self.window_ms;
            }
            _ => {
                bucket.prev = 0;
                bucket.curr = 0;
                bucket.window_start_ms =
                    now_ms - (now_ms - bucket.window_start_ms) % self.window_ms;
            }
        }
    }

    /// Requests counted in the trailing window ending at `now_ms`.
    fn estimate(&self, bucket: &TokenBucket, now_ms: u64) -> u128 {
        let into = u128::from(now_ms.saturating_sub(bucket.window_start_ms));
        let window = u128::from(self.window_ms);
        let overlap = window.saturating_sub(into);
        u128::from(bucket.prev) * overlap / window + u128::from(bucket.curr)
    }

    /// Milliseconds until a request would be admitted, for a bucket that has
    /// just refused one.
    fn wait_ms(&self, bucket: &TokenBucket, now_ms: u64) -> u64 {
        let window = u128::from(self.window_ms);
        let max = u128::from(self.max_requests);
        let into = u128::from(now_ms.saturating_sub(bucket.window_start_ms));
        // Room left in the current window once the next request is counted.
        let (prev, headroom, wait_to_window_end) =
            match max.checked_sub(u128::from(bucket.curr) + 1) {
                Some(headroom) => (u128::from(bucket.prev), headroom, 0),
                // The current window is full: wait for it to end, after which its
                // count is the previous window's.
                None => (
                    u128::from(bucket.curr),
                    max - 1,
                    window.saturating_sub(into),
                ),
            };
        // The estimate is admitting once `prev * overlap / window <= headroom`
        // in integer division, that is `overlap <= ((headroom + 1) * window - 1) / prev`.
        let needed_into = ((headroom + 1) * window - 1)
            .checked_div(prev)
            .map_or(0, |largest_overlap| window - largest_overlap.min(window));
        let wait = if wait_to_window_end > 0 {
            wait_to_window_end + needed_into
        } else {
            needed_into.saturating_sub(into)
        };
        u64::try_from(wait).unwrap_or(u64::MAX)
    }

    /// Run an expiry sweep when one is due, on at most one caller.
    ///
    /// Due means a sweep interval has passed on the injected clock since the
    /// last one. The compare-exchange on the stamp picks the caller that
    /// sweeps; every other request in the same interval skips straight on,
    /// so the full-table scan runs once per interval instead of once per
    /// request.
    fn sweep_if_due(&self, now_ms: u64) {
        let last = self.last_sweep_ms.load(Ordering::Acquire);
        // A clock that stepped back leaves the stamp in the future; that
        // counts as due, so the stamp re-anchors instead of the sweep
        // waiting for the clock to catch up while the table fills.
        if now_ms >= last && now_ms - last < self.sweep_interval_ms() {
            return;
        }
        if self
            .last_sweep_ms
            .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.evict_expired_ms(now_ms);
        }
    }

    /// Remove buckets that no longer weigh on the estimate at the injected clock's time.
    #[cfg(test)]
    fn evict_expired(&self) {
        self.evict_expired_at(self.clock.now());
    }

    /// Remove buckets that no longer weigh on the estimate at `now`.
    #[cfg(test)]
    fn evict_expired_at(&self, now: DateTime<Utc>) {
        self.evict_expired_ms(epoch_millis(now));
    }

    fn evict_expired_ms(&self, now_ms: u64) {
        let mut removed = 0usize;
        self.buckets.retain(|_, bucket| {
            // A bucket still weighs on the estimate for one window past the
            // one it was last rolled into, so it lives for two.
            let live =
                now_ms.saturating_sub(bucket.window_start_ms) < self.window_ms.saturating_mul(2);
            if !live {
                removed += 1;
            }
            live
        });
        self.bucket_count.fetch_sub(removed, Ordering::AcqRel);
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
    metrics: Option<Arc<dyn crate::metrics::AuthnMetrics>>,
}

impl RateLimitLayer {
    /// Create a new rate-limit layer from the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            store: BucketStore::new(config.max_requests, config.window, config.clock),
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
            Acquire::Limited { retry_after_secs } | Acquire::Saturated { retry_after_secs } => {
                if let Some(ref m) = metrics {
                    m.rate_limit_rejected();
                }
                tracing::debug!(
                    key_fingerprint = %keys::fingerprint(&key),
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
