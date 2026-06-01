//! Tests for the parent `ratelimit` module.
//!
//! Lives in a sibling sub-module so the production module stays free of the
//! 360+ lines of `OkService` / fixture scaffolding.

use super::*;
use axum::http::HeaderValue;
use tower::ServiceExt;

/// Trivial inner service that always returns 200 OK.
#[derive(Clone)]
struct OkService;

impl Service<Request<Body>> for OkService {
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let waker = cx.waker();
        assert!(
            waker.will_wake(waker),
            "Waker::will_wake must hold reflexively"
        );
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        tracing::trace!(method = %req.method(), "OkService call");
        Box::pin(async { Ok(Response::new(Body::empty())) })
    }
}

fn make_request_with_ip(ip: &str) -> Request<Body> {
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_str(ip).unwrap());
    req
}

fn make_service(max: u32, window: Duration) -> RateLimitService<OkService> {
    let config = RateLimitConfig::builder()
        .max_requests(max)
        .window(window)
        .key(KeyExtractor::ForwardedIp)
        .build();
    let layer = RateLimitLayer::new(config);
    layer.layer(OkService)
}

#[tokio::test]
async fn request_within_limit_passes() {
    let svc = make_service(5, Duration::from_secs(60));
    let req = make_request_with_ip("1.2.3.4");
    let res = ServiceExt::oneshot(svc, req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn request_exceeding_limit_returns_429() {
    let svc = make_service(2, Duration::from_secs(60));

    // Exhaust the two allowed requests.
    let res = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Third request must be rejected.
    let res = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn window_reset_allows_new_requests() {
    let store = BucketStore::new(1, Duration::from_secs(1));

    let t0 = Instant::now();

    // First request succeeds.
    assert!(matches!(
        store.try_acquire_at("k", t0),
        Acquire::Allowed { .. }
    ));

    // Second request within the same window fails.
    assert!(matches!(
        store.try_acquire_at("k", t0),
        Acquire::Limited { .. }
    ));

    // After the window resets, requests succeed again.
    let t1 = t0 + Duration::from_secs(2);
    assert!(matches!(
        store.try_acquire_at("k", t1),
        Acquire::Allowed { .. }
    ));
}

#[tokio::test]
async fn per_key_isolation() {
    let svc = make_service(1, Duration::from_secs(60));

    // IP A exhausts its single token.
    let res = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    // IP B still has its own bucket; should succeed.
    let res = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.0.0.2"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn retry_after_header_present_when_configured() {
    let config = RateLimitConfig::builder()
        .max_requests(1)
        .window(Duration::from_secs(120))
        .key(KeyExtractor::ForwardedIp)
        .retry_after(true)
        .build();
    let svc = RateLimitLayer::new(config).layer(OkService);

    // Exhaust token.
    let _ = ServiceExt::oneshot(svc.clone(), make_request_with_ip("5.5.5.5"))
        .await
        .unwrap();

    // This request should be limited and carry Retry-After.
    let res = ServiceExt::oneshot(svc.clone(), make_request_with_ip("5.5.5.5"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    let header = res
        .headers()
        .get("retry-after")
        .expect("missing Retry-After header");
    let secs: u64 = header.to_str().unwrap().parse().unwrap();
    assert!(secs > 0);
}

#[tokio::test]
async fn retry_after_header_absent_when_disabled() {
    let config = RateLimitConfig::builder()
        .max_requests(1)
        .window(Duration::from_secs(60))
        .key(KeyExtractor::ForwardedIp)
        .retry_after(false)
        .build();
    let svc = RateLimitLayer::new(config).layer(OkService);

    let _ = ServiceExt::oneshot(svc.clone(), make_request_with_ip("6.6.6.6"))
        .await
        .unwrap();

    let res = ServiceExt::oneshot(svc.clone(), make_request_with_ip("6.6.6.6"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().get("retry-after").is_none());
}

#[tokio::test]
async fn concurrent_access_does_not_panic() {
    let svc = make_service(1000, Duration::from_secs(60));

    let handles: Vec<_> = (0..50)
        .map(|i| {
            let svc = svc.clone();
            tokio::spawn(async move {
                let ip = format!("10.0.{}.{}", i / 256, i % 256);
                let req = make_request_with_ip(&ip);
                let res = ServiceExt::oneshot(svc, req).await.unwrap();
                assert_eq!(res.status(), StatusCode::OK);
            })
        })
        .collect();

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn evict_expired_removes_stale_buckets() {
    let store = BucketStore::new(1, Duration::from_secs(10));

    let t0 = Instant::now();
    store.try_acquire_at("stale", t0);

    // Advance well past the window.
    let t1 = t0 + Duration::from_secs(20);

    // Insert a fresh bucket at t1.
    store.try_acquire_at("fresh", t1);

    // Evict using t1 as "now"; stale bucket's window started at t0 (20s ago > 10s window).
    store.evict_expired_at(t1);

    // Stale bucket should be gone; fresh one remains.
    assert!(!store.buckets.contains_key("stale"));
    assert!(store.buckets.contains_key("fresh"));
}

#[tokio::test]
async fn header_key_extractor() {
    let config = RateLimitConfig::builder()
        .max_requests(1)
        .window(Duration::from_secs(60))
        .key(KeyExtractor::Header("x-api-key".into()))
        .build();
    let svc = RateLimitLayer::new(config).layer(OkService);

    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert("x-api-key", HeaderValue::from_static("key-a"));
    let res = ServiceExt::oneshot(svc.clone(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Same key, should be limited.
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert("x-api-key", HeaderValue::from_static("key-a"));
    let res = ServiceExt::oneshot(svc.clone(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    // Different key, should pass.
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert("x-api-key", HeaderValue::from_static("key-b"));
    let res = ServiceExt::oneshot(svc.clone(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn eviction_triggers_on_request_count_not_just_bucket_size() {
    // Regression test: eviction used to require >1024 buckets AND len%512==0.
    // Now it triggers every 1024 requests via atomic counter.
    let store = BucketStore::new(100, Duration::from_secs(1));
    let t0 = Instant::now();

    // Create a stale bucket.
    store.try_acquire_at("stale", t0);

    // Advance time past window.
    let t1 = t0 + Duration::from_secs(5);

    // Simulate 1024 requests on a single key (few buckets, many requests).
    for _ in 0..1024 {
        store.try_acquire_at("active", t1);
        // Manually increment counter to match what the service call does.
        store.request_count.fetch_add(1, Ordering::Relaxed);
    }

    // Force eviction at t1.
    store.evict_expired_at(t1);

    // Stale bucket should be gone.
    assert!(
        !store.buckets.contains_key("stale"),
        "stale bucket should have been evicted"
    );
    assert!(store.buckets.contains_key("active"));
}

// ── Per-username login lockout DoS mitigation ───────────────────

fn make_login_request(identifier: Option<&str>) -> Request<Body> {
    let mut req = Request::new(Body::empty());
    if let Some(id) = identifier
        && let Some(ext) = RateLimitLoginIdentifier::new(id)
    {
        req.extensions_mut().insert(ext);
    }
    req
}

fn make_login_service(max: u32) -> RateLimitService<OkService> {
    let config = RateLimitConfig::builder()
        .max_requests(max)
        .window(Duration::from_secs(60))
        .key(KeyExtractor::LoginIdentifier)
        .build();
    RateLimitLayer::new(config).layer(OkService)
}

#[tokio::test]
async fn login_identifier_buckets_attempts_per_username() {
    // Two requests for `alice` exhaust her bucket. A request for `bob`
    // is independent and still passes; the per-username bucketing is
    // what stops the attack from spilling across accounts AND what
    // contains the legitimate user's lockout pain to their own account.
    let svc = make_login_service(2);

    let res = ServiceExt::oneshot(svc.clone(), make_login_request(Some("alice")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = ServiceExt::oneshot(svc.clone(), make_login_request(Some("alice")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Third alice attempt: 429.
    let res = ServiceExt::oneshot(svc.clone(), make_login_request(Some("alice")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    // Different identifier, fresh bucket.
    let res = ServiceExt::oneshot(svc.clone(), make_login_request(Some("bob")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_identifier_normalises_case_and_whitespace() {
    // `Alice`, `  alice  `, `ALICE` all share one bucket so an attacker
    // can't trivially evade the per-username limit.
    let svc = make_login_service(1);

    let res = ServiceExt::oneshot(svc.clone(), make_login_request(Some("Alice")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Same identifier in a different case is the same bucket.
    let res = ServiceExt::oneshot(svc.clone(), make_login_request(Some("  ALICE  ")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn login_identifier_missing_extension_falls_to_anonymous_bucket() {
    // No extension → all such requests share one bucket. This is the
    // "fail closed" stance: a misconfigured route limits anonymous
    // traffic collectively rather than letting it bypass the layer.
    let svc = make_login_service(1);

    let res = ServiceExt::oneshot(svc.clone(), make_login_request(None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = ServiceExt::oneshot(svc.clone(), make_login_request(None))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "missing extension must funnel into the shared anonymous bucket"
    );
}

#[test]
fn login_identifier_rejects_empty_input() {
    assert!(RateLimitLoginIdentifier::new("").is_none());
    assert!(RateLimitLoginIdentifier::new("   ").is_none());
    assert!(RateLimitLoginIdentifier::new("alice").is_some());
}

// ── Mutation-coverage tests ────────────────────────────────────────────────

/// Keys at exactly `MAX_KEY_LEN` bytes are passed through
/// unchanged. Pins the `>` operator at line 412 against `==`/`>=`
/// (which would truncate at the boundary too) and `<` (which would
/// truncate everything *under* the cap, the inverse of the intent).
#[test]
fn truncate_key_at_max_key_len_unchanged() {
    let key = "x".repeat(MAX_KEY_LEN);
    let out = truncate_key(key.clone());
    assert_eq!(
        out.len(),
        MAX_KEY_LEN,
        "key length at exactly MAX_KEY_LEN must pass through"
    );
    assert_eq!(out, key, "at-cap key must be byte-identical");
}

/// Keys one byte over the cap are truncated. Pairs with the
/// at-cap test to discriminate `>` from `<`.
#[test]
fn truncate_key_one_byte_over_cap_is_truncated() {
    let key = "x".repeat(MAX_KEY_LEN + 1);
    let out = truncate_key(key);
    assert_eq!(
        out.len(),
        MAX_KEY_LEN,
        "one byte over MAX_KEY_LEN must truncate to MAX_KEY_LEN"
    );
}

/// When a multi-byte char straddles the cap, `truncate_key`
/// walks back to the previous UTF-8 boundary so the resulting `String`
/// is valid UTF-8 (otherwise `String::truncate` panics). Pins three
/// mutations on the walk loop:
/// - `delete !` at line 415: the loop becomes `while is_char_boundary
///   { cut -= 1; }`. Starting at `cut = 256` (mid-emoji, not a
///   boundary), the loop body is skipped immediately and `cut` stays
///   at 256; `String::truncate(256)` then panics on the non-boundary,
///   causing the test to fail.
/// - `-= → +=` at line 416: `cut` walks UP, exits at the string end,
///   and `truncate(end)` is a no-op; output length stays at 258
///   instead of 254.
/// - `-= → /=` at line 416: `cut /= 1` is a no-op, the loop never
///   exits → mutant times out.
///
/// Setup: `"a"×254 + "🚀"` is 254 + 4 = 258 bytes. The cap (256) lands
/// in the middle of the emoji, so the walk-back must reach 254.
#[test]
fn truncate_key_walks_back_to_char_boundary_on_multibyte() {
    let key = "a".repeat(MAX_KEY_LEN - 2) + "🚀";
    assert_eq!(key.len(), MAX_KEY_LEN + 2, "test fixture: 258-byte key");

    let out = truncate_key(key);
    assert_eq!(
        out.len(),
        MAX_KEY_LEN - 2,
        "walk-back must land at UTF-8 boundary (254), not 256/258"
    );
    assert!(
        out.is_char_boundary(out.len()),
        "truncated key must end on a char boundary"
    );
    assert!(
        !out.contains('🚀'),
        "truncated key must drop the straddling multi-byte char"
    );
}

/// The public `evict_expired` wrapper must delegate to
/// `evict_expired_at(Instant::now())`. The body replacement
/// `evict_expired with ()` is otherwise indistinguishable, since every
/// existing test calls `evict_expired_at` directly.
#[tokio::test]
async fn evict_expired_delegates_to_at_helper() {
    let store = BucketStore::new(1, Duration::from_millis(20));
    // Insert a bucket via the public path (uses Instant::now()).
    store.try_acquire("aged-out");
    assert!(store.buckets.contains_key("aged-out"));
    // Wait past the window.
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Public wrapper must call the helper with current time and prune.
    store.evict_expired();
    assert!(
        !store.buckets.contains_key("aged-out"),
        "evict_expired() must delegate to evict_expired_at(Instant::now()), \
         not be a no-op"
    );
}

/// `evict_expired_at` retains buckets while
/// `now.duration_since(window_start) < self.window`: strict less-than.
/// At exactly `window`, the bucket must evict. Pins the `< → <=`
/// mutation, which would keep buckets at the boundary.
#[tokio::test]
async fn evict_expired_at_evicts_when_age_equals_window() {
    let store = BucketStore::new(1, Duration::from_secs(10));
    let t0 = Instant::now();
    store.try_acquire_at("at-cutoff", t0);
    // Evict at exactly window-end: duration_since = 10s, original < 10s = false (evict).
    store.evict_expired_at(t0 + Duration::from_secs(10));
    assert!(
        !store.buckets.contains_key("at-cutoff"),
        "at age == window the bucket must evict (strict `<`, not `<=`)"
    );
}

/// `extract_peer_ip` reads the `SocketAddr` from request
/// extensions and returns its IP as a string. Pins both
/// `String::new()` and `"xyzzy".into()` body mutations; neither
/// existing test populates `SocketAddr`, so the function was unobserved.
#[test]
fn extract_peer_ip_reads_socket_addr_from_extensions() {
    use std::net::SocketAddr;

    let mut req = Request::new(Body::empty());
    let addr: SocketAddr = "192.0.2.7:54321".parse().expect("test addr");
    req.extensions_mut().insert(addr);
    let ip = extract_peer_ip(&req);
    assert_eq!(
        ip, "192.0.2.7",
        "extract_peer_ip must return the SocketAddr's IP"
    );

    // No SocketAddr → fail-closed shared bucket name.
    let req = Request::new(Body::empty());
    let ip = extract_peer_ip(&req);
    assert_eq!(
        ip, "unknown",
        "missing SocketAddr must fall through to the shared 'unknown' bucket"
    );
}

#[test]
fn warn_threshold_helpers_have_strict_bounds() {
    assert!(should_warn_very_low_max_requests(0));
    assert!(should_warn_very_low_max_requests(4));
    assert!(!should_warn_very_low_max_requests(5));
    assert!(!should_warn_very_low_max_requests(100));

    use std::time::Duration;
    assert!(!should_warn_very_long_window(Duration::from_secs(3600)));
    assert!(should_warn_very_long_window(Duration::from_secs(3601)));
    assert!(!should_warn_very_long_window(Duration::from_secs(60)));
}
