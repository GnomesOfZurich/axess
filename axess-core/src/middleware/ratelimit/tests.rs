//! Tests for the parent `ratelimit` module.
//!
//! Lives in a sibling sub-module so the production module stays free of the
//! 360+ lines of `OkService` / fixture scaffolding.

use super::*;
use axess_clock::testing::MockClock;
use axum::http::HeaderValue;
use chrono::TimeZone;
use tower::ServiceExt;

mod hardening;
mod key_bounds;
mod sliding_window;
mod sweep;

use keys::{MAX_KEY_LEN, extract_key, resolve_target};
use std::sync::atomic::Ordering;
use store::HARD_BUCKET_CAP;

/// A fixed origin well away from the real clock.
fn t_zero() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2031, 3, 1, 12, 0, 0).unwrap()
}

fn secs(t: DateTime<Utc>, n: i64) -> DateTime<Utc> {
    t + chrono::Duration::seconds(n)
}

fn test_store(max: u32, window: Duration) -> BucketStore {
    BucketStore::new(max, window, Arc::new(MockClock::at(t_zero())))
}

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

/// A request that the client-IP layer has already resolved to `ip`.
///
/// This used to set `X-Forwarded-For` and let the extractor believe it,
/// which is precisely the bypass `KeyExtractor::ClientIp` exists to close:
/// the header is no longer read, so a header-based fixture would put every
/// request in the same bucket. The resolved value goes in the extensions,
/// where the layer puts it.
fn make_request_with_ip(ip: &str) -> Request<Body> {
    let mut req = Request::new(Body::empty());
    req.extensions_mut()
        .insert(crate::client_ip::ClientIp::for_test(Some(
            ip.parse().unwrap(),
        )));
    req
}

/// A request carrying a forged forwarded header and no resolved address,
/// which is what an attacker can actually produce.
fn make_request_with_forged_header(ip: &str) -> Request<Body> {
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_str(ip).unwrap());
    req
}

fn make_service(max: u32, window: Duration) -> RateLimitService<OkService> {
    let config = RateLimitConfig::builder()
        .max_requests(max)
        .window(window)
        .key(KeyExtractor::ClientIp)
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
    let store = test_store(1, Duration::from_secs(1));

    let t0 = t_zero();

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
    let t1 = secs(t0, 2);
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
        .key(KeyExtractor::ClientIp)
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
        .key(KeyExtractor::ClientIp)
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
    let store = test_store(1, Duration::from_secs(10));

    let t0 = t_zero();
    store.try_acquire_at("stale", t0);

    // Advance well past the window.
    let t1 = secs(t0, 20);

    // Insert a fresh bucket at t1.
    store.try_acquire_at("fresh", t1);

    // Evict using t1 as "now"; stale bucket's window started at t0 (20s ago > 10s window).
    store.evict_expired_at(t1);

    // Stale bucket should be gone; fresh one remains.
    assert!(!store.buckets.contains_key("stale"));
    assert!(store.buckets.contains_key("fresh"));
}

fn header_request(user: Option<&str>, key: &str) -> Request<Body> {
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert("x-api-key", HeaderValue::from_str(key).unwrap());
    req.extensions_mut()
        .insert(std::net::SocketAddr::from(([203, 0, 113, 9], 4000)));
    if let Some(u) = user {
        req.extensions_mut()
            .insert(RateLimitUserId(u.parse().unwrap()));
    }
    req
}

const USER_A: &str = "00000000-0000-4000-8000-00000000000a";
const USER_B: &str = "00000000-0000-4000-8000-00000000000b";

fn header_service() -> RateLimitService<OkService> {
    let config = RateLimitConfig::builder()
        .max_requests(1)
        .window(Duration::from_secs(60))
        .key(KeyExtractor::Header("x-api-key".into()))
        .build();
    RateLimitLayer::new(config).layer(OkService)
}

#[tokio::test]
async fn header_key_subdivides_an_authenticated_identity() {
    let svc = header_service();
    let status = |req| {
        let svc = svc.clone();
        async move { ServiceExt::oneshot(svc, req).await.unwrap().status() }
    };
    assert_eq!(
        status(header_request(Some(USER_A), "key-a")).await,
        StatusCode::OK
    );
    assert_eq!(
        status(header_request(Some(USER_A), "key-a")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        status(header_request(Some(USER_A), "key-b")).await,
        StatusCode::OK
    );
    // Another user's identical header value is another bucket.
    assert_eq!(
        status(header_request(Some(USER_B), "key-a")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn rotating_header_values_without_identity_share_the_peer_bucket() {
    let svc = header_service();
    let first = ServiceExt::oneshot(svc.clone(), header_request(None, "v1"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    for v in ["v2", "v3", "v4"] {
        let res = ServiceExt::oneshot(svc.clone(), header_request(None, v))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a new header value must not buy a new bucket"
        );
    }
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

/// The `evict_expired` wrapper reads the store's clock: advancing the mock
/// clock past the window is what ages the bucket out.
#[tokio::test]
async fn evict_expired_reads_the_store_clock() {
    let clock = MockClock::at(t_zero());
    let store = BucketStore::new(1, Duration::from_secs(20), Arc::new(clock.clone()));
    store.try_acquire("aged-out");
    assert!(store.buckets.contains_key("aged-out"));
    store.evict_expired();
    assert!(
        store.buckets.contains_key("aged-out"),
        "a bucket inside its window survives"
    );
    clock.advance_secs(21);
    store.evict_expired();
    assert!(
        store.buckets.contains_key("aged-out"),
        "one window on it still weighs on the estimate"
    );
    clock.advance_secs(20);
    store.evict_expired();
    assert!(
        !store.buckets.contains_key("aged-out"),
        "evict_expired() must read the injected clock"
    );
}

/// `evict_expired_at` retains buckets while
/// `now - window_start < 2 * window`: strict less-than.
/// At exactly two windows, the bucket must evict. Pins the `< → <=`
/// mutation, which would keep buckets at the boundary.
#[tokio::test]
async fn evict_expired_at_evicts_when_age_equals_window() {
    let store = test_store(1, Duration::from_secs(10));
    let t0 = t_zero();
    store.try_acquire_at("at-cutoff", t0);
    // Evict at exactly two windows: 20 s, original < 20 s = false (evict).
    store.evict_expired_at(secs(t0, 20));
    assert!(
        !store.buckets.contains_key("at-cutoff"),
        "at age == two windows the bucket must evict (strict `<`, not `<=`)"
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
    let ip = resolve_target(&req, &KeyExtractor::PeerIp).key;
    assert_eq!(
        ip, "ip:192.0.2.7",
        "the peer key must carry the SocketAddr's IP"
    );

    // No SocketAddr → fail-closed shared bucket name.
    let req = Request::new(Body::empty());
    let ip = resolve_target(&req, &KeyExtractor::PeerIp).key;
    assert_eq!(
        ip, "ip:unknown",
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

/// The bypass this variant exists to close: rotating a forwarded header
/// must not buy a fresh bucket. Before 0.7.0 each of these landed in its
/// own bucket and the limiter was ornamental behind a proxy that appends.
#[tokio::test]
async fn forged_forwarded_headers_share_one_bucket() {
    let svc = make_service(1, Duration::from_secs(60));

    let res = ServiceExt::oneshot(svc.clone(), make_request_with_forged_header("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = ServiceExt::oneshot(svc.clone(), make_request_with_forged_header("10.0.0.2"))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a different forged header must not reset the bucket"
    );
}

/// A header value spelled like an address lives in a different bucket from
/// the client at that address, so `X-Api-Key: 10.0.0.5` cannot drain
/// 10.0.0.5's bucket.
#[test]
fn header_key_and_ip_fallback_do_not_collide() {
    let extractor = KeyExtractor::Header("x-api-key".to_string());
    let with_header = header_request(Some(USER_A), "10.0.0.5");
    let from_ip = make_request_with_ip("10.0.0.5");
    let a = extract_key(&with_header, &extractor);
    let b = extract_key(&from_ip, &extractor);
    assert_ne!(
        a, b,
        "header key {a:?} and ip fallback {b:?} must be distinct buckets"
    );
    assert!(a.starts_with("h:") && b.starts_with("ip:"));
}
