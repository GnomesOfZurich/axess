//! Benchmarks for the rate limiter; throughput under concurrent load.

use axess_core::middleware::ratelimit::{KeyExtractor, RateLimitConfig, RateLimitLayer};
use axum::{Router, body::Body, http::Request, routing::get};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;
use tower::ServiceExt;

fn make_request(ip: &str) -> Request<Body> {
    Request::builder()
        .header("x-forwarded-for", ip)
        .body(Body::empty())
        .unwrap()
}

/// Single-threaded throughput: how many requests/sec can the rate limiter handle?
fn bench_ratelimit_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RateLimitLayer::new(
            RateLimitConfig::builder()
                .max_requests(1_000_000) // High limit so we measure overhead, not rejection
                .window(Duration::from_secs(60))
                .key(KeyExtractor::ForwardedIp)
                .build(),
        ));

    c.bench_function("ratelimit_allow_single_ip", |b| {
        b.to_async(&rt).iter(|| {
            let app = app.clone();
            async move {
                let resp = app
                    .oneshot(black_box(make_request("10.0.0.1")))
                    .await
                    .unwrap();
                black_box(resp.status());
            }
        })
    });
}

/// Multi-IP throughput: different keys don't contend.
fn bench_ratelimit_multi_ip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RateLimitLayer::new(
            RateLimitConfig::builder()
                .max_requests(1_000_000)
                .window(Duration::from_secs(60))
                .key(KeyExtractor::ForwardedIp)
                .build(),
        ));

    let mut counter = 0u32;

    c.bench_function("ratelimit_allow_rotating_ips", |b| {
        b.to_async(&rt).iter(|| {
            let app = app.clone();
            counter = counter.wrapping_add(1);
            let ip = format!("10.0.{}.{}", (counter >> 8) & 0xFF, counter & 0xFF);
            async move {
                let resp = app.oneshot(make_request(&ip)).await.unwrap();
                black_box(resp.status());
            }
        })
    });
}

/// Cost of a rejected request (429 path).
fn bench_ratelimit_reject(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RateLimitLayer::new(
            RateLimitConfig::builder()
                .max_requests(1) // Exhaust immediately
                .window(Duration::from_secs(3600))
                .key(KeyExtractor::ForwardedIp)
                .build(),
        ));

    // Exhaust the single token.
    rt.block_on(async {
        app.clone().oneshot(make_request("10.0.0.1")).await.unwrap();
    });

    c.bench_function("ratelimit_reject_429", |b| {
        b.to_async(&rt).iter(|| {
            let app = app.clone();
            async move {
                let resp = app
                    .oneshot(black_box(make_request("10.0.0.1")))
                    .await
                    .unwrap();
                black_box(resp.status());
            }
        })
    });
}

criterion_group!(
    benches,
    bench_ratelimit_throughput,
    bench_ratelimit_multi_ip,
    bench_ratelimit_reject,
);
criterion_main!(benches);
