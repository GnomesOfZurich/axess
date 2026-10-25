//! Clock injection, the time-gated sweep, the bucket count and the hard cap.

use super::*;

fn millis(t: DateTime<Utc>, ms: i64) -> DateTime<Utc> {
    t + chrono::Duration::milliseconds(ms)
}

fn status(res: Result<Response<Body>, std::convert::Infallible>) -> StatusCode {
    res.unwrap().status()
}

#[tokio::test]
async fn the_layer_window_follows_the_injected_clock() {
    let clock = MockClock::at(t_zero());
    let config = RateLimitConfig::builder()
        .max_requests(1)
        .window(Duration::from_secs(60))
        .key(KeyExtractor::ClientIp)
        .clock(clock.clone())
        .build();
    let svc = RateLimitLayer::new(config).layer(OkService);

    let first = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.1.1.1")).await;
    assert_eq!(status(first), StatusCode::OK);
    let second = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.1.1.1")).await;
    assert_eq!(status(second), StatusCode::TOO_MANY_REQUESTS);

    clock.advance_secs(59);
    let still = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.1.1.1")).await;
    assert_eq!(status(still), StatusCode::TOO_MANY_REQUESTS);

    clock.advance_secs(1);
    let after = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.1.1.1")).await;
    assert_eq!(
        status(after),
        StatusCode::OK,
        "the window resets exactly when the injected clock passes it"
    );
}

#[test]
fn retry_after_is_the_time_left_on_the_injected_clock() {
    let store = test_store(1, Duration::from_secs(60));
    let t0 = t_zero();
    store.try_acquire_at("k", t0);
    match store.try_acquire_at("k", secs(t0, 45)) {
        Acquire::Limited { retry_after_secs } => assert_eq!(retry_after_secs, 15),
        _ => panic!("the bucket is empty at +45 s"),
    }
}

#[test]
fn a_sweep_runs_once_per_interval_and_not_once_per_request() {
    // A 2 s window sweeps every 1 s (the floor).
    let store = test_store(5, Duration::from_secs(2));
    let t0 = t_zero();

    store.try_acquire_at("y", millis(t0, 500));
    // Due (2.0 s since construction): "y" is still live, nothing goes.
    store.try_acquire_at("p", millis(t0, 2_000));
    assert_eq!(store.buckets.len(), 2);

    // "y" expired at 2.5 s, but the last sweep was 0.7 s ago: not due.
    store.try_acquire_at("q", millis(t0, 2_700));
    assert!(
        store.buckets.contains_key("y"),
        "a request inside the sweep interval must not scan the table"
    );
    assert_eq!(store.bucket_count.load(Ordering::Acquire), 3);

    // 1.0 s after the last sweep: due, and "y" goes.
    store.try_acquire_at("r", millis(t0, 3_000));
    assert!(!store.buckets.contains_key("y"));
    assert_eq!(store.bucket_count.load(Ordering::Acquire), 3);
    assert_eq!(store.buckets.len(), 3);
}

#[test]
fn the_sweep_interval_is_an_eighth_of_the_window_with_a_one_second_floor() {
    assert_eq!(
        test_store(1, Duration::from_secs(60)).sweep_interval_ms(),
        7_500
    );
    assert_eq!(
        test_store(1, Duration::from_secs(4)).sweep_interval_ms(),
        1_000
    );
}

#[test]
fn the_bucket_count_tracks_inserts_and_evictions() {
    let store = test_store(1, Duration::from_secs(10));
    let t0 = t_zero();
    for i in 0..50 {
        store.try_acquire_at(&format!("k{i}"), t0);
    }
    store.try_acquire_at("k0", t0);
    assert_eq!(store.bucket_count.load(Ordering::Acquire), 50);
    store.evict_expired_at(secs(t0, 10));
    assert_eq!(store.bucket_count.load(Ordering::Acquire), 0);
    assert!(store.buckets.is_empty());
}

fn fill_to_the_cap(store: &BucketStore, at: DateTime<Utc>) {
    for i in 0..HARD_BUCKET_CAP {
        assert!(matches!(
            store.try_acquire_at(&format!("flood-{i}"), at),
            Acquire::Allowed { .. }
        ));
    }
    assert_eq!(store.bucket_count.load(Ordering::Acquire), HARD_BUCKET_CAP);
}

#[test]
fn at_the_hard_cap_a_new_key_is_refused_and_a_known_key_is_not_evicted() {
    let store = test_store(2, Duration::from_secs(600));
    let t0 = t_zero();
    fill_to_the_cap(&store, t0);

    match store.try_acquire_at("newcomer", millis(t0, 1)) {
        Acquire::Saturated { retry_after_secs } => assert_eq!(retry_after_secs, 75),
        _ => panic!("a key with no bucket must be refused at the cap"),
    }
    assert!(!store.buckets.contains_key("newcomer"));
    assert_eq!(store.bucket_count.load(Ordering::Acquire), HARD_BUCKET_CAP);

    // A key that already has a bucket keeps its count: its second token is
    // granted, its third is the ordinary limit, and neither is a capacity
    // refusal.
    assert!(matches!(
        store.try_acquire_at("flood-0", millis(t0, 2)),
        Acquire::Allowed { remaining: 0 }
    ));
    assert!(matches!(
        store.try_acquire_at("flood-0", millis(t0, 3)),
        Acquire::Limited { .. }
    ));

    // Once the window has passed the sweep frees the table and the key fits.
    assert!(matches!(
        store.try_acquire_at("newcomer", secs(t0, 601)),
        Acquire::Allowed { .. }
    ));
    assert_eq!(store.bucket_count.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn the_layer_answers_429_for_a_new_key_when_the_table_is_full() {
    let clock = MockClock::at(t_zero());
    let config = RateLimitConfig::builder()
        .max_requests(5)
        .window(Duration::from_secs(600))
        .key(KeyExtractor::ClientIp)
        .clock(clock.clone())
        .build();
    let svc = RateLimitLayer::new(config).layer(OkService);
    fill_to_the_cap(&svc.store, t_zero());

    let new = ServiceExt::oneshot(svc.clone(), make_request_with_ip("10.9.9.9"))
        .await
        .unwrap();
    assert_eq!(new.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(new.headers().get("retry-after").unwrap(), "75");
    assert!(!svc.store.buckets.contains_key("10.9.9.9"));
}
