//! The sliding-window counter.

use super::*;

fn millis(t: DateTime<Utc>, ms: i64) -> DateTime<Utc> {
    t + chrono::Duration::milliseconds(ms)
}

fn allowed(a: Acquire) -> bool {
    matches!(a, Acquire::Allowed { .. })
}

/// The boundary burst: one request at the start and four at the end of a
/// 60 s window used to be followed by five more in the first instant of the
/// next window. Now the second burst is refused until the first has aged out.
#[test]
fn a_burst_across_the_window_boundary_is_not_doubled() {
    let store = test_store(5, Duration::from_secs(60));
    let t0 = t_zero();
    assert!(allowed(store.try_acquire_at("k", t0)));
    for _ in 0..4 {
        assert!(allowed(store.try_acquire_at("k", millis(t0, 59_900))));
    }
    assert!(!allowed(store.try_acquire_at("k", millis(t0, 59_950))));
    let mut passed = 0;
    for _ in 0..9 {
        if allowed(store.try_acquire_at("k", secs(t0, 60))) {
            passed += 1;
        }
    }
    assert_eq!(passed, 0, "the 5 just used still weigh on the next window");
}

/// The weight of the previous window decays linearly: half way through the
/// next window about half of the old allowance is free again.
#[test]
fn the_previous_window_decays_linearly() {
    let store = test_store(10, Duration::from_secs(60));
    let t0 = t_zero();
    for _ in 0..10 {
        assert!(allowed(store.try_acquire_at("k", t0)));
    }
    let mut passed = 0;
    for _ in 0..10 {
        if allowed(store.try_acquire_at("k", secs(t0, 90))) {
            passed += 1;
        }
    }
    assert_eq!(passed, 5, "10 * 30/60 = 5 still counted at 90 s");
}

/// A full allowance is free again two windows after the burst.
#[test]
fn two_windows_later_the_whole_allowance_is_free() {
    let store = test_store(5, Duration::from_secs(60));
    let t0 = t_zero();
    for _ in 0..5 {
        store.try_acquire_at("k", t0);
    }
    for _ in 0..5 {
        assert!(allowed(store.try_acquire_at("k", secs(t0, 120))));
    }
}

/// `remaining` is derived from the estimate.
#[test]
fn remaining_counts_down_and_follows_the_estimate() {
    let store = test_store(3, Duration::from_secs(60));
    let t0 = t_zero();
    for want in [2, 1, 0] {
        match store.try_acquire_at("k", t0) {
            Acquire::Allowed { remaining } => assert_eq!(remaining, want),
            Acquire::Limited { .. } | Acquire::Saturated { .. } => panic!("refused"),
        }
    }
}

/// `retry_after` names a time at which the request really is admitted, and
/// not a second earlier, in both the full-window and the decaying case.
#[test]
fn the_retry_after_is_when_the_request_is_actually_admitted() {
    let t0 = t_zero();
    for (max, hits) in [(5u32, 5u32), (1, 1), (10, 10)] {
        let store = test_store(max, Duration::from_secs(60));
        for _ in 0..hits {
            store.try_acquire_at("k", t0);
        }
        let Acquire::Limited { retry_after_secs } = store.try_acquire_at("k", t0) else {
            panic!("max {max}: expected a refusal");
        };
        let early = millis(t0, i64::try_from(retry_after_secs).unwrap() * 1000 - 1000);
        assert!(
            !allowed(store.try_acquire_at("k", early)),
            "max {max}: admitted before the advertised {retry_after_secs}s"
        );
        let at = millis(t0, i64::try_from(retry_after_secs).unwrap() * 1000);
        assert!(
            allowed(store.try_acquire_at("k", at)),
            "max {max}: still refused at the advertised {retry_after_secs}s"
        );
    }
}

/// After a backwards clock step the bucket is not limited until the clock
/// catches up: its window re-anchors at the earlier time.
#[test]
fn a_clock_step_back_re_anchors_the_window() {
    let store = test_store(2, Duration::from_secs(60));
    let t0 = t_zero();
    let late = secs(t0, 3_600);
    store.try_acquire_at("k", late);
    store.try_acquire_at("k", late);
    let back = secs(t0, 3_000);
    assert!(!allowed(store.try_acquire_at("k", back)));
    assert!(
        allowed(store.try_acquire_at("k", secs(back, 120))),
        "two windows after the step the bucket is free, not held until 3600"
    );
}

/// A bucket survives one window after its own and is gone after two.
#[test]
fn a_bucket_is_evicted_only_after_two_windows() {
    let store = test_store(1, Duration::from_secs(10));
    let t0 = t_zero();
    store.try_acquire_at("k", t0);
    store.evict_expired_at(secs(t0, 15));
    assert!(
        store.buckets.contains_key("k"),
        "still weighs on the next window"
    );
    store.evict_expired_at(secs(t0, 20));
    assert!(!store.buckets.contains_key("k"));
}
