//! The back-off: its bounds, its growth, and that the jitter is the
//! injected random source's.

use std::time::Duration;

use super::*;
use crate::testing::MockRng;

#[test]
fn a_policy_is_raised_to_its_floors() {
    let policy = BackoffPolicy::new(Duration::ZERO, Duration::ZERO);
    assert_eq!(policy.initial(), BackoffPolicy::MIN_INITIAL);
    assert_eq!(policy.max(), BackoffPolicy::MIN_INITIAL);
}

#[test]
fn the_default_is_one_second_to_thirty() {
    let policy = BackoffPolicy::default();
    assert_eq!(policy.initial(), Duration::from_secs(1));
    assert_eq!(policy.max(), Duration::from_secs(30));
}

#[test]
fn each_wait_is_between_half_its_nominal_length_and_the_whole() {
    let policy = BackoffPolicy::new(Duration::from_secs(1), Duration::from_secs(30));
    let rng = MockRng::new(11);
    let mut backoff = Backoff::new(policy);
    let nominal = [1u64, 2, 4, 8, 16, 30, 30, 30];
    for (failure, nominal) in nominal.into_iter().enumerate() {
        let wait = backoff.next_wait(&rng);
        let nominal = Duration::from_secs(nominal);
        assert!(
            wait >= nominal / 2 && wait <= nominal,
            "failure {failure}: {wait:?} is outside {:?}..={nominal:?}",
            nominal / 2,
        );
        assert_eq!(backoff.steps() as usize, failure + 1);
    }
}

#[test]
fn a_reset_starts_the_waits_over() {
    let rng = MockRng::new(3);
    let mut backoff = Backoff::new(BackoffPolicy::default());
    for _ in 0..6 {
        backoff.next_wait(&rng);
    }
    backoff.reset();
    assert_eq!(backoff.steps(), 0);
    assert!(backoff.next_wait(&rng) <= Duration::from_secs(1));
}

#[test]
fn the_same_seed_gives_the_same_waits() {
    let waits = |seed| {
        let rng = MockRng::new(seed);
        let mut backoff = Backoff::new(BackoffPolicy::default());
        (0..8).map(|_| backoff.next_wait(&rng)).collect::<Vec<_>>()
    };
    assert_eq!(waits(42), waits(42));
    assert_ne!(waits(42), waits(43));
}

#[test]
fn a_failure_count_past_any_doubling_stays_at_the_cap() {
    let rng = MockRng::new(5);
    let mut backoff = Backoff::new(BackoffPolicy::new(
        Duration::from_secs(1),
        Duration::from_secs(30),
    ));
    for _ in 0..200 {
        let wait = backoff.next_wait(&rng);
        assert!(wait <= Duration::from_secs(30));
    }
    assert_eq!(backoff.steps(), 200);
}

#[test]
fn a_policy_with_a_wide_span_still_reaches_its_maximum() {
    // Ten milliseconds to half an hour is more than sixteen doublings.
    let max = Duration::from_secs(30 * 60);
    let rng = MockRng::new(9);
    let mut backoff = Backoff::new(BackoffPolicy::new(Duration::from_millis(10), max));
    let waits: Vec<Duration> = (0..40).map(|_| backoff.next_wait(&rng)).collect();
    assert!(waits.iter().all(|wait| *wait <= max));
    assert!(
        waits[30..].iter().all(|wait| *wait >= max / 2),
        "the late waits are drawn around the maximum: {:?}",
        &waits[30..]
    );
    // Sixteen doublings of 10 ms are some 655 s; the waits go on past that.
    assert!(waits[20] >= max / 2, "{:?}", waits[20]);
}

#[test]
fn a_run_counts_its_own_steps_only() {
    let rng = MockRng::new(1);
    let mut failures = Backoff::new(BackoffPolicy::default());
    let mut repeats = Backoff::new(BackoffPolicy::default());
    for _ in 0..5 {
        repeats.next_wait(&rng);
    }
    failures.next_wait(&rng);
    assert_eq!(failures.steps(), 1);
    assert_eq!(repeats.steps(), 5);
}
