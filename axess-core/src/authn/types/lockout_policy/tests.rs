//! A lockout policy's bounds hold for every extreme duration an operator
//! can type, and the lockout end never panics.

use super::LockoutPolicyError;
use crate::authn::types::LockoutPolicy;
use axess_clock::{Timestamp, Until};
use axess_testing::durations::extreme_durations;
use std::time::Duration;

/// A fixed instant, so the test reads no clock.
fn now() -> Timestamp {
    Timestamp::from_unix_seconds(1_700_000_000).expect("a valid instant")
}

fn policy_with(duration: Option<Duration>) -> LockoutPolicy {
    LockoutPolicy {
        duration,
        ..LockoutPolicy::default()
    }
}

#[test]
fn the_lockout_end_never_panics_and_never_precedes_now() {
    let now = now();
    for extreme in extreme_durations() {
        let until = policy_with(Some(extreme.value)).lockout_until(now);
        let Some(until) = until else {
            panic!("{}: a policy with a duration has an end", extreme.name);
        };
        assert!(
            until >= Until::At(now),
            "{}: ends at {until:?}",
            extreme.name
        );
        if extreme.value > LockoutPolicy::MAX_DURATION {
            assert_eq!(until, Until::Forever, "{}", extreme.name);
        }
    }
    assert_eq!(policy_with(None).lockout_until(now), None);
}

/// A lockout too long to hold never ends, whether it is counted from now or
/// from the last failure: `derived_lockout` gives the `Until::Forever` that
/// `lockout_until` gives, and a duration that fits ends at the same reading
/// by either road.
#[test]
fn a_derived_lockout_too_long_to_hold_never_ends_as_lockout_until_says() {
    let now = now();
    let locked = LockoutPolicy::default().effective_max_attempts();
    // The longest span there is, and about 285,000 years: past the range of
    // a reading from any start of today.
    for duration in [Duration::MAX, Duration::from_secs(9_000_000_000_000)] {
        let policy = policy_with(Some(duration));
        assert_eq!(policy.lockout_until(now), Some(Until::Forever));
        let derived = policy
            .derived_lockout(locked, Some(now), now)
            .expect("a lockout");
        assert_eq!(derived.until, Some(Until::Forever), "{duration:?}");
        let later = Timestamp::MAX;
        assert_eq!(
            policy
                .derived_lockout(locked, Some(now), later)
                .map(|lock| lock.until),
            Some(Some(Until::Forever)),
            "a lockout that never ends holds at the latest reading"
        );
    }
    let fits = policy_with(Some(Duration::from_secs(900)));
    assert_eq!(
        fits.derived_lockout(locked, Some(now), now)
            .map(|lock| lock.until),
        Some(fits.lockout_until(now))
    );
}

#[test]
fn a_duration_at_the_bound_passes_and_one_past_it_is_refused_by_name() {
    let max = LockoutPolicy::MAX_DURATION;
    assert_eq!(policy_with(Some(max)).validate(), Ok(()));
    assert_eq!(policy_with(None).validate(), Ok(()));
    assert_eq!(LockoutPolicy::default().validate(), Ok(()));
    let past = max + Duration::from_nanos(1);
    assert_eq!(
        policy_with(Some(past)).validate(),
        Err(LockoutPolicyError::DurationAboveMax {
            duration: past,
            max
        })
    );
    for extreme in extreme_durations() {
        let verdict = policy_with(Some(extreme.value)).validate();
        assert_eq!(
            verdict.is_ok(),
            extreme.value <= max,
            "{}: {verdict:?}",
            extreme.name
        );
    }
}

#[test]
fn bounded_clamps_a_duration_past_the_bound_and_keeps_the_rest() {
    let max = LockoutPolicy::MAX_DURATION;
    for extreme in extreme_durations() {
        let policy = LockoutPolicy {
            max_attempts: 7,
            duration: Some(extreme.value),
            ..LockoutPolicy::default()
        };
        let bounded = policy.bounded();
        assert_eq!(bounded.validate(), Ok(()), "{}", extreme.name);
        assert_eq!(
            bounded.duration,
            Some(extreme.value.min(max)),
            "{}",
            extreme.name
        );
        assert_eq!(bounded.max_attempts, 7);
        assert_eq!(bounded.attempt_window, policy.attempt_window);
    }
    let indefinite = policy_with(None).bounded();
    assert_eq!(indefinite.duration, None);
}

#[test]
fn a_count_or_window_that_disables_the_lock_is_refused_and_bounded() {
    let max = LockoutPolicy::MAX_ATTEMPTS;
    let too_many = LockoutPolicy {
        max_attempts: max + 1,
        ..LockoutPolicy::default()
    };
    assert_eq!(
        too_many.validate(),
        Err(LockoutPolicyError::MaxAttemptsAboveMax {
            max_attempts: max + 1,
            max
        })
    );
    assert_eq!(too_many.bounded().max_attempts, max);
    assert_eq!(
        LockoutPolicy {
            max_attempts: max,
            ..LockoutPolicy::default()
        }
        .validate(),
        Ok(())
    );
    assert_eq!(
        LockoutPolicy {
            max_attempts: u32::MAX,
            ..LockoutPolicy::default()
        }
        .bounded()
        .max_attempts,
        max
    );

    let no_window = LockoutPolicy {
        attempt_window: Duration::ZERO,
        ..LockoutPolicy::default()
    };
    assert_eq!(
        no_window.validate(),
        Err(LockoutPolicyError::AttemptWindowZero)
    );
    assert_eq!(
        no_window.bounded().attempt_window,
        LockoutPolicy::default().attempt_window,
        "a zero window is read as the default window"
    );

    for extreme in extreme_durations() {
        let policy = LockoutPolicy {
            attempt_window: extreme.value,
            ..LockoutPolicy::default()
        };
        let bounded = policy.bounded();
        assert_eq!(bounded.validate(), Ok(()), "{}", extreme.name);
        assert!(
            !bounded.attempt_window.is_zero()
                && bounded.attempt_window <= LockoutPolicy::MAX_DURATION,
            "{}: {:?}",
            extreme.name,
            bounded.attempt_window
        );
        assert_eq!(
            policy.validate().is_ok(),
            !extreme.value.is_zero() && extreme.value <= LockoutPolicy::MAX_DURATION,
            "{}",
            extreme.name
        );
    }
}

#[test]
fn the_longest_lockout_and_window_are_one_hundred_years_of_365_days() {
    let hundred_years = Duration::from_secs(100 * 365 * 86_400);
    let one_second_more = hundred_years + Duration::from_secs(1);
    assert_eq!(policy_with(Some(hundred_years)).validate(), Ok(()));
    assert_eq!(
        policy_with(Some(one_second_more)).validate(),
        Err(LockoutPolicyError::DurationAboveMax {
            duration: one_second_more,
            max: hundred_years
        })
    );
    let window = |attempt_window| LockoutPolicy {
        attempt_window,
        ..LockoutPolicy::default()
    };
    assert_eq!(window(hundred_years).validate(), Ok(()));
    assert_eq!(
        window(one_second_more).validate(),
        Err(LockoutPolicyError::AttemptWindowAboveMax {
            window: one_second_more,
            max: hundred_years
        })
    );
    assert_eq!(
        policy_with(Some(one_second_more)).bounded().duration,
        Some(hundred_years)
    );
    assert_eq!(
        window(one_second_more).bounded().attempt_window,
        hundred_years
    );
}

/// The clamp's edge to the nanosecond, for the duration and the window. At
/// the bound itself the value kept and the value clamped are the same
/// duration, so `bounded` answers the bound there by either road.
#[test]
fn bounded_keeps_a_duration_up_to_the_bound_and_clamps_the_first_one_past_it() {
    let max = LockoutPolicy::MAX_DURATION;
    let nanosecond = Duration::from_nanos(1);
    for (asked, served) in [
        (max - nanosecond, max - nanosecond),
        (max, max),
        (max + nanosecond, max),
    ] {
        assert_eq!(
            policy_with(Some(asked)).bounded().duration,
            Some(served),
            "a lockout of {asked:?}"
        );
        let window = LockoutPolicy {
            attempt_window: asked,
            ..LockoutPolicy::default()
        };
        assert_eq!(
            window.bounded().attempt_window,
            served,
            "a window of {asked:?}"
        );
    }
}
