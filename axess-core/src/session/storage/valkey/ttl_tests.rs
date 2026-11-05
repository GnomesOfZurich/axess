//! Pure decisions behind the Valkey TTL and registry-expiry handling.

use super::internal::{
    DEGRADED_POLL, DEGRADED_POLL_MAX, Watch, after_check, after_degraded_poll, degraded_poll_delay,
    ex_seconds, registry_cutoff_ms, registry_key_ttl_secs, registry_member_live,
    registry_member_ttl_ms,
};
use std::time::Duration;

#[test]
fn sub_second_ttl_is_clamped_to_one_second_not_zero() {
    assert_eq!(ex_seconds(Duration::from_millis(1)), Some(1));
    assert_eq!(ex_seconds(Duration::from_millis(999)), Some(1));
    assert_eq!(ex_seconds(Duration::from_secs(1)), Some(1));
    assert_eq!(ex_seconds(Duration::from_millis(2500)), Some(2));
}

#[test]
fn zero_ttl_means_already_expired() {
    assert_eq!(ex_seconds(Duration::ZERO), None);
}

#[test]
fn huge_ttl_saturates() {
    assert_eq!(ex_seconds(Duration::MAX), Some(i64::MAX));
}

#[test]
fn registry_key_outlives_a_sub_second_member() {
    assert_eq!(registry_key_ttl_secs(Duration::from_millis(1)), 1);
    assert_eq!(registry_key_ttl_secs(Duration::ZERO), 1);
    assert_eq!(registry_key_ttl_secs(Duration::from_millis(1001)), 2);
    assert_eq!(registry_key_ttl_secs(Duration::from_secs(86_400)), 86_400);
}

#[test]
fn registry_key_ttl_covers_the_member_lifetime() {
    for ms in [1u64, 999, 1000, 1001, 59_999, 86_400_000] {
        let ttl = Duration::from_millis(ms);
        assert!(registry_key_ttl_secs(ttl) * 1000 >= registry_member_ttl_ms(ttl));
    }
}

#[test]
fn member_expires_exactly_at_score_plus_ttl() {
    let ttl_ms = 1000;
    assert!(registry_member_live(10_000.0, 10_999, ttl_ms));
    assert!(!registry_member_live(10_000.0, 11_000, ttl_ms));
    assert!(!registry_member_live(10_000.0, 50_000, ttl_ms));
}

#[test]
fn cutoff_agrees_with_liveness() {
    let (now, ttl_ms) = (50_000_i64, 1000_i64);
    let cutoff = registry_cutoff_ms(now, ttl_ms);
    for score in [48_999.0, 49_000.0, 49_001.0, 50_000.0] {
        assert_eq!(score > cutoff, registry_member_live(score, now, ttl_ms));
    }
}

/// The degraded poll doubles its interval for each consecutive poll the
/// registry failed to answer, up to the cap, and a draw spreads each wait
/// over the quarter interval on either side.
#[test]
fn degraded_poll_backs_off_per_failed_poll_to_a_cap_and_spreads_around_the_interval() {
    let ms = |n: u64| Duration::from_millis(n);
    assert_eq!(DEGRADED_POLL, Duration::from_secs(5));
    assert_eq!(DEGRADED_POLL_MAX, Duration::from_secs(60));
    assert_eq!(degraded_poll_delay(0, 0), ms(3_750));
    assert_eq!(degraded_poll_delay(0, 2_500), ms(6_250));
    assert_eq!(degraded_poll_delay(0, 2_501), ms(3_750), "the draw wraps");
    assert_eq!(degraded_poll_delay(1, 0), ms(7_500));
    assert_eq!(degraded_poll_delay(2, 0), ms(15_000));
    assert_eq!(degraded_poll_delay(4, 0), ms(45_000), "capped at a minute");
    assert_eq!(degraded_poll_delay(40, 0), ms(45_000));
    assert_eq!(degraded_poll_delay(40, 30_000), ms(75_000));
}

/// A revoked session ends the watch; an answer resets the failure count; a
/// registry that does not answer counts one more failed poll.
#[test]
fn a_degraded_poll_ends_on_revocation_and_counts_unanswered_polls() {
    let answered = |valid: bool| Ok::<bool, ()>(valid);
    assert_eq!(after_degraded_poll(answered(false), 3), Watch::Ended);
    assert_eq!(after_degraded_poll(answered(true), 3), Watch::Polling(0));
    assert_eq!(
        after_degraded_poll(Err::<bool, ()>(()), 3),
        Watch::Polling(4)
    );
    assert_eq!(
        after_degraded_poll(Err::<bool, ()>(()), u32::MAX),
        Watch::Polling(u32::MAX)
    );
}

/// A check the registry cannot answer must send the watcher into the polling
/// state; waiting for the next event would leave a revoked socket open
/// whenever the revocation message was the one that was lost.
#[test]
fn an_unanswered_check_moves_the_watcher_to_polling() {
    assert_eq!(after_check(Ok::<bool, ()>(false)), Watch::Ended);
    assert_eq!(after_check(Ok::<bool, ()>(true)), Watch::Waiting);
    assert_eq!(after_check(Err::<bool, ()>(())), Watch::Polling(0));
}
