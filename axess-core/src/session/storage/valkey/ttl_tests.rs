//! Pure decisions behind the Valkey TTL and registry-expiry handling.

use super::internal::{
    ex_seconds, expired_cycle_outcome, registry_cutoff_ms, registry_key_ttl_secs,
    registry_member_live, registry_member_ttl_ms,
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

#[test]
fn zero_ttl_rotation_reports_a_missing_session_as_gone_for_same_or_different_keys() {
    use crate::session::store::CycleOutcome;
    assert_eq!(expired_cycle_outcome(true, 0), CycleOutcome::SessionGone);
    assert_eq!(expired_cycle_outcome(true, 1), CycleOutcome::Rotated);
    assert_eq!(expired_cycle_outcome(false, 0), CycleOutcome::Rotated);
}
