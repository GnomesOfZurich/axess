#![cfg(feature = "testing")]
//! The mock identity store reads an attempt window too long for a date as a
//! window no failure is older than, as the SQLite example does: the count
//! keeps building, where a fallback of one hour would freshen it.

use axess_clock::testing::MockClock;
use axess_core::authn::store::IdentityAuthnLog;
use axess_core::authn::types::LockoutPolicy;
use axess_core::testing::mock_authn::MockIdentityStore;
use std::time::Duration;

#[tokio::test]
async fn a_window_too_long_for_a_date_never_freshens_the_count() {
    let clock = MockClock::at_reference();
    let store = MockIdentityStore::new().with_clock(clock.clone());
    let user = axess_core::authn::ids::testing::user("u1");
    let policy = LockoutPolicy {
        max_attempts: 5,
        attempt_window: Duration::MAX,
        ..LockoutPolicy::default()
    };
    assert_eq!(
        store.reserve_attempt(&user, &policy).await.unwrap(),
        Some(1)
    );
    clock.advance(axess_clock::SignedDuration::hours(2));
    assert_eq!(
        store.reserve_attempt(&user, &policy).await.unwrap(),
        Some(2),
        "a failure two hours old is inside a window too long for a date"
    );
}

#[tokio::test]
async fn a_failure_older_than_a_representable_window_starts_the_count_again() {
    let clock = MockClock::at_reference();
    let store = MockIdentityStore::new().with_clock(clock.clone());
    let user = axess_core::authn::ids::testing::user("u1");
    let policy = LockoutPolicy {
        max_attempts: 5,
        attempt_window: Duration::from_secs(60),
        ..LockoutPolicy::default()
    };
    assert_eq!(
        store.reserve_attempt(&user, &policy).await.unwrap(),
        Some(1)
    );
    clock.advance(axess_clock::SignedDuration::minutes(2));
    assert_eq!(
        store.reserve_attempt(&user, &policy).await.unwrap(),
        Some(1)
    );
}
