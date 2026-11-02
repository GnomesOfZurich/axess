//! The mock stores honour the uniqueness and single-use contracts of the
//! traits they stand in for, so a test that passes against them has
//! exercised the same refusals a real store gives.

use super::*;
use crate::authn::store::{IdentityAdmin, IdentityPasswordReset};
use crate::testing::{tenant_record, user_record};
use std::sync::Arc;

#[tokio::test]
async fn create_tenant_refuses_a_duplicate_identifier() {
    let store = MockIdentityStore::new();
    store.create_tenant(tenant_record("acme")).await.unwrap();
    let mut other = tenant_record("acme");
    other.id = axess_identity::testing::tenant("a-different-id");
    assert!(matches!(
        store.create_tenant(other).await,
        Err(MockStoreError::AlreadyExists)
    ));
}

#[tokio::test]
async fn create_user_refuses_a_duplicate_id_under_a_new_identifier() {
    let store = MockIdentityStore::new();
    let user = user_record("u1", "t1");
    store.create_user(user.clone()).await.unwrap();
    let mut clash = user;
    clash.identifier = "someone-else".into();
    assert!(matches!(
        store.create_user(clash).await,
        Err(MockStoreError::AlreadyExists)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_token_verifies_once_under_concurrent_attempts() {
    let store = Arc::new(MockIdentityStore::new());
    let user = axess_identity::testing::user("u1");
    for round in 0..200 {
        let hash = format!("hash-{round}");
        store
            .store_reset_token(
                &user,
                &hash,
                chrono::Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .unwrap();
        let attempts: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();
                let hash = hash.clone();
                tokio::spawn(async move {
                    store
                        .verify_reset_token(&user, &hash, chrono::Utc::now())
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut winners = 0;
        for attempt in attempts {
            winners += usize::from(attempt.await.unwrap());
        }
        assert_eq!(
            winners, 1,
            "round {round}: a single-use token verified {winners} times"
        );
    }
}

#[tokio::test]
async fn a_wrong_hash_does_not_consume_the_reset_token() {
    let store = MockIdentityStore::new();
    let user = axess_identity::testing::user("u1");
    store
        .store_reset_token(
            &user,
            "right",
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    assert!(
        !store
            .verify_reset_token(&user, "wrong", chrono::Utc::now())
            .await
            .unwrap()
    );
    assert!(
        store
            .verify_reset_token(&user, "right", chrono::Utc::now())
            .await
            .unwrap()
    );
    assert!(
        !store
            .verify_reset_token(&user, "right", chrono::Utc::now())
            .await
            .unwrap()
    );
}

/// Expiry is judged on the `now` the caller passes, not on the machine's
/// clock: a token issued on a mock clock far from real time verifies up to its
/// expiry and is refused from that instant, one second later included.
#[tokio::test]
async fn a_reset_token_expires_on_the_instant_passed_in() {
    use chrono::TimeZone;
    let origin = chrono::Utc.with_ymd_and_hms(2031, 3, 1, 12, 0, 0).unwrap();
    let ttl = chrono::Duration::minutes(30);
    let store = MockIdentityStore::new();
    let user = axess_identity::testing::user("u1");
    let issue = |hash: &'static str| store.store_reset_token(&user, hash, origin + ttl);

    issue("h1").await.unwrap();
    let before = origin + ttl - chrono::Duration::minutes(1);
    assert!(store.verify_reset_token(&user, "h1", before).await.unwrap());

    issue("h2").await.unwrap();
    assert!(
        !store
            .verify_reset_token(&user, "h2", origin + ttl)
            .await
            .unwrap(),
        "the token is refused at its expiry instant"
    );
    assert!(
        !store
            .verify_reset_token(&user, "h2", origin + ttl + chrono::Duration::seconds(1))
            .await
            .unwrap(),
        "and stays refused after it"
    );
}

/// The tenant lookup the session validator makes on every request answers
/// from the user's tenant alone and names itself in the call log.
#[tokio::test]
async fn get_user_tenant_answers_with_the_tenant_only() {
    use crate::authn::store::IdentityLookup;
    let log = CallLog::new();
    let user = user_record("u1", "t1");
    let store = MockIdentityStore::new()
        .with_call_log(&log)
        .with_user(user.clone());
    assert_eq!(
        store.get_user_tenant(&user.id).await.unwrap(),
        Some(user.tenant_id)
    );
    let stranger = axess_identity::testing::user("nobody");
    assert_eq!(store.get_user_tenant(&stranger).await.unwrap(), None);
    assert_eq!(log.calls(), vec!["get_user_tenant", "get_user_tenant"]);
}

mod lockout_outlives_the_window {
    //! The attempt window bounds how long failures accumulate; it must not
    //! end a lockout. A count at the limit stays until a timed lockout has
    //! run out or the counter is reset, however old the last failure is.

    use super::*;
    use crate::authn::ids::UserId;
    use crate::authn::store::IdentityAuthnLog;
    use crate::authn::types::LockoutPolicy;
    use axess_clock::Clock as _;
    use axess_clock::testing::MockClock;
    use std::time::Duration;

    fn policy(duration: Option<Duration>) -> LockoutPolicy {
        LockoutPolicy {
            max_attempts: 3,
            duration,
            attempt_window: Duration::from_secs(60 * 60),
            ..LockoutPolicy::default()
        }
    }

    async fn locked_store(policy: &LockoutPolicy) -> (MockIdentityStore, MockClock, UserId) {
        let clock = MockClock::at(chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap());
        let store = MockIdentityStore::new().with_clock(clock.clone());
        let user = axess_identity::testing::user("locked");
        for expected in 1..=3 {
            assert_eq!(
                store.reserve_attempt(&user, policy).await.unwrap(),
                Some(expected)
            );
        }
        assert_eq!(
            store.reserve_attempt(&user, policy).await.unwrap(),
            None,
            "the case this module refuses: the account is at its limit"
        );
        (store, clock, user)
    }

    #[tokio::test]
    async fn an_indefinite_lockout_is_not_ended_by_the_window() {
        let policy = policy(None);
        let (store, clock, user) = locked_store(&policy).await;
        clock.advance(chrono::Duration::hours(2));
        assert_eq!(
            store.reserve_attempt(&user, &policy).await.unwrap(),
            None,
            "duration None locks until an administrator resets the counter"
        );
        let (count, last) = store.failed_attempts(&user).await.unwrap();
        assert_eq!(count, 3, "the raw count is reported at or above the limit");
        assert!(policy.derived_lockout(count, last, clock.now()).is_some());
    }

    #[tokio::test]
    async fn a_lockout_longer_than_the_window_outlives_it() {
        let policy = policy(Some(Duration::from_secs(3 * 60 * 60)));
        let (store, clock, user) = locked_store(&policy).await;
        clock.advance(chrono::Duration::hours(2));
        assert_eq!(store.reserve_attempt(&user, &policy).await.unwrap(), None);
    }

    #[tokio::test]
    async fn an_ended_timed_lockout_starts_the_count_over() {
        let policy = policy(Some(Duration::from_secs(15 * 60)));
        let (store, clock, user) = locked_store(&policy).await;
        clock.advance(chrono::Duration::hours(2));
        assert_eq!(
            store.reserve_attempt(&user, &policy).await.unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn a_count_below_the_limit_still_expires_with_the_window() {
        let policy = policy(None);
        let clock = MockClock::at(chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap());
        let store = MockIdentityStore::new().with_clock(clock.clone());
        let user = axess_identity::testing::user("two-strikes");
        store.reserve_attempt(&user, &policy).await.unwrap();
        assert_eq!(
            store.reserve_attempt(&user, &policy).await.unwrap(),
            Some(2)
        );
        clock.advance(chrono::Duration::hours(2));
        assert_eq!(
            store.reserve_attempt(&user, &policy).await.unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn reset_clears_an_indefinite_lockout() {
        let policy = policy(None);
        let (store, clock, user) = locked_store(&policy).await;
        clock.advance(chrono::Duration::hours(2));
        store.reset_failed_attempts(&user).await.unwrap();
        assert_eq!(
            store.reserve_attempt(&user, &policy).await.unwrap(),
            Some(1)
        );
    }
}

/// The user-table outage answers `Unavailable`, not `NotFound`, while
/// armed, and the store answers again once disarmed.
#[tokio::test]
async fn the_get_user_outage_is_unavailable_and_can_be_disarmed() {
    use crate::authn::store::IdentityLookup as _;
    let user = user_record("u1", "t1");
    let store = MockIdentityStore::new().with_user(user.clone());
    assert!(store.get_user(&user.id).await.unwrap().is_some(), "seeded");
    store.arm_get_user_failure();
    assert!(matches!(
        store.get_user(&user.id).await,
        Err(MockStoreError::Unavailable)
    ));
    store.disarm_get_user_failure();
    assert!(store.get_user(&user.id).await.unwrap().is_some());
}
