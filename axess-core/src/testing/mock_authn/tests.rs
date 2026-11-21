//! The mock stores honour the uniqueness and single-use contracts of the
//! traits they stand in for, so a test that passes against them has
//! exercised the same refusals a real store gives.

use super::*;
use crate::authn::store::{IdentityAdmin, IdentityPasswordReset};
use crate::testing::{tenant_record_at, user_record_at};
use axess_clock::testing::Shift;
use std::sync::Arc;

#[tokio::test]
async fn create_tenant_refuses_a_duplicate_identifier() {
    let store = MockIdentityStore::new();
    store
        .create_tenant(tenant_record_at(
            "acme",
            axess_clock::testing::MockClock::reference_time(),
        ))
        .await
        .unwrap();
    let mut other = tenant_record_at("acme", axess_clock::testing::MockClock::reference_time());
    other.id = axess_identity::testing::tenant("a-different-id");
    assert!(matches!(
        store.create_tenant(other).await,
        Err(MockStoreError::AlreadyExists)
    ));
}

#[tokio::test]
async fn create_user_refuses_a_duplicate_id_under_a_new_identifier() {
    let store = MockIdentityStore::new();
    let user = user_record_at(
        "u1",
        "t1",
        axess_clock::testing::MockClock::reference_time(),
    );
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
                axess_clock::testing::MockClock::reference_time()
                    .plus(axess_clock::SignedDuration::hours(1)),
                axess_clock::testing::MockClock::reference_time(),
                3,
            )
            .await
            .unwrap();
        let attempts: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();
                let hash = hash.clone();
                tokio::spawn(async move {
                    store
                        .verify_reset_token(
                            &user,
                            &hash,
                            axess_clock::testing::MockClock::reference_time(),
                        )
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
            axess_clock::testing::MockClock::reference_time()
                .plus(axess_clock::SignedDuration::hours(1)),
            axess_clock::testing::MockClock::reference_time(),
            3,
        )
        .await
        .unwrap();
    assert!(
        !store
            .verify_reset_token(
                &user,
                "wrong",
                axess_clock::testing::MockClock::reference_time()
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .verify_reset_token(
                &user,
                "right",
                axess_clock::testing::MockClock::reference_time()
            )
            .await
            .unwrap()
    );
    assert!(
        !store
            .verify_reset_token(
                &user,
                "right",
                axess_clock::testing::MockClock::reference_time()
            )
            .await
            .unwrap()
    );
}

/// Expiry is judged on the `now` the caller passes, not on the machine's
/// clock: a token issued on a mock clock far from real time verifies up to its
/// expiry and is refused from that instant, one second later included.
#[tokio::test]
async fn a_reset_token_expires_on_the_instant_passed_in() {
    use axess_clock::Timestamp;
    let origin = Timestamp::from_utc(2031, 3, 1, 12, 0, 0).unwrap();
    let ttl = axess_clock::SignedDuration::minutes(30);
    let store = MockIdentityStore::new();
    let user = axess_identity::testing::user("u1");
    let issue =
        |hash: &'static str| store.store_reset_token(&user, hash, origin.plus(ttl), origin, 3);

    issue("h1").await.unwrap();
    let before = origin.plus(
        ttl.checked_sub(axess_clock::SignedDuration::minutes(1))
            .unwrap(),
    );
    assert!(store.verify_reset_token(&user, "h1", before).await.unwrap());

    issue("h2").await.unwrap();
    assert!(
        !store
            .verify_reset_token(&user, "h2", origin.plus(ttl))
            .await
            .unwrap(),
        "the token is refused at its expiry instant"
    );
    assert!(
        !store
            .verify_reset_token(
                &user,
                "h2",
                origin.plus(
                    ttl.checked_add(axess_clock::SignedDuration::seconds(1))
                        .unwrap()
                )
            )
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
    let user = user_record_at(
        "u1",
        "t1",
        axess_clock::testing::MockClock::reference_time(),
    );
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
        let clock =
            MockClock::at(axess_clock::Timestamp::from_unix_seconds(1_700_000_000).unwrap());
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
        clock.advance(axess_clock::SignedDuration::hours(2));
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
        clock.advance(axess_clock::SignedDuration::hours(2));
        assert_eq!(store.reserve_attempt(&user, &policy).await.unwrap(), None);
    }

    #[tokio::test]
    async fn an_ended_timed_lockout_starts_the_count_over() {
        let policy = policy(Some(Duration::from_secs(15 * 60)));
        let (store, clock, user) = locked_store(&policy).await;
        clock.advance(axess_clock::SignedDuration::hours(2));
        assert_eq!(
            store.reserve_attempt(&user, &policy).await.unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn a_count_below_the_limit_still_expires_with_the_window() {
        let policy = policy(None);
        let clock =
            MockClock::at(axess_clock::Timestamp::from_unix_seconds(1_700_000_000).unwrap());
        let store = MockIdentityStore::new().with_clock(clock.clone());
        let user = axess_identity::testing::user("two-strikes");
        store.reserve_attempt(&user, &policy).await.unwrap();
        assert_eq!(
            store.reserve_attempt(&user, &policy).await.unwrap(),
            Some(2)
        );
        clock.advance(axess_clock::SignedDuration::hours(2));
        assert_eq!(
            store.reserve_attempt(&user, &policy).await.unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn reset_clears_an_indefinite_lockout() {
        let policy = policy(None);
        let (store, clock, user) = locked_store(&policy).await;
        clock.advance(axess_clock::SignedDuration::hours(2));
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
    let user = user_record_at(
        "u1",
        "t1",
        axess_clock::testing::MockClock::reference_time(),
    );
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

mod throttle {
    //! The throttle entry is read and recorded under a key of tenant, user
    //! and address; the record is atomic, so parallel failures all count.

    use super::*;
    use crate::authn::store::IdentityAuthnLog;
    use crate::authn::types::{Throttle, ThrottleSubject};
    use axess_clock::Clock as _;
    use axess_clock::testing::MockClock;
    use std::net::{IpAddr, Ipv4Addr};

    fn subject(last: u8) -> ThrottleSubject {
        Throttle::default().subject(
            &axess_identity::testing::tenant("t"),
            &axess_identity::testing::user("u"),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))),
        )
    }

    fn store() -> (MockIdentityStore, MockClock) {
        let clock =
            MockClock::at(axess_clock::Timestamp::from_unix_seconds(1_700_000_000).unwrap());
        (MockIdentityStore::new().with_clock(clock.clone()), clock)
    }

    #[tokio::test]
    async fn parallel_failures_are_all_counted() {
        let (store, _) = store();
        let throttle = Throttle::default();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..12 {
            let store = store.clone();
            set.spawn(async move {
                store
                    .record_throttle_failure(&subject(1), &throttle)
                    .await
                    .unwrap()
            });
        }
        while let Some(done) = set.join_next().await {
            done.unwrap();
        }
        let state = store.throttle_state(&subject(1)).await.unwrap().unwrap();
        assert_eq!(state.failures, 12);
    }

    #[tokio::test]
    async fn a_right_guess_clears_the_key_and_another_key_is_untouched() {
        let (store, _) = store();
        let throttle = Throttle::default();
        store
            .record_throttle_failure(&subject(1), &throttle)
            .await
            .unwrap();
        store
            .record_throttle_failure(&subject(2), &throttle)
            .await
            .unwrap();
        store.clear_throttle(&subject(1)).await.unwrap();
        assert_eq!(store.throttle_state(&subject(1)).await.unwrap(), None);
        assert_eq!(
            store
                .throttle_state(&subject(2))
                .await
                .unwrap()
                .map(|s| s.failures),
            Some(1)
        );
    }

    #[tokio::test]
    async fn a_stale_key_starts_over_at_one_and_is_forgotten_by_the_next_record() {
        let (store, clock) = store();
        let throttle = Throttle::default();
        for _ in 0..3 {
            store
                .record_throttle_failure(&subject(1), &throttle)
                .await
                .unwrap();
        }
        store
            .record_throttle_failure(&subject(2), &throttle)
            .await
            .unwrap();
        clock.advance(axess_clock::SignedDuration::seconds(129));
        store
            .record_throttle_failure(&subject(1), &throttle)
            .await
            .unwrap();
        let state = store.throttle_state(&subject(1)).await.unwrap().unwrap();
        assert_eq!(
            (state.failures, state.last_failure_at),
            (1, clock.now()),
            "older than twice max_delay: as good as absent"
        );
        assert_eq!(
            store.throttle_state(&subject(2)).await.unwrap(),
            None,
            "a record sweeps every stale key, so the map does not grow without bound"
        );
    }
}

/// Two users claiming one credential id at the same time: exactly one claim
/// holds, whichever runs first, and a release lets the other have it.
#[cfg(feature = "fido2")]
#[tokio::test]
async fn racing_claims_of_one_credential_id_have_one_winner() {
    use crate::authn::store::FactorStore;
    let store = MockFactorStore::new();
    let tenant = axess_identity::testing::tenant("t1");
    let (a, b) = (
        axess_identity::testing::user("a"),
        axess_identity::testing::user("b"),
    );
    let (first, second) = tokio::join!(
        store.claim_fido2_credential(&tenant, &a, b"cred"),
        store.claim_fido2_credential(&tenant, &b, b"cred"),
    );
    let (first, second) = (first.unwrap(), second.unwrap());
    assert!(
        first.is_claimed() != second.is_claimed(),
        "both or neither claimed: {first:?} {second:?}"
    );
    let (winner, loser) = if first.is_claimed() { (a, b) } else { (b, a) };
    assert!(
        store
            .claim_fido2_credential(&tenant, &winner, b"cred")
            .await
            .unwrap()
            .is_claimed()
    );
    store
        .release_fido2_credential(&tenant, &loser, b"cred")
        .await
        .unwrap();
    assert!(
        !store
            .claim_fido2_credential(&tenant, &loser, b"cred")
            .await
            .unwrap()
            .is_claimed(),
        "a release by a user that does not hold the claim changed it"
    );
    store
        .release_fido2_credential(&tenant, &winner, b"cred")
        .await
        .unwrap();
    assert!(
        store
            .claim_fido2_credential(&tenant, &loser, b"cred")
            .await
            .unwrap()
            .is_claimed()
    );
    let other_tenant = axess_identity::testing::tenant("t2");
    assert!(
        store
            .claim_fido2_credential(&other_tenant, &winner, b"cred")
            .await
            .unwrap()
            .is_claimed(),
        "the id is held per tenant"
    );
}

/// The mock store keeps the rules of the claim, the refusal that names its
/// holder among them.
#[tokio::test]
async fn the_mock_factor_store_meets_the_claim_contract() {
    crate::testing::store_contract::assert_fido2_claim_contract(
        &MockFactorStore::new(),
        &axess_identity::testing::tenant("t1"),
        &axess_identity::testing::user("a"),
        &axess_identity::testing::user("b"),
    )
    .await;
}

/// A reset token is live until its expiry and not at it: one that ends at
/// this instant no longer counts toward the bound on live tokens.
#[tokio::test]
async fn a_reset_token_that_ends_at_this_instant_no_longer_counts_as_live() {
    let store = MockIdentityStore::new();
    let user = axess_identity::testing::user("alice");
    let now = axess_clock::testing::MockClock::reference_time();
    let ends = now.plus(axess_clock::SignedDuration::minutes(15));
    let later = ends.plus(axess_clock::SignedDuration::minutes(15));
    assert!(
        store
            .store_reset_token(&user, "hash-a", ends, now, 1)
            .await
            .unwrap()
    );
    assert!(
        !store
            .store_reset_token(
                &user,
                "hash-b",
                later,
                ends.minus(axess_clock::SignedDuration::seconds(1)),
                1
            )
            .await
            .unwrap(),
        "the bound holds while the first token is live"
    );
    assert!(
        store
            .store_reset_token(&user, "hash-b", later, ends, 1)
            .await
            .unwrap(),
        "the first token ended at this instant"
    );
}

/// A reset token checks by its own hash, and only while it is live.
#[tokio::test]
async fn a_reset_token_checks_only_by_its_own_hash_and_only_while_live() {
    let store = MockIdentityStore::new();
    let user = axess_identity::testing::user("alice");
    let now = axess_clock::testing::MockClock::reference_time();
    let ends = now.plus(axess_clock::SignedDuration::minutes(15));
    store
        .store_reset_token(&user, "hash-a", ends, now, 3)
        .await
        .unwrap();

    assert!(store.check_reset_token(&user, "hash-a", now).await.unwrap());
    assert!(
        !store.check_reset_token(&user, "hash-b", now).await.unwrap(),
        "another hash while a token is live"
    );
    assert!(
        !store
            .check_reset_token(&user, "hash-a", ends)
            .await
            .unwrap(),
        "its own hash at the instant it ends"
    );
}
