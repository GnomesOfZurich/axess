//! The attempt counter reserves a guess before the credential is checked: the
//! test and the increment are one statement, so concurrent guesses cannot
//! pass the limit, and a verified guess gives its reservation back.

use axess::SystemClock;
use axess::authn::{IdentityAuthnLog, LockoutPolicy, UserId};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

fn limit(max_attempts: u32) -> LockoutPolicy {
    LockoutPolicy {
        max_attempts,
        ..LockoutPolicy::default()
    }
}

async fn backend() -> (OurBackend, UserId) {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("in-memory url")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("connect in-memory sqlite");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    seed(
        &SystemClock,
        &pool,
        &axess::authn::FactorSecretCipher::new([7; 32]),
    )
    .await
    .expect("seed");
    let id: String = sqlx::query_scalar("SELECT id FROM users LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("a seeded user");
    (
        OurBackend::new(pool),
        UserId::try_new(&id).expect("a user id"),
    )
}

#[tokio::test]
async fn a_reservation_is_refused_once_the_count_reaches_the_limit() {
    let (backend, user) = backend().await;
    for expected in 1..=3 {
        assert_eq!(
            backend.reserve_attempt(&user, &limit(3)).await.unwrap(),
            Some(expected)
        );
    }
    assert_eq!(
        backend.reserve_attempt(&user, &limit(3)).await.unwrap(),
        None
    );
    assert_eq!(
        backend.failed_attempts(&user).await.unwrap().0,
        3,
        "a refusal changes nothing"
    );
}

#[tokio::test]
async fn parallel_reservations_cannot_pass_the_limit() {
    let (backend, user) = backend().await;
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let backend = backend.clone();
        set.spawn(async move { backend.reserve_attempt(&user, &limit(3)).await.unwrap() });
    }
    let mut granted = 0;
    while let Some(done) = set.join_next().await {
        if done.unwrap().is_some() {
            granted += 1;
        }
    }
    assert_eq!(granted, 3);
    assert_eq!(backend.failed_attempts(&user).await.unwrap().0, 3);
}

#[tokio::test]
async fn releasing_gives_one_back_and_clears_the_time_at_zero() {
    let (backend, user) = backend().await;
    backend.reserve_attempt(&user, &limit(5)).await.unwrap();
    backend.reserve_attempt(&user, &limit(5)).await.unwrap();
    backend.release_attempt(&user).await.unwrap();
    let (count, last) = backend.failed_attempts(&user).await.unwrap();
    assert_eq!((count, last.is_some()), (1, true));
    backend.release_attempt(&user).await.unwrap();
    assert_eq!(backend.failed_attempts(&user).await.unwrap(), (0, None));
    backend.release_attempt(&user).await.unwrap();
    assert_eq!(
        backend.failed_attempts(&user).await.unwrap().0,
        0,
        "never below zero"
    );
}

#[tokio::test]
async fn an_ended_lockout_starts_the_count_over() {
    let (backend, user) = backend().await;
    let policy = LockoutPolicy {
        max_attempts: 2,
        duration: Some(std::time::Duration::from_secs(0)),
        ..LockoutPolicy::default()
    };
    assert_eq!(
        backend.reserve_attempt(&user, &policy).await.unwrap(),
        Some(1)
    );
    assert_eq!(
        backend.reserve_attempt(&user, &policy).await.unwrap(),
        Some(2)
    );
    // At the limit, but the zero-length lockout is already over.
    assert_eq!(
        backend.reserve_attempt(&user, &policy).await.unwrap(),
        Some(1)
    );
}

mod lockout_outlives_the_window {
    //! The attempt window bounds how long failures accumulate; it must not
    //! end a lockout. A count at the limit stays until a timed lockout has
    //! run out or the counter is reset, however old the last failure is.

    use super::*;
    use axess::Clock;
    use chrono::{DateTime, Utc};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A clock the test moves by hand, so a two-hour gap is two hours.
    #[derive(Clone)]
    struct MockClock(Arc<Mutex<DateTime<Utc>>>);

    impl MockClock {
        fn at(time: DateTime<Utc>) -> Self {
            Self(Arc::new(Mutex::new(time)))
        }

        fn advance(&self, by: chrono::Duration) {
            *self.0.lock().unwrap() += by;
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    fn policy(duration: Option<Duration>) -> LockoutPolicy {
        LockoutPolicy {
            max_attempts: 3,
            duration,
            attempt_window: Duration::from_secs(60 * 60),
            ..LockoutPolicy::default()
        }
    }

    async fn locked_backend(policy: &LockoutPolicy) -> (OurBackend, MockClock, UserId) {
        let (backend, user) = backend().await;
        let clock = MockClock::at(chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap());
        let backend = backend.with_clock(Arc::new(clock.clone()));
        let max = policy.effective_max_attempts();
        for expected in 1..=max {
            assert_eq!(
                backend.reserve_attempt(&user, policy).await.unwrap(),
                Some(expected)
            );
        }
        assert_eq!(
            backend.reserve_attempt(&user, policy).await.unwrap(),
            None,
            "the case this module refuses: the account is at its limit"
        );
        (backend, clock, user)
    }

    #[tokio::test]
    async fn an_indefinite_lockout_is_not_ended_by_the_window() {
        let policy = policy(None);
        let (backend, clock, user) = locked_backend(&policy).await;
        clock.advance(chrono::Duration::hours(2));
        assert_eq!(
            backend.reserve_attempt(&user, &policy).await.unwrap(),
            None,
            "duration None locks until an administrator resets the counter"
        );
    }

    #[tokio::test]
    async fn the_raw_count_is_reported_at_the_limit_after_the_window() {
        // The read uses the store's own policy (five attempts, one hour),
        // so the count is driven to that limit.
        let (backend, user) = backend().await;
        let own = backend.lockout_policy();
        let (backend, clock, user) = {
            let clock = MockClock::at(chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap());
            let backend = backend.with_clock(Arc::new(clock.clone()));
            for _ in 0..own.effective_max_attempts() {
                backend.reserve_attempt(&user, &own).await.unwrap().unwrap();
            }
            (backend, clock, user)
        };
        clock.advance(chrono::Duration::hours(2));
        let (count, last) = backend.failed_attempts(&user).await.unwrap();
        assert_eq!(
            (count, last.is_some()),
            (own.effective_max_attempts(), true),
            "at the limit the library derives the lockout from the raw count and time; \
             a zero here would end a lockout longer than the window"
        );
    }

    #[tokio::test]
    async fn a_lockout_longer_than_the_window_outlives_it() {
        let policy = policy(Some(Duration::from_secs(3 * 60 * 60)));
        let (backend, clock, user) = locked_backend(&policy).await;
        clock.advance(chrono::Duration::hours(2));
        assert_eq!(backend.reserve_attempt(&user, &policy).await.unwrap(), None);
    }

    #[tokio::test]
    async fn an_ended_timed_lockout_starts_the_count_over() {
        let policy = policy(Some(Duration::from_secs(15 * 60)));
        let (backend, clock, user) = locked_backend(&policy).await;
        clock.advance(chrono::Duration::hours(2));
        assert_eq!(
            backend.reserve_attempt(&user, &policy).await.unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn a_count_below_the_limit_still_expires_with_the_window() {
        let policy = policy(None);
        let (backend, user) = backend().await;
        let clock = MockClock::at(chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap());
        let backend = backend.with_clock(Arc::new(clock.clone()));
        backend.reserve_attempt(&user, &policy).await.unwrap();
        assert_eq!(
            backend.reserve_attempt(&user, &policy).await.unwrap(),
            Some(2)
        );
        clock.advance(chrono::Duration::hours(2));
        assert_eq!(
            backend.reserve_attempt(&user, &policy).await.unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn reset_clears_an_indefinite_lockout() {
        let policy = policy(None);
        let (backend, clock, user) = locked_backend(&policy).await;
        clock.advance(chrono::Duration::hours(2));
        backend.reset_failed_attempts(&user).await.unwrap();
        assert_eq!(
            backend.reserve_attempt(&user, &policy).await.unwrap(),
            Some(1)
        );
    }
}
