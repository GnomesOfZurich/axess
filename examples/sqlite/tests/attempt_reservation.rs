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
    seed(&SystemClock, &pool).await.expect("seed");
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
