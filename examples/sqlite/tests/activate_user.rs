//! Activating a suspended user lifts the suspension whatever kind it was:
//! a timed suspension's end time and the failed-attempt counters are cleared,
//! so the account is usable at once and the old failures do not lock it again.

use axess::authn::{EntityState, IdentityAdmin, IdentityLookup, StatusDetail, UserId};
use axess::{Clock, SystemClock};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const ALICE: &str = "00000000-0000-0000-0000-000000000010";

async fn pool() -> sqlx::SqlitePool {
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
    pool
}

#[tokio::test]
async fn activating_a_user_ends_a_timed_suspension_and_clears_the_counters() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let alice = UserId::try_new(ALICE).expect("user id");
    let now = SystemClock.now();

    backend
        .suspend_user(
            &alice,
            StatusDetail {
                reason: "review".into(),
                since: now,
                until: Some(now + chrono::Duration::hours(1)),
            },
        )
        .await
        .expect("suspend");
    sqlx::query("UPDATE users SET failed_attempts = 5, last_failed_at = ?2 WHERE id = ?1")
        .bind(ALICE)
        .bind(now.to_rfc3339())
        .execute(&pool)
        .await
        .expect("failures");
    assert!(matches!(
        backend.account_status(&alice).await.expect("status"),
        EntityState::Suspended(_)
    ));

    backend.activate_user(&alice).await.expect("activate");

    let state = backend.account_status(&alice).await.expect("status");
    assert!(
        matches!(state, EntityState::Active),
        "still not active: {state:?}"
    );
    let (count, last): (i64, Option<String>) =
        sqlx::query_as("SELECT failed_attempts, last_failed_at FROM users WHERE id = ?1")
            .bind(ALICE)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!((count, last), (0, None), "failure counters kept");
}
