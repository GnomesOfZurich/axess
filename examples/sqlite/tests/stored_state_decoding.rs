//! What the example reads back from its tables: a timed suspension ends when
//! its time does, a status it does not know is an error, and an auth method
//! whose steps cannot be read is an error, never a method with no steps.

use axess::SystemClock;
use axess::authn::{EntityState, FactorStore, IdentityLookup, TenantId, UserId};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
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
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
    )
    .await
    .expect("seed");
    pool
}

async fn set_user(pool: &sqlx::SqlitePool, status: &str, locked_until: Option<&str>) {
    sqlx::query("UPDATE users SET status = ?2, locked_until = ?3 WHERE id = ?1")
        .bind(ALICE)
        .bind(status)
        .bind(locked_until)
        .execute(pool)
        .await
        .expect("update user");
}

#[tokio::test]
async fn a_timed_suspension_that_has_ended_no_longer_suspends() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let alice = UserId::try_new(ALICE).expect("user");

    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    set_user(&pool, "suspended", Some(&past)).await;
    let state = backend.account_status(&alice).await.expect("status");
    assert!(
        matches!(state, EntityState::Active),
        "still suspended after its end: {state:?}"
    );

    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    set_user(&pool, "suspended", Some(&future)).await;
    let state = backend.account_status(&alice).await.expect("status");
    assert!(matches!(state, EntityState::Suspended(_)), "{state:?}");

    set_user(&pool, "suspended", None).await;
    let state = backend.account_status(&alice).await.expect("status");
    assert!(matches!(state, EntityState::Suspended(_)), "{state:?}");
}

#[tokio::test]
async fn an_unknown_status_is_an_error() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let alice = UserId::try_new(ALICE).expect("user");
    set_user(&pool, "actvie", None).await;
    let state = backend.account_status(&alice).await;
    assert!(state.is_err(), "read as {state:?}");
}

#[tokio::test]
async fn an_auth_method_with_unreadable_steps_is_an_error() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let alice = UserId::try_new(ALICE).expect("user");
    let tenant = TenantId::try_new(TENANT).expect("tenant");
    sqlx::query("UPDATE auth_methods SET steps_json = 'not json'")
        .execute(&pool)
        .await
        .expect("corrupt");
    let methods = backend.available_methods(&alice, &tenant).await;
    assert!(methods.is_err(), "read as {methods:?}");
}

/// The cause a suspension was written with is the cause it reads back with:
/// a lockout a store materialises stays a lockout, an operator's suspension
/// stays an operator's.
#[tokio::test]
async fn a_suspension_reads_back_with_the_cause_it_was_written_with() {
    use axess::authn::{IdentityAdmin, StatusCause, StatusDetail};
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let alice = UserId::try_new(ALICE).expect("user");
    let now = chrono::Utc::now();

    backend
        .suspend_user(
            &alice,
            StatusDetail::lockout("too many attempts", now)
                .with_until(Some(now + chrono::Duration::hours(1))),
        )
        .await
        .expect("suspend");
    match backend.account_status(&alice).await.expect("status") {
        EntityState::Suspended(detail) => {
            assert_eq!(detail.cause, StatusCause::Lockout);
            assert!(detail.until.is_some());
        }
        other => panic!("expected a suspension, got {other:?}"),
    }

    backend
        .suspend_user(&alice, StatusDetail::administrative("fraud review", now))
        .await
        .expect("suspend");
    match backend.account_status(&alice).await.expect("status") {
        EntityState::Suspended(detail) => {
            assert_eq!(detail.cause, StatusCause::Administrative);
            assert!(detail.until.is_none());
        }
        other => panic!("expected a suspension, got {other:?}"),
    }
}

/// A suspended row written before the cause column existed reads as a
/// suspension with an unspecified cause; a pending row is awaiting
/// verification and a terminated one is closed, by what the status says.
#[tokio::test]
async fn a_row_without_a_stored_cause_reads_by_its_status() {
    use axess::authn::StatusCause;
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let alice = UserId::try_new(ALICE).expect("user");

    set_user(&pool, "suspended", None).await;
    match backend.account_status(&alice).await.expect("status") {
        EntityState::Suspended(detail) => assert_eq!(detail.cause, StatusCause::unspecified()),
        other => panic!("expected a suspension, got {other:?}"),
    }

    set_user(&pool, "pending", None).await;
    match backend.account_status(&alice).await.expect("status") {
        EntityState::Pending(detail) => assert_eq!(detail.cause, StatusCause::Verification),
        other => panic!("expected pending, got {other:?}"),
    }

    set_user(&pool, "terminated", None).await;
    match backend.account_status(&alice).await.expect("status") {
        EntityState::Terminated(detail) => assert_eq!(detail.cause, StatusCause::Closure),
        other => panic!("expected terminated, got {other:?}"),
    }
}
