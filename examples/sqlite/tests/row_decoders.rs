//! The user and tenant row decoders against corrupted rows: a value the
//! schema's CHECK constraints did not catch is an integrity error the lookup
//! reports, never a panic and never a user read as unlocked.

use axess::SystemClock;
use axess::authn::{IdentityLookup, TenantId, UserId};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const ALICE: &str = "00000000-0000-0000-0000-000000000010";
const TENANT: &str = "00000000-0000-0000-0000-000000000001";

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
async fn a_user_row_with_a_bad_id_column_is_an_error_not_a_panic() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let alice = UserId::try_new(ALICE).expect("user id");
    assert!(
        backend.get_user(&alice).await.expect("lookup").is_some(),
        "the seeded row reads"
    );

    sqlx::query("UPDATE users SET created_by = 'not a user id' WHERE id = ?1")
        .bind(ALICE)
        .execute(&pool)
        .await
        .expect("corrupt the row");
    let err = backend
        .get_user(&alice)
        .await
        .expect_err("a malformed id column is an integrity error");
    assert!(err.to_string().contains("created_by"), "{err}");
}

#[tokio::test]
async fn an_unparseable_locked_until_never_reads_as_unlocked() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let alice = UserId::try_new(ALICE).expect("user id");
    assert_eq!(
        backend.account_status(&alice).await.expect("status"),
        axess::authn::EntityState::Active,
        "the seeded row is active"
    );

    sqlx::query("UPDATE users SET locked_until = 'garbage' WHERE id = ?1")
        .bind(ALICE)
        .execute(&pool)
        .await
        .expect("corrupt the row");
    let status = backend.account_status(&alice).await;
    assert!(
        !matches!(status, Ok(axess::authn::EntityState::Active)),
        "garbage in locked_until must not read as unlocked: {status:?}"
    );
    assert!(
        status.is_err(),
        "an unparseable locked_until is an error: {status:?}"
    );
    let full = backend.get_user(&alice).await;
    assert!(full.is_err(), "the full row read reports it too: {full:?}");
}

#[tokio::test]
async fn a_tenant_row_with_a_bad_id_column_is_an_error_not_a_panic() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let tenant = TenantId::try_new(TENANT).expect("tenant id");
    assert!(backend.get_tenant(&tenant).await.expect("lookup").is_some());

    sqlx::query("UPDATE tenants SET updated_by = 'x' WHERE id = ?1")
        .bind(TENANT)
        .execute(&pool)
        .await
        .expect("corrupt the row");
    let err = backend
        .get_tenant(&tenant)
        .await
        .expect_err("a malformed id column is an integrity error");
    assert!(err.to_string().contains("updated_by"), "{err}");
}
