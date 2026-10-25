//! `IdentityAdmin::delete_user` against the real SQL path: after the call the
//! erased user answers none to every lookup and no table still holds a row
//! naming them, while the other seeded user is untouched and the audit log
//! keeps its rows with the user column cleared.

use axess::SystemClock;
use axess::authn::AuthnScope;
use axess::authn::{
    FactorKind, FactorStore, IdentityAdmin, IdentityLookup, IdentityPasswordHistory,
    IdentityPasswordReset, TenantId, UserId,
};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const ALICE: &str = "00000000-0000-0000-0000-000000000010";
const BOB: &str = "00000000-0000-0000-0000-000000000020";
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
    seed(&SystemClock, &pool).await.expect("seed");
    pool
}

/// Rows of `table` whose `column` holds `user`. The table and column names
/// are literals in this file, never input.
async fn rows_where(pool: &sqlx::SqlitePool, table: &str, column: &str, user: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1");
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[tokio::test]
async fn delete_user_erases_every_row_naming_the_user() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let alice = UserId::try_new(ALICE).expect("user id");
    let tenant = TenantId::try_new(TENANT).expect("tenant id");
    let scope = AuthnScope::User {
        tenant_id: tenant,
        user_id: alice,
    };

    backend
        .record_password_hash(&alice, "old-hash")
        .await
        .expect("history");
    backend
        .store_reset_token(&alice, "h", chrono::Utc::now() + chrono::Duration::hours(1))
        .await
        .expect("reset token");
    sqlx::query(
        "INSERT INTO refresh_tokens
             (id, user_id, tenant_id, token_hash, issued_at, expires_at)
         VALUES ('r1', ?1, ?2, 'rh', '2031-01-01T00:00:00Z', '2031-02-01T00:00:00Z')",
    )
    .bind(ALICE)
    .bind(TENANT)
    .execute(&pool)
    .await
    .expect("refresh token");
    sqlx::query(
        "INSERT INTO auth_events (user_id, tenant_id, event_type, event_status)
         VALUES (?1, ?2, 'login', 'success')",
    )
    .bind(ALICE)
    .bind(TENANT)
    .execute(&pool)
    .await
    .expect("audit row");
    for table in [
        "factor_configs",
        "auth_methods",
        "password_history",
        "password_reset_tokens",
        "refresh_tokens",
        "auth_events",
        "users",
    ] {
        let column = if table == "users" { "id" } else { "user_id" };
        let n = rows_where(&pool, table, column, ALICE).await;
        assert!(n > 0, "{table} holds a row for alice before the erasure");
    }

    backend.delete_user(&alice).await.expect("delete");

    assert!(backend.get_user(&alice).await.expect("get").is_none());
    assert!(
        backend
            .find_user("alice", &tenant)
            .await
            .expect("find")
            .is_none()
    );
    assert!(
        backend
            .load_factor(&scope, FactorKind::Password)
            .await
            .expect("load")
            .is_none()
    );
    assert!(
        backend
            .available_methods(&alice, &tenant)
            .await
            .expect("methods")
            .is_empty()
    );
    assert!(
        backend
            .password_history(&alice, 10)
            .await
            .expect("history")
            .is_empty()
    );
    assert!(
        !backend
            .verify_reset_token(&alice, "h", chrono::Utc::now())
            .await
            .expect("verify")
    );
    for table in [
        "factor_configs",
        "auth_methods",
        "password_history",
        "password_reset_tokens",
        "refresh_tokens",
        "auth_events",
    ] {
        assert_eq!(
            rows_where(&pool, table, "user_id", ALICE).await,
            0,
            "{table}"
        );
    }
    let kept: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auth_events WHERE user_id IS NULL AND event_type = 'login'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(kept, 1, "the audit row survives, unattributed");

    let bob = UserId::try_new(BOB).expect("user id");
    assert!(backend.get_user(&bob).await.expect("get").is_some());
    assert!(rows_where(&pool, "factor_configs", "user_id", BOB).await > 0);
    assert!(backend.delete_user(&alice).await.is_err(), "second erasure");
}
