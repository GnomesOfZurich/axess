//! Tenant- and system-scope rows store `user_id` NULL, which a plain
//! `UNIQUE(user_id, tenant_id, ...)` never matches. These tests pin that a
//! second save at the same scope replaces the row, a second insert-if-absent
//! reports it was absent no longer, and the migration that adds the partial
//! indexes also removes duplicates an older database already holds.

use axess::SystemClock;
use axess::authn::{
    AuthMethod, AuthnScope, FactorConfig, FactorKind, FactorStep, FactorStore, TenantId,
    TotpConfig, ZeroizedString,
};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

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

fn totp(secret: &str) -> FactorConfig {
    FactorConfig::Totp(TotpConfig {
        secret: ZeroizedString::new(secret).into(),
        ..TotpConfig::default()
    })
}

async fn count(pool: &sqlx::SqlitePool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[tokio::test]
async fn a_tenant_scope_factor_is_saved_once_and_replaced() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let scope = AuthnScope::Tenant(TenantId::try_new(TENANT).expect("tenant"));
    let rows = "SELECT COUNT(*) FROM factor_configs WHERE user_id IS NULL AND kind = 'totp' AND tenant_id = '00000000-0000-0000-0000-000000000001'";

    backend
        .save_factor(&scope, totp("AAAA"))
        .await
        .expect("first");
    backend
        .save_factor(&scope, totp("BBBB"))
        .await
        .expect("second");
    assert_eq!(count(&pool, rows).await, 1, "one row per tenant and kind");
    let stored: String = sqlx::query_scalar(
        "SELECT config_json FROM factor_configs WHERE user_id IS NULL AND kind = 'totp' AND tenant_id = ?1",
    )
    .bind(TENANT)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert!(stored.contains("BBBB"), "the second save wins: {stored}");

    // The row exists, so a conditional insert reports it was not inserted.
    let inserted = backend
        .insert_factor_if_absent(&scope, totp("CCCC"))
        .await
        .expect("insert if absent");
    assert!(!inserted);
    assert_eq!(count(&pool, rows).await, 1);
}

#[tokio::test]
async fn a_tenant_scope_method_is_saved_once_per_name() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let scope = AuthnScope::Tenant(TenantId::try_new(TENANT).expect("tenant"));
    let method = |kinds: Vec<FactorKind>| AuthMethod {
        name: "tenant-default".into(),
        steps: kinds.into_iter().map(FactorStep::Required).collect(),
        scope: scope.clone(),
    };

    backend
        .save_method(&scope, method(vec![FactorKind::Password]))
        .await
        .expect("first");
    backend
        .save_method(&scope, method(vec![FactorKind::Password, FactorKind::Totp]))
        .await
        .expect("second");
    let sql = "SELECT COUNT(*) FROM auth_methods WHERE user_id IS NULL AND name = 'tenant-default'";
    assert_eq!(count(&pool, sql).await, 1);
    let steps: String = sqlx::query_scalar(
        "SELECT steps_json FROM auth_methods WHERE user_id IS NULL AND name = 'tenant-default'",
    )
    .fetch_one(&pool)
    .await
    .expect("row");
    assert!(steps.contains("Totp"), "the second save wins: {steps}");
}

#[tokio::test]
async fn the_migration_removes_duplicates_an_older_database_holds() {
    let pool = pool().await;
    // Recreate the old state: no partial indexes, then two rows at one scope.
    sqlx::query("DROP INDEX factor_configs_tenant_scope_unique")
        .execute(&pool)
        .await
        .expect("drop");
    sqlx::query("DROP INDEX auth_methods_tenant_scope_unique")
        .execute(&pool)
        .await
        .expect("drop");
    for (id, secret) in [("d1", "OLD"), ("d2", "NEW")] {
        sqlx::query(
            "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json)
             VALUES (?1, NULL, ?2, 'hotp', ?3)",
        )
        .bind(id)
        .bind(TENANT)
        .bind(secret)
        .execute(&pool)
        .await
        .expect("duplicate");
    }

    let migration = include_str!("../migrations/20261028000100_unique_tenant_scope_rows.sql");
    sqlx::raw_sql(migration)
        .execute(&pool)
        .await
        .expect("rerun");

    let kept: Vec<String> = sqlx::query_scalar(
        "SELECT config_json FROM factor_configs WHERE kind = 'hotp' AND user_id IS NULL",
    )
    .fetch_all(&pool)
    .await
    .expect("rows");
    assert_eq!(kept, vec!["NEW".to_owned()], "the newest row is kept");
}

#[tokio::test]
async fn the_schema_itself_refuses_a_second_method_row_at_a_tenant_scope() {
    let pool = pool().await;
    let insert = |id: &'static str| {
        sqlx::query(
            "INSERT INTO auth_methods (id, name, steps_json, user_id, tenant_id)
             VALUES (?1, 'dup', '[]', NULL, ?2)",
        )
        .bind(id)
        .bind(TENANT)
        .execute(&pool)
    };
    insert("m1").await.expect("first row");
    let second = insert("m2").await;
    assert!(
        second.is_err(),
        "a plain insert of a second tenant-scope method row must violate a unique index"
    );
}
