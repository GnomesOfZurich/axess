//! How the SQLite store reads a write its table refuses: only the unique
//! index over the pair is a held pair; any other refusal is the backend's.

use super::directory_tests::{record, secret};
use super::*;

#[tokio::test]
async fn a_write_the_table_refuses_for_another_reason_is_not_a_held_pair() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("pool");
    let store = SqliteTenantOAuthProviderStore::new(pool.clone());
    store.init_schema().await.expect("schema");
    sqlx::query(
        "CREATE TRIGGER refuse_every_insert BEFORE INSERT ON tenant_oauth_providers \
         BEGIN SELECT RAISE(ABORT, 'every insert is refused'); END",
    )
    .execute(&pool)
    .await
    .expect("trigger");

    let refused = store
        .put(record("acme", "https://idp.example", "client-x", secret()))
        .await
        .expect_err("the trigger refuses the write");

    assert!(!refused.is_pair_held(), "{refused}");
    assert!(
        refused.to_string().contains("every insert is refused"),
        "the backend's error is kept: {refused}"
    );
}
