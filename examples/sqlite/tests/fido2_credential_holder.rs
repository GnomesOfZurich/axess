//! The cross-user passkey check reads the credential ids out of stored
//! factor rows, within one tenant.
//!
//! The row is written as the store writes it, straight into `factor_configs`,
//! so the test reads the same bytes whether or not the `fido2` feature is on
//! (with it, `Fido2Config::credentials` is typed and a hand-made passkey would
//! have to be a complete one; the lookup only reads the JSON).

use axess::SystemClock;
use axess::authn::{FactorStore, TenantId, UserId};
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
        &axess::authn::FactorSecretCipher::new([7; 32]),
    )
    .await
    .expect("seed");
    pool
}

/// Store a passkey row for Alice holding the credential id `YWFhYQ` (`aaaa`),
/// in the shape the store's `save_factor` writes.
async fn store_alice_passkey(pool: &sqlx::SqlitePool) {
    let config_json = serde_json::json!({
        "credentials": [{
            "passkey": { "cred": { "cred_id": "YWFhYQ", "counter": 1 } },
            "name": "key"
        }]
    })
    .to_string();
    sqlx::query(
        "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled, updated_at)
         VALUES (?1, ?2, ?3, 'fido2', ?4, 1, datetime('now'))",
    )
    .bind("fc-walk-alice-passkey")
    .bind(ALICE)
    .bind(TENANT)
    .bind(config_json)
    .execute(pool)
    .await
    .expect("stored passkey row");
}

#[tokio::test]
async fn the_holder_of_a_stored_credential_id_is_found_within_its_tenant() {
    let pool = pool().await;
    store_alice_passkey(&pool).await;
    let backend = OurBackend::new(pool);
    let tenant = TenantId::try_new(TENANT).expect("tenant");

    let holder = backend
        .fido2_credential_holder(&tenant, b"aaaa")
        .await
        .expect("lookup");
    assert_eq!(holder, Some(UserId::try_new(ALICE).expect("user")));

    let other_id = backend
        .fido2_credential_holder(&tenant, b"bbbb")
        .await
        .expect("lookup");
    assert_eq!(other_id, None, "an id nobody holds");

    let other_tenant = TenantId::try_new("00000000-0000-0000-0000-000000000002").expect("tenant");
    let elsewhere = backend
        .fido2_credential_holder(&other_tenant, b"aaaa")
        .await
        .expect("lookup");
    assert_eq!(elsewhere, None, "another tenant does not see it");
}
