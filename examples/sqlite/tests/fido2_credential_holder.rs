//! The claim on a passkey credential id reads the ids out of stored factor
//! rows too, within one tenant: a passkey stored without a claim holds its
//! id for the user it is stored for.
//!
//! The row is written as the store writes it, straight into `factor_configs`,
//! so the test reads the same bytes whether or not the `fido2` feature is on
//! (with it, `Fido2Config::credentials` is typed and a hand-made passkey would
//! have to be a complete one; the lookup only reads the JSON).

use axess::authn::{FactorStore, Fido2CredentialClaim, TenantId, UserId};
use axess_clock::testing::MockClock;
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const ALICE: &str = "00000000-0000-0000-0000-000000000010";
const BOB: &str = "00000000-0000-0000-0000-000000000011";

async fn pool(clock: &MockClock) -> sqlx::SqlitePool {
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
        clock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF")
            .with_clock(std::sync::Arc::new(clock.clone())),
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

/// Another user's claim on the id of a stored passkey is refused and names
/// the user the passkey is stored for; an id no stored passkey carries is
/// free, and so is the same id in another tenant.
#[tokio::test]
async fn a_stored_passkey_refuses_another_users_claim_within_its_tenant() {
    let clock = MockClock::at_reference();
    let pool = pool(&clock).await;
    store_alice_passkey(&pool).await;
    let backend = OurBackend::new(pool).with_clock(std::sync::Arc::new(clock.clone()));
    let tenant = TenantId::try_new(TENANT).expect("tenant");
    let (alice, bob) = (
        UserId::try_new(ALICE).expect("user"),
        UserId::try_new(BOB).expect("user"),
    );

    let refused = backend
        .claim_fido2_credential(&tenant, &bob, b"aaaa")
        .await
        .expect("claim");
    assert_eq!(refused, Fido2CredentialClaim::HeldBy(alice));

    let other_id = backend
        .claim_fido2_credential(&tenant, &bob, b"bbbb")
        .await
        .expect("claim");
    assert_eq!(
        other_id,
        Fido2CredentialClaim::Claimed,
        "an id nobody holds"
    );

    let other_tenant = TenantId::try_new("00000000-0000-0000-0000-000000000002").expect("tenant");
    let elsewhere = backend
        .claim_fido2_credential(&other_tenant, &bob, b"aaaa")
        .await
        .expect("claim");
    assert_eq!(
        elsewhere,
        Fido2CredentialClaim::Claimed,
        "another tenant does not see it"
    );
}
