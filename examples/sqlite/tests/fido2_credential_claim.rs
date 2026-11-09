//! A passkey credential id is claimed by one account of a tenant with one
//! conditional insert, so two registrations racing for it have one winner.

use axess::SystemClock;
use axess::authn::{FactorStore, TenantId, UserId};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const OTHER_TENANT: &str = "00000000-0000-0000-0000-000000000002";
const ALICE: &str = "00000000-0000-0000-0000-000000000010";
const BOB: &str = "00000000-0000-0000-0000-000000000011";

async fn backend() -> OurBackend {
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
    OurBackend::new(pool)
}

#[tokio::test]
async fn racing_claims_of_one_credential_id_have_one_winner() {
    let backend = backend().await;
    let tenant = TenantId::try_new(TENANT).expect("tenant");
    let (alice, bob) = (
        UserId::try_new(ALICE).expect("user"),
        UserId::try_new(BOB).expect("user"),
    );

    let (a, b) = tokio::join!(
        backend.claim_fido2_credential(&tenant, &alice, b"cred"),
        backend.claim_fido2_credential(&tenant, &bob, b"cred"),
    );
    let (a, b) = (a.expect("claim"), b.expect("claim"));
    assert!(a != b, "both or neither claimed: {a} {b}");

    let (winner, loser) = if a { (alice, bob) } else { (bob, alice) };
    assert!(
        backend
            .claim_fido2_credential(&tenant, &winner, b"cred")
            .await
            .expect("claim"),
        "claiming again as the holder holds"
    );
    backend
        .release_fido2_credential(&tenant, &loser, b"cred")
        .await
        .expect("release");
    assert!(
        !backend
            .claim_fido2_credential(&tenant, &loser, b"cred")
            .await
            .expect("claim"),
        "a release by a non-holder changed the claim"
    );
    backend
        .release_fido2_credential(&tenant, &winner, b"cred")
        .await
        .expect("release");
    assert!(
        backend
            .claim_fido2_credential(&tenant, &loser, b"cred")
            .await
            .expect("claim")
    );
    let other = TenantId::try_new(OTHER_TENANT).expect("tenant");
    assert!(
        backend
            .claim_fido2_credential(&other, &winner, b"cred")
            .await
            .expect("claim"),
        "the id is held per tenant"
    );
}
