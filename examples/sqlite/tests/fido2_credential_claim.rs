//! A passkey credential id is claimed by one account of a tenant with one
//! statement, so two registrations racing for it have one winner and the
//! other is told who holds the id.

use axess::authn::{FactorStore, IdentityAdmin, TenantId, UserId};
use axess_clock::testing::MockClock;
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const OTHER_TENANT: &str = "00000000-0000-0000-0000-000000000002";
const ALICE: &str = "00000000-0000-0000-0000-000000000010";
const BOB: &str = "00000000-0000-0000-0000-000000000011";

async fn backend() -> OurBackend {
    let clock = MockClock::at_reference();
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
        &clock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF")
            .with_clock(std::sync::Arc::new(clock.clone())),
    )
    .await
    .expect("seed");
    OurBackend::new(pool).with_clock(std::sync::Arc::new(clock.clone()))
}

/// The store keeps the rules of the claim, the refusal that names its holder
/// among them: the check a store outside this repository runs.
#[tokio::test]
async fn the_store_meets_the_claim_contract() {
    let backend = backend().await;
    axess_core::testing::store_contract::assert_fido2_claim_contract(
        &backend,
        &TenantId::try_new(TENANT).expect("tenant"),
        &UserId::try_new(ALICE).expect("user"),
        &UserId::try_new(BOB).expect("user"),
    )
    .await;
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
    assert!(
        a.is_claimed() != b.is_claimed(),
        "both or neither claimed: {a:?} {b:?}"
    );

    let (winner, loser) = if a.is_claimed() {
        (alice, bob)
    } else {
        (bob, alice)
    };
    assert!(
        backend
            .claim_fido2_credential(&tenant, &winner, b"cred")
            .await
            .expect("claim")
            .is_claimed(),
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
            .expect("claim")
            .is_claimed(),
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
            .is_claimed()
    );
    let other = TenantId::try_new(OTHER_TENANT).expect("tenant");
    assert!(
        backend
            .claim_fido2_credential(&other, &winner, b"cred")
            .await
            .expect("claim")
            .is_claimed(),
        "the id is held per tenant"
    );
}

/// Erasing an account releases the credential ids it claimed, so an id a
/// deleted user held can be registered by another account of the tenant.
#[tokio::test]
async fn a_deleted_users_claims_are_released() {
    let backend = backend().await;
    let tenant = TenantId::try_new(TENANT).expect("tenant");
    let (alice, bob) = (
        UserId::try_new(ALICE).expect("user"),
        UserId::try_new(BOB).expect("user"),
    );
    assert!(
        backend
            .claim_fido2_credential(&tenant, &alice, b"cred")
            .await
            .expect("claim")
            .is_claimed()
    );
    backend.delete_user(&alice).await.expect("delete");
    assert!(
        backend
            .claim_fido2_credential(&tenant, &bob, b"cred")
            .await
            .expect("claim")
            .is_claimed(),
        "a claim left behind by the deleted user blocks the id"
    );
}
