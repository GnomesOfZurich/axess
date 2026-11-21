#![cfg(all(feature = "testing", feature = "fido2"))]
//! The in-memory backend holds one passkey credential id per account of a
//! tenant: its factor store decides the claim under one lock, and a deleted
//! user's claims go with the user.

use axess_core::InMemoryBackend;
use axess_core::authn::factor::{FactorConfig, Fido2Config, Fido2Credential};
use axess_core::authn::ids::{TenantId, UserId};
use axess_core::authn::store::{FactorStore, Fido2CredentialClaim, IdentityAdmin};
use axess_core::authn::types::AuthnScope;
use webauthn_rs::prelude::Passkey;

fn backend() -> InMemoryBackend {
    let clock = axess_clock::testing::MockClock::at_reference();
    InMemoryBackend::new()
        .with_clock(std::sync::Arc::new(clock.clone()))
        .with_default_tenant("default", "Default Tenant")
        .with_user_password("alice", "default", "Sample2+")
        .with_user_password("bob", "default", "Sample2+")
}

fn tenant() -> TenantId {
    axess_identity::testing::tenant("default")
}

fn alice() -> UserId {
    axess_identity::testing::user("alice")
}

fn bob() -> UserId {
    axess_identity::testing::user("bob")
}

/// A passkey whose credential id is the base64url text `id` decodes to.
fn passkey(id: &str) -> Passkey {
    let coord = "A".repeat(43);
    serde_json::from_value(serde_json::json!({
        "cred": {
            "cred_id": id,
            "cred": { "type_": "ES256",
                "key": { "EC_EC2": { "curve": "SECP256R1", "x": coord, "y": coord } } },
            "counter": 1,
            "transports": null,
            "user_verified": true,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "required",
            "extensions": {},
            "attestation": { "data": "None", "metadata": "None" },
            "attestation_format": "none"
        }
    }))
    .expect("passkey fixture")
}

/// The backend keeps the rules of the claim, the refusal that names its
/// holder among them.
#[tokio::test]
async fn the_in_memory_backend_meets_the_claim_contract() {
    axess_core::testing::store_contract::assert_fido2_claim_contract(
        &backend(),
        &tenant(),
        &alice(),
        &bob(),
    )
    .await;
}

#[tokio::test]
async fn racing_claims_of_one_credential_id_have_one_winner() {
    let backend = backend();
    let (tenant, alice, bob) = (tenant(), alice(), bob());
    let (a, b) = tokio::join!(
        backend.claim_fido2_credential(&tenant, &alice, b"cred"),
        backend.claim_fido2_credential(&tenant, &bob, b"cred"),
    );
    let (a, b) = (a.expect("claim"), b.expect("claim"));
    assert!(
        a.is_claimed() != b.is_claimed(),
        "both or neither claimed the id: alice {a:?}, bob {b:?}"
    );
}

#[tokio::test]
async fn a_claimed_id_is_refused_to_another_user_until_released() {
    let backend = backend();
    assert!(
        backend
            .claim_fido2_credential(&tenant(), &alice(), b"cred")
            .await
            .expect("claim")
            .is_claimed()
    );
    assert!(
        !backend
            .claim_fido2_credential(&tenant(), &bob(), b"cred")
            .await
            .expect("claim")
            .is_claimed(),
        "the id another user of the tenant holds was admitted"
    );
    backend
        .release_fido2_credential(&tenant(), &alice(), b"cred")
        .await
        .expect("release");
    assert!(
        backend
            .claim_fido2_credential(&tenant(), &bob(), b"cred")
            .await
            .expect("claim")
            .is_claimed()
    );
}

#[tokio::test]
async fn a_deleted_users_claims_are_released() {
    let backend = backend();
    assert!(
        backend
            .claim_fido2_credential(&tenant(), &alice(), b"cred")
            .await
            .expect("claim")
            .is_claimed()
    );
    backend.delete_user(&alice()).await.expect("delete");
    assert!(
        backend
            .claim_fido2_credential(&tenant(), &bob(), b"cred")
            .await
            .expect("claim")
            .is_claimed(),
        "a claim left behind by the deleted user blocks the id"
    );
}

/// A passkey stored without a claim holds its id too: another user's claim
/// on it is refused and names the user it is stored for, the holder's own
/// claim holds, and an id no stored passkey carries is free. A backend that
/// answered every id as free would let a second account register a passkey
/// another holds.
#[tokio::test]
async fn a_stored_passkey_refuses_another_users_claim_and_names_its_holder() {
    let backend = backend();
    let scope = AuthnScope::User {
        tenant_id: tenant(),
        user_id: alice(),
    };
    let registered_at =
        axess_clock::Timestamp::parse_rfc3339("2026-01-01T00:00:00Z").expect("fixed time");
    // "YWFhYQ" is the base64url of the bytes `aaaa`.
    let stored = Fido2Credential::new(passkey("YWFhYQ"), "first", registered_at);
    backend
        .save_factor(
            &scope,
            FactorConfig::Fido2(Fido2Config {
                credentials: vec![stored],
            }),
        )
        .await
        .expect("save");

    assert_eq!(
        backend
            .claim_fido2_credential(&tenant(), &bob(), b"aaaa")
            .await
            .expect("claim"),
        Fido2CredentialClaim::HeldBy(alice()),
        "the stored passkey's holder was not named"
    );
    assert_eq!(
        backend
            .claim_fido2_credential(&tenant(), &alice(), b"aaaa")
            .await
            .expect("claim"),
        Fido2CredentialClaim::Claimed,
        "the holder's own claim was refused"
    );
    assert_eq!(
        backend
            .claim_fido2_credential(&tenant(), &bob(), b"bbbb")
            .await
            .expect("claim"),
        Fido2CredentialClaim::Claimed,
        "an id no stored passkey carries was not free"
    );
}
