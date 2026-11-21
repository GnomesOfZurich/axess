//! The parts of the ownership proofs a registration does not show on its
//! own: what an attestation names, which attestation the operator's proof
//! accepts, which client counts as public, how a refusal reads, and which
//! of a tenant's proofs are asked.

use super::directory_tests;
use super::*;
use crate::authn::ids::testing::{tenant, user};
use axess_clock::testing::MockClock;
use axess_factors::FactorSecret;
use axess_factors::client_assertion::SignerSpec;
use axess_factors::egress::EgressPolicy;
use axess_rng::SystemRng;

const ISSUER: &str = "https://idp.example";

/// Acme's `sso` record for `client-x` at [`ISSUER`], on a client secret.
fn record() -> TenantOAuthProviderRecord {
    directory_tests::record("acme", ISSUER, "client-x", directory_tests::secret())
}

fn attestation(purpose: OwnershipPurpose) -> OwnershipAttestation {
    OwnershipAttestation::recorded(
        user("operator"),
        tenant("acme"),
        ("sso", ISSUER, "client-x"),
        purpose,
    )
}

fn claim<'a>(
    record: &'a TenantOAuthProviderRecord,
    credential: &'a str,
    purpose: OwnershipPurpose,
    attestation: Option<&'a OwnershipAttestation>,
) -> OwnershipClaim<'a> {
    OwnershipClaim {
        record,
        credential,
        purpose,
        attestation,
        egress: EgressPolicy::screened_allowing_loopback_http(),
        clock: Arc::new(MockClock::at_reference()),
        rng: Arc::new(SystemRng),
    }
}

/// A proof that refuses, naming itself.
struct Refuses(&'static str);

impl ClientOwnershipProof for Refuses {
    fn prove<'a>(&'a self, _: &'a OwnershipClaim<'a>) -> OwnershipFuture<'a> {
        Box::pin(std::future::ready(Err(refusal(self.0))))
    }
}

/// A proof that holds, naming itself.
struct Holds(&'static str);

impl ClientOwnershipProof for Holds {
    fn prove<'a>(&'a self, _: &'a OwnershipClaim<'a>) -> OwnershipFuture<'a> {
        Box::pin(std::future::ready(Ok(OwnershipProven::Other {
            proof: self.0.to_string(),
        })))
    }
}

fn refusal(proof: &str) -> OwnershipRefused {
    OwnershipRefused::Other {
        proof: proof.to_string(),
        reason: "refused".to_string(),
    }
}

#[test]
fn an_attestation_names_the_operator_tenant_provider_pair_and_write() {
    let made = attestation(OwnershipPurpose::HandOver);
    assert_eq!(made.operator(), &user("operator"));
    assert_eq!(made.tenant(), &tenant("acme"));
    assert_eq!(made.name(), "sso");
    assert_eq!(made.issuer(), ISSUER);
    assert_eq!(made.client_id(), "client-x");
    assert_eq!(made.purpose(), OwnershipPurpose::HandOver);
    assert_eq!(
        attestation(OwnershipPurpose::Register).purpose(),
        OwnershipPurpose::Register
    );
}

#[test]
fn an_attestation_attests_only_the_record_whose_four_names_it_carries() {
    let made = attestation(OwnershipPurpose::Register);
    assert!(made.attests(&record()));

    let mut other_tenant = record();
    other_tenant.tenant_id = tenant("beta");
    let mut other_name = record();
    other_name.name = "other".into();
    let mut other_issuer = record();
    other_issuer.issuer = "https://other.example".into();
    let mut other_client = record();
    other_client.client_id = "client-y".into();
    for (what, other) in [
        ("tenant", other_tenant),
        ("name", other_name),
        ("issuer", other_issuer),
        ("client id", other_client),
    ] {
        assert!(!made.attests(&other), "another {what} is not attested");
    }
}

#[tokio::test]
async fn the_operator_proof_holds_for_the_record_and_write_attested_only() {
    let held = record();
    let register = attestation(OwnershipPurpose::Register);

    let proven = OperatorAttestation
        .prove(&claim(
            &held,
            "",
            OwnershipPurpose::Register,
            Some(&register),
        ))
        .await;
    assert_eq!(
        proven,
        Ok(OwnershipProven::Attested {
            operator: user("operator")
        })
    );

    let for_another_write = OperatorAttestation
        .prove(&claim(
            &held,
            "",
            OwnershipPurpose::HandOver,
            Some(&register),
        ))
        .await;
    assert_eq!(
        for_another_write,
        Err(OwnershipRefused::AttestedForAnotherPurpose {
            attested: OwnershipPurpose::Register,
            write: OwnershipPurpose::HandOver,
        })
    );

    let mut another = record();
    another.client_id = "client-y".into();
    let for_another_record = OperatorAttestation
        .prove(&claim(
            &another,
            "",
            OwnershipPurpose::Register,
            Some(&register),
        ))
        .await;
    assert_eq!(for_another_record, Err(OwnershipRefused::NotAttested));

    let none = OperatorAttestation
        .prove(&claim(&held, "", OwnershipPurpose::Register, None))
        .await;
    assert_eq!(none, Err(OwnershipRefused::NotAttested));
}

#[test]
fn a_public_client_is_a_secret_record_with_an_empty_credential() {
    let secret = record();
    assert!(claim(&secret, "", OwnershipPurpose::Register, None).is_public_client());
    assert!(!claim(&secret, "s3cret", OwnershipPurpose::Register, None).is_public_client());

    let mut keyed = record();
    keyed.credential = TenantClientCredential::PrivateKeyJwt {
        key_pem: FactorSecret::Plain(String::new().into()),
        signer: SignerSpec::new(jsonwebtoken::Algorithm::RS256),
    };
    assert!(
        !claim(&keyed, "", OwnershipPurpose::Register, None).is_public_client(),
        "a key record is not public, whatever its key"
    );
}

#[test]
fn a_purpose_reads_as_the_name_an_audit_row_carries() {
    assert_eq!(OwnershipPurpose::Register.as_str(), "register");
    assert_eq!(OwnershipPurpose::HandOver.as_str(), "hand_over");
    assert_eq!(OwnershipPurpose::Register.to_string(), "register");
    assert_eq!(OwnershipPurpose::HandOver.to_string(), "hand_over");
}

#[test]
fn every_refusal_is_named_in_order_when_none_holds() {
    let text = OwnershipRefused::NoneHeld(vec![refusal("first"), refusal("second")]).to_string();
    assert_eq!(
        text,
        "no accepted proof holds: first: refused; second: refused"
    );
}

#[tokio::test]
async fn a_single_refusal_is_returned_as_itself() {
    let held = record();
    let proofs = OwnershipProofs::accept(Refuses("only"));
    let verdict = proofs
        .prove(&claim(&held, "s3cret", OwnershipPurpose::Register, None))
        .await;
    assert_eq!(verdict, Err(refusal("only")));
}

#[tokio::test]
async fn the_proofs_are_tried_in_order_and_every_refusal_is_kept() {
    let held = record();
    let refusing = OwnershipProofs::accept(Refuses("first")).or_accept(Refuses("second"));
    let verdict = refusing
        .prove(&claim(&held, "s3cret", OwnershipPurpose::Register, None))
        .await;
    assert_eq!(
        verdict,
        Err(OwnershipRefused::NoneHeld(vec![
            refusal("first"),
            refusal("second")
        ]))
    );

    let holding = OwnershipProofs::accept(Refuses("first")).or_accept(Holds("second"));
    let verdict = holding
        .prove(&claim(&held, "s3cret", OwnershipPurpose::Register, None))
        .await;
    assert_eq!(
        verdict,
        Ok(OwnershipProven::Other {
            proof: "second".into()
        })
    );
}

#[tokio::test]
async fn a_tenant_named_is_asked_its_own_proofs_and_every_other_the_shared_ones() {
    let proofs = OwnershipProofs::accept(Holds("shared"))
        .for_tenant(tenant("acme"), Refuses("acme's own"))
        .for_tenant(tenant("acme"), Holds("acme's second"))
        .for_tenant(tenant("gamma"), Refuses("gamma's own"));

    let acme = record();
    let verdict = proofs
        .prove(&claim(&acme, "s3cret", OwnershipPurpose::Register, None))
        .await;
    assert_eq!(
        verdict,
        Ok(OwnershipProven::Other {
            proof: "acme's second".into()
        })
    );

    let mut gamma = record();
    gamma.tenant_id = tenant("gamma");
    let verdict = proofs
        .prove(&claim(&gamma, "s3cret", OwnershipPurpose::Register, None))
        .await;
    assert_eq!(
        verdict,
        Err(refusal("gamma's own")),
        "a tenant whose own proofs all refuse is not asked the shared ones"
    );

    let mut beta = record();
    beta.tenant_id = tenant("beta");
    let verdict = proofs
        .prove(&claim(&beta, "s3cret", OwnershipPurpose::Register, None))
        .await;
    assert_eq!(
        verdict,
        Ok(OwnershipProven::Other {
            proof: "shared".into()
        })
    );
}

#[test]
fn the_proofs_debug_as_counts_only() {
    let proofs = OwnershipProofs::accept(Holds("a"))
        .or_accept(Refuses("b"))
        .for_tenant(tenant("acme"), Holds("c"));
    assert_eq!(
        format!("{proofs:?}"),
        "OwnershipProofs { every_tenant: 2, by_tenant: 1 }"
    );
}
