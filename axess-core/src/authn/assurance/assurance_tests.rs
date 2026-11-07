//! What each factor kind proves by itself, how the backup flags read, and
//! that the record keeps one proof per kind.

use super::*;
use crate::authn::factor::FederatedProvider;

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_700_000_000 + seconds, 0).expect("valid time")
}

#[test]
fn a_memorized_secret_verifies_the_user_and_a_possession_factor_does_not() {
    let verified = [FactorKind::Password, FactorKind::LdapBind];
    let possession = [
        FactorKind::Totp,
        FactorKind::Hotp,
        FactorKind::EmailOtp,
        FactorKind::RecoveryCode,
        FactorKind::Federated(FederatedProvider::Google),
    ];
    for kind in verified {
        let proof = FactorAssurance::for_kind(kind.clone(), at(0));
        assert!(proof.user_verified, "{kind} is the person's knowledge");
        assert_eq!(proof.credential, CredentialBinding::NotApplicable);
        assert_eq!(proof.trust_anchor, None);
    }
    for kind in possession {
        let proof = FactorAssurance::for_kind(kind.clone(), at(0));
        assert!(!proof.user_verified, "{kind} proves possession only");
        assert_eq!(proof.credential, CredentialBinding::NotApplicable);
        assert_eq!(proof.trust_anchor, None);
    }
}

#[test]
fn a_passkey_recorded_by_its_kind_alone_claims_the_least() {
    let proof = FactorAssurance::for_kind(FactorKind::Fido2, at(0));
    assert!(!proof.user_verified);
    assert_eq!(proof.credential, CredentialBinding::Synced);
    assert_eq!(proof.trust_anchor, None);
}

#[test]
fn only_a_credential_that_cannot_be_backed_up_is_device_bound() {
    assert_eq!(
        CredentialBinding::from_backup_flags(false, false),
        CredentialBinding::DeviceBound
    );
    assert_eq!(
        CredentialBinding::from_backup_flags(true, false),
        CredentialBinding::Synced,
        "eligible for backup but not yet backed up may still sync"
    );
    assert_eq!(
        CredentialBinding::from_backup_flags(true, true),
        CredentialBinding::Synced
    );
    assert_eq!(
        CredentialBinding::from_backup_flags(false, true),
        CredentialBinding::Synced
    );
}

#[test]
fn a_fido2_proof_keeps_its_flags_and_trust_anchor() {
    let proof = FactorAssurance::fido2(true, false, false, Some(Arc::from("vendor")), at(5));
    assert_eq!(proof.kind, FactorKind::Fido2);
    assert_eq!(proof.at, at(5));
    assert!(proof.user_verified);
    assert_eq!(proof.credential, CredentialBinding::DeviceBound);
    assert_eq!(proof.trust_anchor.as_deref(), Some("vendor"));
}

#[test]
fn the_record_holds_the_latest_proof_of_each_kind() {
    let mut record = Vec::new();
    record_proof(
        &mut record,
        FactorAssurance::for_kind(FactorKind::Password, at(0)),
    );
    record_proof(
        &mut record,
        FactorAssurance::fido2(true, true, true, None, at(1)),
    );
    record_proof(
        &mut record,
        FactorAssurance::fido2(true, false, false, None, at(2)),
    );
    assert_eq!(record.len(), 2, "one entry per kind");
    assert_eq!(record[0].kind, FactorKind::Password);
    assert_eq!(
        record[1].at,
        at(2),
        "the later passkey replaced the earlier"
    );
    assert_eq!(record[1].credential, CredentialBinding::DeviceBound);
}

#[test]
fn the_binding_names_are_the_ones_policies_compare_against() {
    for (binding, name) in [
        (CredentialBinding::DeviceBound, "device_bound"),
        (CredentialBinding::Synced, "synced"),
        (CredentialBinding::NotApplicable, "not_applicable"),
    ] {
        assert_eq!(binding.as_str(), name);
        assert_eq!(
            serde_json::to_value(binding).unwrap(),
            serde_json::json!(name)
        );
    }
}
