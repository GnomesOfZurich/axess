//! Step-up names, their factors and ceremonies, the order a gate tries them
//! in, and the best proof each can yield.

use super::*;
use crate::authn::assurance::CredentialBinding;
use crate::authn::factor::{Fido2Ceremony, SecurityKeyVerification};

fn all() -> Vec<StepUp> {
    vec![
        StepUp::Fido2(Fido2Ceremony::AttestedPasskey {
            trust_anchor: "roots".into(),
        }),
        StepUp::Fido2(Fido2Ceremony::Passkey),
        StepUp::Fido2(Fido2Ceremony::SecurityKey(
            SecurityKeyVerification::Preferred,
        )),
        StepUp::Fido2(Fido2Ceremony::SecurityKey(
            SecurityKeyVerification::Discouraged,
        )),
        StepUp::LdapBind,
        StepUp::Password,
        StepUp::RecoveryCode,
        StepUp::EmailOtp,
        StepUp::Hotp,
        StepUp::Totp,
    ]
}

#[test]
fn every_step_up_name_round_trips_and_names_its_factor() {
    for step_up in all() {
        let name = step_up.to_string();
        assert_eq!(name.parse::<StepUp>().unwrap(), step_up, "{name}");
        assert_eq!(
            serde_json::to_value(&step_up).unwrap(),
            serde_json::json!(name)
        );
        assert_eq!(
            step_up.fido2_ceremony().is_some(),
            step_up.factor_kind() == FactorKind::Fido2
        );
    }
}

#[test]
fn an_unknown_step_up_is_refused_by_name() {
    for value in ["", "fido2", "sms", "Passkey", "attested_passkey:"] {
        let err = value.parse::<StepUp>().unwrap_err();
        assert_eq!(err.value, value);
    }
}

#[test]
fn a_gate_tries_possession_codes_first_and_the_strictest_ceremony_last() {
    let mut ordered = all();
    ordered.sort();
    let names: Vec<String> = ordered.iter().map(ToString::to_string).collect();
    assert_eq!(
        names,
        [
            "totp",
            "hotp",
            "email_otp",
            "recovery_code",
            "password",
            "ldap_bind",
            "security_key:discouraged",
            "security_key:preferred",
            "passkey",
            "attested_passkey:roots",
        ]
    );
}

#[test]
fn the_best_proof_is_what_the_ceremony_can_yield() {
    let at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
    let passkey = StepUp::Fido2(Fido2Ceremony::Passkey).best_proof(at);
    assert!(passkey.user_verified);
    assert_eq!(passkey.credential, CredentialBinding::DeviceBound);
    assert_eq!(passkey.trust_anchor, None);

    let discouraged = StepUp::Fido2(Fido2Ceremony::SecurityKey(
        SecurityKeyVerification::Discouraged,
    ))
    .best_proof(at);
    assert!(
        !discouraged.user_verified,
        "it asks the authenticator not to verify"
    );

    let attested = StepUp::Fido2(Fido2Ceremony::AttestedPasskey {
        trust_anchor: "roots".into(),
    })
    .best_proof(at);
    assert_eq!(attested.trust_anchor.as_deref(), Some("roots"));

    assert_eq!(
        StepUp::Totp.best_proof(at),
        FactorAssurance::for_kind(FactorKind::Totp, at)
    );
}
