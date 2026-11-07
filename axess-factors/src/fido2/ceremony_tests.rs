//! The ceremony names: written and read back, refused when unknown, and
//! ordered from the one that asks the least to the one that asks the most.

use super::*;

#[test]
fn every_ceremony_name_round_trips() {
    for ceremony in [
        Fido2Ceremony::Passkey,
        Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred),
        Fido2Ceremony::SecurityKey(SecurityKeyVerification::Discouraged),
        Fido2Ceremony::AttestedPasskey {
            trust_anchor: "vendor-roots".into(),
        },
    ] {
        let name = ceremony.to_string();
        assert_eq!(name.parse::<Fido2Ceremony>().unwrap(), ceremony, "{name}");
        let json = serde_json::to_value(&ceremony).unwrap();
        assert_eq!(json, serde_json::json!(name));
        assert_eq!(
            serde_json::from_value::<Fido2Ceremony>(json).unwrap(),
            ceremony
        );
    }
}

#[test]
fn an_unknown_or_malformed_name_is_refused_by_name() {
    for value in [
        "",
        "Passkey",
        "security_key",
        "security_key:required",
        "attested_passkey",
        "attested_passkey:",
        "attested_passkey:two words",
        "attested_passkey:tab\there",
    ] {
        let err = value.parse::<Fido2Ceremony>().unwrap_err();
        assert_eq!(err.value, value);
        assert!(err.to_string().contains("unknown FIDO2 ceremony"));
    }
}

#[test]
fn the_default_is_the_passkey_ceremony_axess_ran_before() {
    assert_eq!(DEFAULT_FIDO2_CEREMONY, Fido2Ceremony::Passkey);
    let options = Fido2Options::default();
    assert_eq!(options.registration_ceremony, Fido2Ceremony::Passkey);
    assert_eq!(options.login_ceremony, Fido2Ceremony::Passkey);
}

#[test]
fn ceremonies_order_from_the_least_asked_to_the_most() {
    let mut ceremonies = [
        Fido2Ceremony::AttestedPasskey {
            trust_anchor: "a".into(),
        },
        Fido2Ceremony::Passkey,
        Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred),
        Fido2Ceremony::SecurityKey(SecurityKeyVerification::Discouraged),
    ];
    ceremonies.sort();
    let names: Vec<String> = ceremonies.iter().map(ToString::to_string).collect();
    assert_eq!(
        names,
        [
            "security_key:discouraged",
            "security_key:preferred",
            "passkey",
            "attested_passkey:a"
        ]
    );
}
