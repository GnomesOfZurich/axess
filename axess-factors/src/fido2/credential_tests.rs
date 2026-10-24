//! `Fido2Credential::record_authentication` stamps only the credential the
//! assertion belongs to. Credentials are built from their serialised form,
//! since webauthn-rs offers no constructor without a ceremony.

use super::*;
use chrono::TimeZone;
use serde_json::json;

/// Credential ids are URL-safe base64: `YWFhYQ` is `aaaa`, `YmJiYg` is `bbbb`.
const AAAA: &str = "YWFhYQ";
const BBBB: &str = "YmJiYg";

fn passkey(id: &str, counter: u32) -> Passkey {
    // 32 zero bytes, URL-safe base64 without padding.
    let coord = "A".repeat(43);
    serde_json::from_value(json!({
        "cred": {
            "cred_id": id,
            "cred": {
                "type_": "ES256",
                "key": { "EC_EC2": { "curve": "SECP256R1", "x": coord, "y": coord } }
            },
            "counter": counter,
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

fn result_for(id: &str, counter: u32) -> AuthenticationResult {
    serde_json::from_value(json!({
        "cred_id": id,
        "needs_update": true,
        "user_verified": true,
        "backup_state": false,
        "backup_eligible": false,
        "counter": counter,
        "extensions": {}
    }))
    .expect("authentication result fixture")
}

fn credential(id: &str) -> Fido2Credential {
    let registered = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    Fido2Credential::new(passkey(id, 1), "key", registered)
}

#[test]
fn record_authentication_stamps_the_matching_credential() {
    let now = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
    let mut cred = credential(AAAA);
    cred.record_authentication(&result_for(AAAA, 5), now);
    assert_eq!(cred.last_used_at, Some(now));
}

#[test]
fn record_authentication_leaves_other_credentials_untouched() {
    let now = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
    let mut other = credential(BBBB);
    other.record_authentication(&result_for(AAAA, 5), now);
    assert_eq!(other.last_used_at, None);
}
