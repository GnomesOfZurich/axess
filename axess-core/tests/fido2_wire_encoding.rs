#![cfg(all(feature = "testing", feature = "fido2"))]
//! What a FIDO2 assertion may look like on the wire, and which stored key a
//! discoverable login is verified against.
//!
//! webauthn-rs 0.6.2 reads every binary field of an assertion as URL-safe
//! base64, with or without padding, and nothing else: the standard alphabet
//! (`+`, `/`) no longer parses, so `FactorCredential::as_public_key_credential`
//! answers `None` for it and the login is refused.

use axess_core::authn::factor::FactorCredential;
use axess_factors::fido2::{DefaultFido2Provider, Fido2Provider};
use url::Url;
use webauthn_rs::prelude::*;

/// An assertion whose signature field is `signature`, every other binary
/// field `AAAA`.
fn assertion_json(raw_id: &str, signature: &str) -> serde_json::Value {
    serde_json::json!({
        "id": raw_id, "rawId": raw_id, "type": "public-key",
        "response": { "authenticatorData": "AAAA", "clientDataJSON": "AAAA",
                      "signature": signature, "userHandle": null }
    })
}

fn read(json: serde_json::Value) -> Option<PublicKeyCredential> {
    FactorCredential::Fido2Assertion(json).as_public_key_credential()
}

#[test]
fn an_assertion_in_the_url_safe_alphabet_is_read() {
    let credential = read(assertion_json("AAAA", "-_8")).expect("URL-safe base64 is read");
    assert_eq!(credential.response.signature.as_slice(), &[0xfb, 0xff]);
}

#[test]
fn a_padded_url_safe_assertion_is_read() {
    let credential = read(assertion_json("AAAA", "-_8=")).expect("padding is accepted");
    assert_eq!(credential.response.signature.as_slice(), &[0xfb, 0xff]);
}

#[test]
fn an_assertion_in_the_standard_alphabet_is_refused() {
    assert!(
        read(assertion_json("AAAA", "+/8")).is_none(),
        "the standard base64 alphabet must not parse as an assertion"
    );
}

/// A passkey with credential id `id` (URL-safe base64) and a placeholder
/// public key.
fn passkey(id: &str) -> Passkey {
    let coord = format!("{}A", "A".repeat(42));
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

fn provider() -> DefaultFido2Provider {
    let origin = Url::parse("https://example.com").expect("origin");
    let webauthn = WebauthnBuilder::new("example.com", &origin)
        .expect("builder")
        .build()
        .expect("webauthn");
    DefaultFido2Provider::new(webauthn)
}

fn finish(keys: &[Passkey]) -> WebauthnResult<AuthenticationResult> {
    let provider = provider();
    let (_, state) = provider
        .start_discoverable_authentication()
        .expect("ceremony starts");
    let assertion: PublicKeyCredential =
        serde_json::from_value(assertion_json("AAAA", "AAAA")).expect("assertion");
    let keys: Vec<DiscoverableKey> = keys.iter().map(DiscoverableKey::from).collect();
    provider.finish_discoverable_authentication(&assertion, state, &keys)
}

#[test]
fn a_discoverable_login_with_no_key_of_the_assertion_is_refused_as_not_found() {
    assert!(matches!(
        finish(&[]),
        Err(WebauthnError::CredentialNotFound)
    ));
    assert!(matches!(
        finish(&[passkey("YWFhYQ"), passkey("YmJiYg")]),
        Err(WebauthnError::CredentialNotFound)
    ));
}

#[test]
fn a_discoverable_login_is_verified_against_the_key_of_the_assertion() {
    // `AAAA` is the assertion's credential id. The key verifies nothing (the
    // assertion carries no real client data), so the refusal is that key's
    // verdict and not a missing key, wherever the key stands in the list.
    for keys in [
        vec![passkey("AAAA")],
        vec![passkey("YWFhYQ"), passkey("AAAA")],
    ] {
        let verdict = finish(&keys);
        assert!(verdict.is_err(), "a forged assertion must not verify");
        assert!(
            !matches!(verdict, Err(WebauthnError::CredentialNotFound)),
            "the matching key must be the one verified, got {verdict:?}"
        );
    }
}
