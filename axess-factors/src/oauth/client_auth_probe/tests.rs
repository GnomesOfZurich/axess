//! The control credential: wrong, and otherwise as like the client's as a
//! provider that checks the shape of a credential can see.

use super::{
    AUTHENTICATED_ERRORS, ClientAuthProbe, NOT_AUTHENTICATED_ERROR, with_signature_altered,
    wrong_secret,
};

/// The character classes of `text`, in order.
fn classes(text: &str) -> Vec<&'static str> {
    text.chars()
        .map(|c| match c {
            '0'..='9' => "digit",
            'a'..='z' => "lower",
            'A'..='Z' => "upper",
            c if c.is_ascii_punctuation() => "punctuation",
            c if c.is_ascii() => "other ascii",
            _ => "non-ascii",
        })
        .collect()
}

/// The control differs from the secret in one character, and matches its
/// length in bytes and characters, its classes and every character before
/// the one changed.
#[test]
fn the_control_secret_keeps_the_length_classes_and_prefix() {
    for secret in [
        "s3cret",
        "0123456789abcdef0123456789abcdef",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "zzzz",
        "9",
        "Y",
        "key-with_trailing-punctuation--",
        "----",
        "pässwörd-ü",
        "ü",
        "€€€",
        "𝄞",
        "secret with spaces ",
    ] {
        let control = wrong_secret(secret);
        let control: &str = &control;
        assert_ne!(control, secret, "{secret:?}");
        assert_eq!(control.len(), secret.len(), "bytes of {secret:?}");
        assert_eq!(
            control.chars().count(),
            secret.chars().count(),
            "characters of {secret:?}"
        );
        assert_eq!(classes(control), classes(secret), "classes of {secret:?}");
        let differing = control
            .chars()
            .zip(secret.chars())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(differing, 1, "{secret:?} -> {control:?}");
    }
}

/// A hex secret stays hex, whichever digit or letter is changed: a provider
/// that answers a malformed secret as `invalid_client` sees a well-formed
/// control.
#[test]
fn a_hex_secret_has_a_hex_control() {
    for last in "0123456789abcdef".chars() {
        let secret = format!("00ff{last}");
        let control = wrong_secret(&secret);
        let control: &str = &control;
        assert!(
            control
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{secret} -> {control}"
        );
        assert!(control.starts_with("00ff"), "{control}");
    }
}

/// The last letter or digit is the one changed, so a secret's prefix and
/// any trailing punctuation are kept.
#[test]
fn the_last_letter_or_digit_is_changed() {
    let control = wrong_secret("ab-cd--");
    assert_eq!(&*control, "ab-cc--");
}

/// The control assertion keeps the header, the claims and the signature's
/// length and encoding, and differs from the signature in the lowest bit of
/// its last byte.
#[test]
fn the_control_assertion_differs_in_the_last_bit_of_its_signature() {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signature = [0x10_u8, 0x20, 0x30, 0x40];
    let assertion = format!("header.claims.{}", engine.encode(signature));

    let altered = with_signature_altered(&assertion).expect("a compact JWS");

    let (signed, encoded) = altered.rsplit_once('.').expect("three parts");
    assert_eq!(signed, "header.claims");
    assert_eq!(encoded.len(), engine.encode(signature).len());
    assert_eq!(
        engine.decode(encoded).expect("base64url"),
        [0x10_u8, 0x20, 0x30, 0x41]
    );
    // The bit is flipped, not set: a signature ending in an odd byte is
    // altered too, and the flip is its own inverse.
    let odd = format!("header.claims.{}", engine.encode([0x10_u8, 0x41]));
    let altered_odd = with_signature_altered(&odd).expect("a compact JWS");
    assert_eq!(
        engine
            .decode(altered_odd.rsplit_once('.').expect("three parts").1)
            .expect("base64url"),
        [0x10_u8, 0x40]
    );
    assert_eq!(with_signature_altered(&altered_odd).as_deref(), Some(&*odd));
    assert_eq!(
        with_signature_altered("header.claims."),
        None,
        "no signature"
    );
    assert_eq!(with_signature_altered("no-dots"), None, "not a JWS");
}

/// Each character's control partner is the one beside it in its own class:
/// a digit or letter swaps with its neighbour, a punctuation character with
/// the one beside it in the ASCII punctuation, and any other character with
/// the code point that differs in the lowest bit, both ways.
#[test]
fn each_character_has_its_one_partner() {
    for (secret, control) in [
        ("0", "1"),
        ("9", "8"),
        ("a", "b"),
        ("z", "y"),
        ("A", "B"),
        ("Z", "Y"),
        ("!", "\""),
        ("-", "."),
        (".", "-"),
        ("~", "}"),
        ("ü", "ý"),
        ("ý", "ü"),
    ] {
        assert_eq!(&*wrong_secret(secret), control, "{secret:?}");
    }
}

/// `invalid_client` under 400 or 401 says the client's authentication
/// failed; a grant refusal under 400 says it passed; every other pair, a
/// status the RFC does not send them with included, proves nothing and
/// names the code and the status.
#[test]
fn an_answer_is_read_by_its_status_and_error_code() {
    for status in [400, 401] {
        assert_eq!(
            ClientAuthProbe::of_answer(status, NOT_AUTHENTICATED_ERROR),
            ClientAuthProbe::NotAuthenticated,
            "{status}"
        );
    }
    for error in AUTHENTICATED_ERRORS {
        assert_eq!(
            ClientAuthProbe::of_answer(400, error),
            ClientAuthProbe::Authenticated {
                error: error.to_owned()
            },
            "{error}"
        );
    }
    for (status, error) in [
        (403, NOT_AUTHENTICATED_ERROR),
        (401, "invalid_grant"),
        (400, "invalid_request"),
        (400, "server_error"),
    ] {
        let ClientAuthProbe::Unproven { reason } = ClientAuthProbe::of_answer(status, error) else {
            panic!("{status} {error} proved something");
        };
        assert!(
            reason.contains(&format!("`{error}`")) && reason.contains(&format!("HTTP {status}")),
            "{reason}"
        );
    }
}
