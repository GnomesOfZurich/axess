//! `tests`: extracted from `totp.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;

/// Regression: a too-short TOTP secret must be refused.
#[test]
fn totp_rejects_short_secret() {
    use chrono::DateTime;
    let short_raw: [u8; 8] = [0xab; 8];
    let short_b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &short_raw);
    // Pinned timestamp; short-secret rejection is time-independent
    // by design, but using `Utc::now()` here would still bypass the
    // workspace's Clock discipline and teach the wrong pattern.
    let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let result = verify_totp(
        &short_b32,
        "123456",
        now,
        TotpVerifyParams {
            length: Some(6),
            period: Some(30),
            past_window: Some(1),
            future_window: Some(1),
            algorithm: TotpAlgorithm::SHA1,
        },
    );
    assert!(result.is_none(), "TOTP must reject sub-128-bit secrets");
}

// RFC 6238 Appendix B test vectors share the SHA-1 secret with RFC 4226 §5.1.
const RFC_4226_SECRET: &[u8] = b"12345678901234567890";
fn rfc_4226_secret_b32() -> String {
    base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        RFC_4226_SECRET,
    )
}

/// RFC 6238 Appendix B test vectors for TOTP-SHA-1 with the same
/// secret. The Appendix gives 8-digit codes at specific Unix
/// timestamps. Pinning these kills `verify_totp`'s comparison
/// operators, the `now / period` quotient mutation (`/ → %` /
/// `* `), and the window-walk boolean flips.
#[test]
fn rfc_6238_appendix_b_totp_sha1_vectors_match() {
    use chrono::DateTime;
    const VECTORS: &[(u64, &str)] = &[
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
    ];
    let b32 = rfc_4226_secret_b32();

    for (t, expected) in VECTORS {
        let now = DateTime::from_timestamp(*t as i64, 0).unwrap();
        let result = verify_totp(
            &b32,
            expected,
            now,
            TotpVerifyParams {
                length: Some(8),
                period: Some(30),
                past_window: Some(0),
                future_window: Some(0),
                algorithm: TotpAlgorithm::SHA1,
            },
        );
        assert!(
            result.is_some(),
            "RFC 6238 Appendix B: verify_totp rejected {expected} at t={t}",
        );
    }
}

/// Negative half: the RFC 6238 vector at t=59 must NOT verify
/// when the clock is far in the future or past beyond the
/// configured window. Catches `>` / `<` / `==` mutations on the
/// drift comparator.
#[test]
fn rfc_6238_vector_does_not_match_outside_window() {
    use chrono::DateTime;
    let b32 = rfc_4226_secret_b32();
    let way_later = DateTime::from_timestamp((59 + 5 * 30) as i64, 0).unwrap();
    let result = verify_totp(
        &b32,
        "94287082",
        way_later,
        TotpVerifyParams {
            length: Some(8),
            period: Some(30),
            past_window: Some(0),
            future_window: Some(0),
            algorithm: TotpAlgorithm::SHA1,
        },
    );
    assert!(
        result.is_none(),
        "verify_totp accepted t=59 code at t=209 with zero-width window; \
             drift comparator does not actually constrain to the window",
    );
}

/// RFC 6238 Appendix B SHA-256 vectors. The Appendix specifies a
/// 32-byte ASCII secret distinct from the SHA-1 secret.
#[test]
fn rfc_6238_appendix_b_totp_sha256_vectors_match() {
    use chrono::DateTime;
    const RFC_6238_SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
    const VECTORS: &[(u64, &str)] = &[
        (59, "46119246"),
        (1111111109, "68084774"),
        (1111111111, "67062674"),
        (1234567890, "91819424"),
        (2000000000, "90698825"),
    ];
    let b32 = base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        RFC_6238_SHA256_SECRET,
    );

    for (t, expected) in VECTORS {
        let now = DateTime::from_timestamp(*t as i64, 0).unwrap();
        let result = verify_totp(
            &b32,
            expected,
            now,
            TotpVerifyParams {
                length: Some(8),
                period: Some(30),
                past_window: Some(0),
                future_window: Some(0),
                algorithm: TotpAlgorithm::SHA256,
            },
        );
        assert!(
            result.is_some(),
            "RFC 6238 Appendix B SHA-256: verify_totp rejected {expected} at t={t}",
        );
    }
}

/// RFC 6238 Appendix B SHA-512 vectors. 64-byte ASCII secret.
#[test]
fn rfc_6238_appendix_b_totp_sha512_vectors_match() {
    use chrono::DateTime;
    const RFC_6238_SHA512_SECRET: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";
    const VECTORS: &[(u64, &str)] = &[
        (59, "90693936"),
        (1111111109, "25091201"),
        (1111111111, "99943326"),
        (1234567890, "93441116"),
        (2000000000, "38618901"),
    ];
    let b32 = base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        RFC_6238_SHA512_SECRET,
    );

    for (t, expected) in VECTORS {
        let now = DateTime::from_timestamp(*t as i64, 0).unwrap();
        let result = verify_totp(
            &b32,
            expected,
            now,
            TotpVerifyParams {
                length: Some(8),
                period: Some(30),
                past_window: Some(0),
                future_window: Some(0),
                algorithm: TotpAlgorithm::SHA512,
            },
        );
        assert!(
            result.is_some(),
            "RFC 6238 Appendix B SHA-512: verify_totp rejected {expected} at t={t}",
        );
    }
}

/// `verify_totp` MUST accept exactly the minimum (16-byte) secret
/// length and reject below.
#[test]
fn verify_totp_accepts_minimum_length_secret() {
    use chrono::DateTime;
    let raw: [u8; 16] = [0xab; 16];
    let b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw);
    let t: u64 = 1_700_000_000;
    let code = format!("{:06}", totp_value(&raw, t, 30, 6, TotpAlgorithm::SHA1));
    let now = DateTime::from_timestamp(t as i64, 0).unwrap();
    let result = verify_totp(
        &b32,
        &code,
        now,
        TotpVerifyParams {
            length: Some(6),
            period: Some(30),
            past_window: Some(0),
            future_window: Some(0),
            algorithm: TotpAlgorithm::SHA1,
        },
    );
    assert!(
        result.is_some(),
        "verify_totp must accept a 16-byte secret at the boundary; \
             minimum length is `< MIN_OTP_SECRET_BYTES`, so 16 must pass"
    );
}

/// `verify_totp` MUST reject a `length` that exceeds [`MAX_TOTP_DIGITS`].
/// The bound is 8 because RFC 6238 §1.2 allows 6 to 8 digits.
#[test]
fn verify_totp_rejects_length_above_max() {
    use chrono::DateTime;
    let b32 = rfc_4226_secret_b32();
    let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let over = MAX_TOTP_DIGITS + 1;
    let code: String = std::iter::repeat_n('1', over).collect();
    let result = verify_totp(
        &b32,
        &code,
        now,
        TotpVerifyParams {
            length: Some(over),
            period: Some(30),
            past_window: Some(1),
            future_window: Some(1),
            algorithm: TotpAlgorithm::SHA1,
        },
    );
    assert!(
        result.is_none(),
        "verify_totp must reject length > MAX_TOTP_DIGITS"
    );
}

/// `percent_encode_component` MUST follow RFC 3986 §2.3 unreserved
/// alphabet.
#[test]
fn percent_encode_component_known_outputs() {
    assert_eq!(percent_encode_component("a b"), "a%20b");
    assert_eq!(percent_encode_component("AZaz09-_.~"), "AZaz09-_.~");
    assert_eq!(
        percent_encode_component("alice@example.com"),
        "alice%40example.com"
    );
    assert_eq!(percent_encode_component(""), "");
}

/// `generate_totp_secret` MUST produce a 32-character (160-bit)
/// RFC 4648 base32 string from a deterministic RNG.
#[test]
fn generate_totp_secret_with_seeded_rng_is_32_char_base32() {
    let rng = axess_rng::testing::MockRng::new(0xA028);
    let secret = generate_totp_secret(&rng);
    assert_eq!(
        secret.len(),
        32,
        "20-byte secret base32-encodes to 32 chars (no padding); got {} chars",
        secret.len(),
    );
    assert!(
        secret
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
        "generate_totp_secret produced non-base32 bytes: {secret}",
    );
}

/// `generate_totp_secret` MUST return a 32-character base32 string.
#[test]
fn generate_totp_secret_is_32_char_base32() {
    let secret = generate_totp_secret(&axess_rng::SystemRng);
    assert_eq!(secret.len(), 32);
    assert!(
        secret
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
        "generate_totp_secret produced non-base32 bytes: {secret}",
    );
}

/// `build_totp_uri` MUST produce a complete RFC 6238 / KeyURI
/// `otpauth://` URI with the supplied label, issuer, secret,
/// digits, and period.
#[test]
fn build_totp_uri_known_output() {
    let uri = build_totp_uri("alice@example.com", "Acme Corp", "JBSWY3DPEHPK3PXP", 6, 30).unwrap();
    assert!(uri.starts_with("otpauth://totp/"), "wrong scheme: {uri}");
    assert!(
        uri.contains("Acme%20Corp:alice%40example.com"),
        "label/issuer not encoded: {uri}"
    );
    assert!(
        uri.contains("secret=JBSWY3DPEHPK3PXP"),
        "secret missing: {uri}"
    );
    assert!(
        uri.contains("issuer=Acme%20Corp"),
        "issuer query missing: {uri}"
    );
    assert!(uri.contains("digits=6"), "digits missing: {uri}");
    assert!(uri.contains("period=30"), "period missing: {uri}");
}

/// A code length below six is brute-forceable and a period of zero would
/// divide by zero; both are refused before any code is compared.
#[test]
fn totp_rejects_short_length_and_zero_period() {
    use chrono::DateTime;
    let raw: [u8; 20] = [0xab; 20];
    let b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw);
    let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let short = TotpVerifyParams {
        length: Some(1),
        period: Some(30),
        ..TotpVerifyParams::default()
    };
    assert!(
        verify_totp(&b32, "1", now, short).is_none(),
        "a one-digit code must be refused"
    );
    let zero_period = TotpVerifyParams {
        length: Some(6),
        period: Some(0),
        ..TotpVerifyParams::default()
    };
    assert!(
        verify_totp(&b32, "123456", now, zero_period).is_none(),
        "a zero period must be refused, not divide by zero"
    );
}

/// A digit count or period `verify_totp` refuses is refused here too, rather
/// than clamped into an authenticator the server would then verify with
/// other parameters than the ones the user was shown.
#[test]
fn build_totp_uri_refuses_parameters_verify_refuses() {
    for (digits, period) in [(1, 30), (5, 30), (9, 30), (12, 30), (6, 0), (6, 4)] {
        assert_eq!(
            build_totp_uri("a", "Acme", "JBSWY3DPEHPK3PXP", digits, period),
            None,
            "digits {digits}, period {period}"
        );
    }
    for digits in 6..=8 {
        assert!(build_totp_uri("a", "Acme", "JBSWY3DPEHPK3PXP", digits, 5).is_some());
    }
}

#[test]
fn build_totp_uri_with_algorithm_names_the_algorithm() {
    let uri = build_totp_uri_with_algorithm(
        "a",
        "Acme",
        "JBSWY3DPEHPK3PXP",
        6,
        30,
        TotpAlgorithm::SHA256,
    )
    .unwrap();
    assert!(
        uri.contains("&algorithm=SHA256"),
        "algorithm missing: {uri}"
    );
    let default = build_totp_uri("a", "Acme", "JBSWY3DPEHPK3PXP", 6, 30).unwrap();
    assert!(
        default.contains("&algorithm=SHA1"),
        "SHA1 missing: {default}"
    );
}

/// The RFC 6238 SHA-1 secret spelled as hex. It holds `0`, `8` and `9`, which
/// base32 does not, so only a hex fallback could read it.
const RFC_4226_SECRET_HEX: &str = "3132333435363738393031323334353637383930";

#[test]
fn a_hex_secret_is_not_read() {
    use chrono::DateTime;
    let now = DateTime::from_timestamp(59, 0).unwrap();
    let result = verify_totp(
        RFC_4226_SECRET_HEX,
        "94287082",
        now,
        TotpVerifyParams {
            length: Some(8),
            period: Some(30),
            past_window: Some(0),
            future_window: Some(0),
            algorithm: TotpAlgorithm::SHA1,
        },
    );
    assert!(result.is_none(), "a hex secret must not verify");
}

#[test]
fn a_secret_of_hex_letters_and_base32_digits_verifies_as_base32() {
    use chrono::DateTime;
    // Every character is in both the hex and the base32 alphabets.
    let secret = "ABCDEF2345ABCDEF2345ABCDEF2345AB";
    let raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret).unwrap();
    let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let code = format!(
        "{:06}",
        totp_value(&raw, 1_700_000_000, 30, 6, TotpAlgorithm::SHA1)
    );
    let result = verify_totp(
        secret,
        &code,
        now,
        TotpVerifyParams {
            length: Some(6),
            period: Some(30),
            past_window: Some(0),
            future_window: Some(0),
            algorithm: TotpAlgorithm::SHA1,
        },
    );
    assert!(result.is_some(), "the base32 reading must verify");
}

// RFC 6238 Appendix B: one secret per HMAC (the SHA-1 secret repeated to the
// digest's block size), 8-digit codes, step 30, T0 = 0.
const RFC_6238_SECRETS: [(TotpAlgorithm, &[u8]); 3] = [
    (TotpAlgorithm::SHA1, b"12345678901234567890"),
    (TotpAlgorithm::SHA256, b"12345678901234567890123456789012"),
    (
        TotpAlgorithm::SHA512,
        b"1234567890123456789012345678901234567890123456789012345678901234",
    ),
];

/// (time, SHA-1 code, SHA-256 code, SHA-512 code), every row of the table.
const RFC_6238_VECTORS: [(u64, [&str; 3]); 6] = [
    (59, ["94287082", "46119246", "90693936"]),
    (1111111109, ["07081804", "68084774", "25091201"]),
    (1111111111, ["14050471", "67062674", "99943326"]),
    (1234567890, ["89005924", "91819424", "93441116"]),
    (2000000000, ["69279037", "90698825", "38618901"]),
    (20000000000, ["65353130", "77737706", "47863826"]),
];

#[test]
fn rfc_6238_appendix_b_codes_match_for_every_algorithm_and_time() {
    for (time, expected) in RFC_6238_VECTORS {
        for ((algorithm, secret), expected) in RFC_6238_SECRETS.into_iter().zip(expected) {
            let code = format!("{:08}", totp_value(secret, time, 30, 8, algorithm));
            assert_eq!(code, expected, "{algorithm} at t={time}");
        }
    }
}

#[test]
fn rfc_6238_appendix_b_codes_verify_through_verify_totp() {
    use chrono::DateTime;
    for (time, expected) in RFC_6238_VECTORS {
        for ((algorithm, secret), expected) in RFC_6238_SECRETS.into_iter().zip(expected) {
            let b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret);
            let now = DateTime::from_timestamp(time as i64, 0).unwrap();
            let params = TotpVerifyParams {
                length: Some(8),
                period: Some(30),
                past_window: Some(0),
                future_window: Some(0),
                algorithm,
            };
            assert_eq!(
                verify_totp(&b32, expected, now, params),
                Some(time / 30),
                "{algorithm} at t={time}"
            );
        }
    }
}

#[test]
fn the_provisioning_uri_is_unchanged_byte_for_byte() {
    assert_eq!(
        build_totp_uri("alice@example.com", "Acme Corp", "JBSWY3DPEHPK3PXP", 6, 30).unwrap(),
        "otpauth://totp/Acme%20Corp:alice%40example.com?secret=JBSWY3DPEHPK3PXP\
         &issuer=Acme%20Corp&algorithm=SHA1&digits=6&period=30"
    );
    assert_eq!(
        build_totp_uri_with_algorithm("a", "I", "JBSWY3DPEHPK3PXP", 8, 60, TotpAlgorithm::SHA512)
            .unwrap(),
        "otpauth://totp/I:a?secret=JBSWY3DPEHPK3PXP&issuer=I&algorithm=SHA512&digits=8&period=60"
    );
}
