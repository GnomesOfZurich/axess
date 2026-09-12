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
    let totp = TotpBuilder::new()
        .with_algorithm(TotpAlgorithm::SHA1)
        .with_digits(6)
        .with_skew(0)
        .with_step_duration(30)
        .with_secret(raw.to_vec())
        .build()
        .unwrap();
    let t: u64 = 1_700_000_000;
    let code = totp.generate(t).to_string();
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
/// The bound is 8 because the underlying `totp-rs` crate enforces
/// RFC 6238 §1.2's 6..=8 digit range in `TotpBuilder::build`.
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
    let uri = build_totp_uri("alice@example.com", "Acme Corp", "JBSWY3DPEHPK3PXP", 6, 30);
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
