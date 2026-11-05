//! `tests`: extracted from `hotp.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;

/// Regression: a too-short HOTP secret (8 bytes / 64 bits)
/// must be refused at verification time per RFC 4226 §4 R6.
#[test]
fn hotp_rejects_short_secret() {
    let short_raw: [u8; 8] = [0xab; 8];
    let short_b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &short_raw);
    let result = verify_hotp(&short_b32, "123456", 0, 6, 0, HotpAlgorithm::Sha1);
    assert!(result.is_none(), "HOTP must reject sub-128-bit secrets");
}

#[test]
fn hotp_accepts_minimum_length_secret() {
    // 16 bytes / 128 bits = exactly the minimum.
    let raw: [u8; 16] = [0xab; 16];
    let b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw);
    let code = hotp_generate(&raw, 0, 6, HotpAlgorithm::Sha1);
    assert_eq!(
        verify_hotp(&b32, &code, 0, 6, 0, HotpAlgorithm::Sha1),
        Some(0),
        "16-byte secret must verify normally"
    );
}

// RFC 4226 Appendix D shared test vector: secret + base32 form. Reused
// across all HOTP RFC tests below, and across the differential SHA-256
// / SHA-512 oracle tests.
const RFC_4226_SECRET: &[u8] = b"12345678901234567890";
fn rfc_4226_secret_b32() -> String {
    base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        RFC_4226_SECRET,
    )
}

/// RFC 4226 Appendix D table: counter → 6-digit HOTP code for the
/// secret `"12345678901234567890"`. Pinning every entry kills the
/// mutations on `hotp_generate`'s Dynamic Truncation arithmetic
/// (`<<`, `&`, `|`, `+`) and on `verify_hotp`'s comparison
/// operators: wrong bit-shift / wrong mask / wrong offset → wrong
/// code → assertion fails.
#[test]
fn rfc_4226_appendix_d_hotp_vectors_match() {
    const VECTORS: &[(u64, &str)] = &[
        (0, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ];
    let b32 = rfc_4226_secret_b32();

    for (counter, expected) in VECTORS {
        let generated = hotp_generate(RFC_4226_SECRET, *counter, 6, HotpAlgorithm::Sha1);
        assert_eq!(
            generated, *expected,
            "RFC 4226 Appendix D: hotp_generate at counter {counter} produced {generated}, expected {expected}",
        );
        assert_eq!(
            verify_hotp(&b32, expected, *counter, 6, 0, HotpAlgorithm::Sha1),
            Some(*counter),
            "RFC 4226 Appendix D: verify_hotp at counter {counter} did not accept {expected}",
        );
    }
}

/// Negative half: the RFC vectors must NOT verify against
/// neighbouring counters. Catches `replace > with <=` /
/// `delete !` / `&& with ||` mutations on the verify_hotp
/// window-walk that would silently widen acceptance.
#[test]
fn rfc_4226_vector_does_not_match_wrong_counter() {
    let b32 = rfc_4226_secret_b32();
    // Counter 0's code must NOT verify against counter 5 with no
    // lookahead window; the verify_hotp must walk only [counter,
    // counter + lookahead], not the full [0, ∞).
    assert_eq!(
        verify_hotp(&b32, "755224", 5, 6, 0, HotpAlgorithm::Sha1),
        None,
        "verify_hotp accepted RFC 4226 counter-0 code at counter 5; \
         window walk is broken",
    );
    assert_eq!(
        verify_hotp(&b32, "000000", 0, 6, 0, HotpAlgorithm::Sha1),
        None,
        "verify_hotp accepted '000000' for RFC 4226 counter 0",
    );
}

/// A code length below six is brute-forceable, and a length of 0 would
/// make the code "0" match every counter; both are refused.
#[test]
fn verify_hotp_rejects_length_below_min() {
    let b32 = rfc_4226_secret_b32();
    assert!(
        verify_hotp(&b32, "0", 0, 0, 0, HotpAlgorithm::Sha1).is_none(),
        "length 0 must be refused"
    );
    assert!(
        verify_hotp(&b32, "12345", 0, 5, 0, HotpAlgorithm::Sha1).is_none(),
        "length 5 must be refused"
    );
    let code = hotp_generate(RFC_4226_SECRET, 0, 6, HotpAlgorithm::Sha1);
    assert_eq!(
        verify_hotp(&b32, &code, 0, 6, 0, HotpAlgorithm::Sha1),
        Some(0),
        "length 6 is the floor and is accepted"
    );
}

/// `verify_hotp` MUST reject `length > MAX_HOTP_DIGITS` (=10).
#[test]
fn verify_hotp_rejects_length_above_max() {
    let b32 = rfc_4226_secret_b32();
    let result = verify_hotp(&b32, "12345678901", 0, 11, 0, HotpAlgorithm::Sha1);
    assert!(
        result.is_none(),
        "verify_hotp must reject length > MAX_HOTP_DIGITS (=10)"
    );
}

/// `verify_hotp` MUST accept `length = 10` (the documented
/// boundary). Pins the inclusive upper bound.
#[test]
fn verify_hotp_accepts_length_at_max() {
    let b32 = rfc_4226_secret_b32();
    let code = hotp_generate(RFC_4226_SECRET, 0, 10, HotpAlgorithm::Sha1);
    let result = verify_hotp(&b32, &code, 0, 10, 0, HotpAlgorithm::Sha1);
    assert_eq!(
        result,
        Some(0),
        "verify_hotp must accept length = MAX_HOTP_DIGITS (=10) at the boundary"
    );
}

/// `verify_hotp` MUST find a match inside the lookahead window
/// when given the start counter and a code from a later counter.
#[test]
fn verify_hotp_window_walks_forward() {
    let b32 = rfc_4226_secret_b32();
    let code = hotp_generate(RFC_4226_SECRET, 2, 6, HotpAlgorithm::Sha1);
    let result = verify_hotp(&b32, &code, 0, 6, 5, HotpAlgorithm::Sha1);
    assert_eq!(
        result,
        Some(2),
        "verify_hotp window walk did not find counter=2 from start=0; \
         window iteration is broken"
    );
}

/// RFC 4226 only gives SHA-1 vectors; the SHA-256 and SHA-512 variants are
/// pinned by RFC 6238 Appendix B, whose codes are HOTP at the counter
/// `time / 30` with 8 digits and a secret per HMAC. Kills the surviving `&`,
/// `<<`, `+` and `-` mutations on those two branches.
#[test]
fn hotp_generate_matches_rfc_6238_appendix_b_for_sha256_and_sha512() {
    const SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
    const SHA512_SECRET: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";
    const VECTORS: [(u64, &str, &str); 6] = [
        (59, "46119246", "90693936"),
        (1111111109, "68084774", "25091201"),
        (1111111111, "67062674", "99943326"),
        (1234567890, "91819424", "93441116"),
        (2000000000, "90698825", "38618901"),
        (20000000000, "77737706", "47863826"),
    ];
    for (time, sha256, sha512) in VECTORS {
        let counter = time / 30;
        assert_eq!(
            hotp_generate(SHA256_SECRET, counter, 8, HotpAlgorithm::Sha256),
            sha256,
            "SHA-256 at t={time}"
        );
        assert_eq!(
            hotp_generate(SHA512_SECRET, counter, 8, HotpAlgorithm::Sha512),
            sha512,
            "SHA-512 at t={time}"
        );
    }
}

/// A code is digits and nothing else. `"+12345"` parses as the number 12345,
/// which is the value of a real six-digit code with a leading zero, so a
/// numeric comparison must refuse it before it parses.
#[test]
fn a_signed_code_never_matches_a_code_with_a_leading_zero() {
    let (counter, code) = (0..2_000u64)
        .map(|c| (c, hotp_generate(RFC_4226_SECRET, c, 6, HotpAlgorithm::Sha1)))
        .find(|(_, code)| code.starts_with('0'))
        .expect("some counter below 2000 yields a leading zero");
    let secret = base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        RFC_4226_SECRET,
    );

    assert_eq!(
        verify_hotp(&secret, &code, counter, 6, 0, HotpAlgorithm::Sha1),
        Some(counter),
        "the real code with its leading zero verifies"
    );
    let signed = format!("+{}", &code[1..]);
    assert_eq!(
        verify_hotp(&secret, &signed, counter, 6, 0, HotpAlgorithm::Sha1),
        None
    );
    let spaced = format!(" {}", &code[1..]);
    assert_eq!(
        verify_hotp(&secret, &spaced, counter, 6, 0, HotpAlgorithm::Sha1),
        None
    );
}

#[test]
fn a_hex_secret_is_not_read() {
    // The RFC 4226 secret as hex; `0`, `8` and `9` are not base32 characters.
    let hex_secret = "3132333435363738393031323334353637383930";
    let code = hotp_generate(b"12345678901234567890", 0, 6, HotpAlgorithm::Sha1);
    assert_eq!(
        verify_hotp(hex_secret, &code, 0, 6, 0, HotpAlgorithm::Sha1),
        None,
        "a hex secret must not verify"
    );
}

#[test]
fn a_secret_of_hex_letters_and_base32_digits_verifies_as_base32() {
    // Every character is in both the hex and the base32 alphabets.
    let secret = "ABCDEF2345ABCDEF2345ABCDEF2345AB";
    let raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret).unwrap();
    let code = hotp_generate(&raw, 7, 6, HotpAlgorithm::Sha1);
    assert_eq!(
        verify_hotp(secret, &code, 7, 6, 0, HotpAlgorithm::Sha1),
        Some(7)
    );
}
