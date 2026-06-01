//! HOTP: HMAC-Based One-Time Passwords (RFC 4226).
//!
//! Counter-based codes; pair the verifier with an application-side
//! counter store that increments on every successful verification.
//! Variants for SHA-1 (RFC default), SHA-256, and SHA-512 cover the
//! OATH-compliant hardware-token universe.

use crate::otp_algorithm::OtpAlgorithm;
use crate::secret::ZeroizedString;
use crate::{MAX_HOTP_DIGITS, MIN_OTP_SECRET_BYTES};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The HMAC algorithm used for HOTP code generation.
///
/// Defaults to SHA-1 per RFC 4226. SHA-256 and SHA-512 variants are supported
/// as extensions (commonly used in OATH-compliant tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HotpAlgorithm {
    /// HMAC-SHA-1 (RFC 4226, 20-byte digest).
    #[default]
    Sha1,
    /// HMAC-SHA-256 (32-byte digest).
    Sha256,
    /// HMAC-SHA-512 (64-byte digest).
    Sha512,
}

/// Default HOTP code length in decimal digits (RFC 4226 §5.3 recommended 6).
pub const HOTP_LENGTH: usize = 6;

// ── HotpConfig ───────────────────────────────────────────────────────────────

/// HOTP factor configuration (RFC 4226).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotpConfig {
    /// Shared secret (raw bytes, base32-encoded for provisioning URIs). Zeroized on drop.
    pub secret: ZeroizedString,
    /// Number of digits in the generated code (typically 6).
    pub digits: u8,
    /// HMAC algorithm used for code derivation.
    pub algorithm: OtpAlgorithm,
    /// Server-side counter; advances on every successful verification.
    pub counter: u64,
    /// Number of future counter values accepted to handle hardware-token drift.
    pub lookahead_window: u32,
    /// Number of failed verification attempts made against the current
    /// counter window. Incremented on each failed verify; reset to 0 on
    /// successful verify. When `attempt_count >= max_attempts`, the
    /// counter is advanced past the lookahead window so the current set
    /// of codes can never be presented again, and the user must re-sync
    /// from a fresh hardware-token press.
    ///
    /// Required by RFC 4226 §7.4 ("the server MUST set a throttling
    /// parameter T"). Without this counter, an attacker has unlimited
    /// guesses against the lookahead window.
    #[serde(default)]
    pub attempt_count: u8,
    /// Maximum failed attempts before the counter is burned. RFC 4226
    /// §7.4 RECOMMENDS T ≤ 10. Default: 5. Set to 0 to disable
    /// (not recommended).
    #[serde(default = "default_max_hotp_attempts")]
    pub max_attempts: u8,
}

fn default_max_hotp_attempts() -> u8 {
    5
}

impl Default for HotpConfig {
    fn default() -> Self {
        Self {
            secret: ZeroizedString::new(""),
            digits: 6,
            algorithm: OtpAlgorithm::Sha1,
            counter: 0,
            lookahead_window: 10,
            attempt_count: 0,
            max_attempts: 5,
        }
    }
}

// mutation-testing follow-up: pin the documented `max_attempts` default. A value
// of 0 would either lock the user out instantly (no attempts allowed)
// or never expire the counter (depending on which interpretation the
// verify path takes). Mutation testing found the previous
// suite didn't assert this default, so a regression bumping the value
// to 0 or 1 would have shipped silently.
#[cfg(test)]
mod hotp_config_defaults {
    use super::{HotpConfig, default_max_hotp_attempts};

    #[test]
    fn hotp_default_max_attempts_is_five() {
        assert_eq!(default_max_hotp_attempts(), 5);
        assert_eq!(HotpConfig::default().max_attempts, 5);
    }
}

/// Verify an HOTP code with a window of acceptable counter values (RFC 4226).
///
/// # Arguments
/// * `secret` - The shared secret (base32 or hex encoded)
/// * `code` - The HOTP code to verify
/// * `counter` - The expected counter value
/// * `length` - Number of digits in the code
/// * `window` - Number of future counter values to check (0 = exact match only)
/// * `algorithm` - The HMAC algorithm to use (defaults to SHA-1 for backward compatibility)
///
/// # Returns
/// `Some(used_counter)` if verification succeeds (the actual counter that matched),
/// `None` if verification fails
pub fn verify_hotp(
    secret: &str,
    code: &str,
    counter: u64,
    length: usize,
    window: u64,
    algorithm: HotpAlgorithm,
) -> Option<u64> {
    if length > MAX_HOTP_DIGITS {
        return None;
    }

    // Normalize secret for base32 (uppercase, try with and without padding).
    // Wrap the uppercase copy in Zeroizing so it's cleared on drop.
    let secret_trimmed = secret.trim();
    let secret_upper = Zeroizing::new(secret_trimmed.to_ascii_uppercase());
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret_upper)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret_upper))
        .or_else(|| hex::decode(secret_trimmed).ok())?;

    // Enforce RFC 4226 §4 R6 minimum (128-bit / 16-byte) secret.
    if decoded.len() < MIN_OTP_SECRET_BYTES {
        return None;
    }

    // Wrap the owned bytes so they get zeroed on drop.
    let secret_bytes = Zeroizing::new(decoded);

    // Try each counter value in the window.
    // Always iterate the full window to avoid leaking the match position via timing.
    // The ct_eq comparison runs every iteration; only the first match is recorded.
    let mut matched: Option<u64> = None;
    let trimmed_code = code.trim();
    for offset in 0..=window {
        let candidate_counter = counter + offset;
        let expected = hotp_generate(&secret_bytes, candidate_counter, length, algorithm);
        let is_match = bool::from(expected.as_bytes().ct_eq(trimmed_code.as_bytes()));
        if is_match && matched.is_none() {
            matched = Some(candidate_counter);
        }
    }

    matched
}

/// Generate an HOTP code per RFC 4226.
///
/// 1. HMAC(secret, counter_be_bytes) → digest (length depends on algorithm)
/// 2. Dynamic truncation → 31-bit integer
/// 3. Modulo 10^digits → zero-padded decimal string
///
/// Supports SHA-1 (RFC 4226), SHA-256, and SHA-512 variants.
pub(crate) fn hotp_generate(
    secret: &[u8],
    counter: u64,
    digits: usize,
    algorithm: HotpAlgorithm,
) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use zeroize::Zeroize;

    // Compute HMAC with the selected algorithm and extract truncated code.
    // Each branch performs: HMAC → dynamic truncation → zeroize digest.
    let binary = match algorithm {
        HotpAlgorithm::Sha1 => {
            let mut mac =
                Hmac::<sha1::Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(&counter.to_be_bytes());
            let mut result = mac.finalize().into_bytes();
            let len = result.len();
            let offset = (result[len - 1] & 0x0f) as usize;
            let value = ((result[offset] & 0x7f) as u32) << 24
                | (result[offset + 1] as u32) << 16
                | (result[offset + 2] as u32) << 8
                | (result[offset + 3] as u32);
            result.as_mut_slice().zeroize();
            value
        }
        HotpAlgorithm::Sha256 => {
            let mut mac =
                Hmac::<sha2::Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(&counter.to_be_bytes());
            let mut result = mac.finalize().into_bytes();
            let len = result.len();
            let offset = (result[len - 1] & 0x0f) as usize;
            let value = ((result[offset] & 0x7f) as u32) << 24
                | (result[offset + 1] as u32) << 16
                | (result[offset + 2] as u32) << 8
                | (result[offset + 3] as u32);
            result.as_mut_slice().zeroize();
            value
        }
        HotpAlgorithm::Sha512 => {
            let mut mac =
                Hmac::<sha2::Sha512>::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(&counter.to_be_bytes());
            let mut result = mac.finalize().into_bytes();
            let len = result.len();
            let offset = (result[len - 1] & 0x0f) as usize;
            let value = ((result[offset] & 0x7f) as u32) << 24
                | (result[offset + 1] as u32) << 16
                | (result[offset + 2] as u32) << 8
                | (result[offset + 3] as u32);
            result.as_mut_slice().zeroize();
            value
        }
    };

    // mutation-testing follow-up: use u64 modulus. `binary` is at most a 31-bit
    // integer (top bit stripped by `& 0x7f` during Dynamic Truncation,
    // RFC 4226 §5.3), so it always fits in u32; but `10^digits` for
    // `digits = 10` overflows u32 (10^10 > 2^32). Promoting to u64
    // makes the full `MAX_HOTP_DIGITS = 10` range usable without
    // panicking on the boundary.
    let modulus: u64 = 10u64.pow(digits as u32);
    format!("{:0>width$}", u64::from(binary) % modulus, width = digits,)
}

#[cfg(test)]
mod tests {
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

    /// Differential test: axess `hotp_generate(_, _, _, Sha256)` MUST
    /// agree with `totp-rs` at `time = counter * period` (which is
    /// definitionally HOTP-SHA-256 at that counter). Kills the
    /// surviving `&` / `<<` / `+` / `-` mutations on the SHA-256
    /// branch of `hotp_generate`. Under any of them the truncation
    /// math diverges from totp-rs's reference implementation.
    ///
    /// Why differential, not RFC: RFC 4226 only specifies HOTP-SHA-1
    /// vectors. The SHA-256/SHA-512 HOTP variants are defined by the
    /// OATH "HOTP-NG" / RFC 6238 §1.2 extension but no public
    /// hard-coded vectors are widely cited. Using `totp-rs` as the
    /// oracle anchors axess's bit-arithmetic to a second, independent
    /// implementation.
    #[cfg(feature = "totp")]
    #[test]
    fn hotp_generate_sha256_matches_totp_rs_oracle() {
        use totp_rs::{Algorithm as TotpAlgorithm, TOTP};
        const PERIOD: u64 = 30;
        for counter in [0u64, 1, 7, 42, 1234, 1_000_000] {
            let oracle_totp = TOTP::new(
                TotpAlgorithm::SHA256,
                6,
                0,
                PERIOD,
                RFC_4226_SECRET.to_vec(),
            )
            .unwrap();
            let oracle_code = oracle_totp.generate(counter * PERIOD);
            let axess_code = hotp_generate(RFC_4226_SECRET, counter, 6, HotpAlgorithm::Sha256);
            assert_eq!(
                axess_code, oracle_code,
                "axess hotp_generate-SHA256 diverged from totp-rs at counter {counter}: \
                 axess={axess_code}, oracle={oracle_code}",
            );
        }
    }

    /// Differential test for SHA-512: same oracle pattern.
    #[cfg(feature = "totp")]
    #[test]
    fn hotp_generate_sha512_matches_totp_rs_oracle() {
        use totp_rs::{Algorithm as TotpAlgorithm, TOTP};
        const PERIOD: u64 = 30;
        for counter in [0u64, 1, 7, 42, 1234, 1_000_000] {
            let oracle_totp = TOTP::new(
                TotpAlgorithm::SHA512,
                6,
                0,
                PERIOD,
                RFC_4226_SECRET.to_vec(),
            )
            .unwrap();
            let oracle_code = oracle_totp.generate(counter * PERIOD);
            let axess_code = hotp_generate(RFC_4226_SECRET, counter, 6, HotpAlgorithm::Sha512);
            assert_eq!(
                axess_code, oracle_code,
                "axess hotp_generate-SHA512 diverged from totp-rs at counter {counter}: \
                 axess={axess_code}, oracle={oracle_code}",
            );
        }
    }
}
