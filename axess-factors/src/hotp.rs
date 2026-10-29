//! HOTP: HMAC-Based One-Time Passwords (RFC 4226).
//!
//! Counter-based codes; pair the verifier with an application-side
//! counter store that increments on every successful verification.
//! Variants for SHA-1 (RFC default), SHA-256, and SHA-512 cover the
//! OATH-compliant hardware-token universe.

use crate::factor_secret::FactorSecret;
use crate::otp_algorithm::OtpAlgorithm;
use crate::{MAX_HOTP_DIGITS, MIN_OTP_DIGITS, MIN_OTP_SECRET_BYTES};
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
    /// Shared secret (raw bytes, base32-encoded for provisioning URIs). Plain
    /// text is zeroized in memory on drop, redacted in `Debug`, and written to
    /// the store as it stands; seal it with a `FactorSecretCipher` to keep it
    /// encrypted at rest. See the OTP secret section of the password and TOTP
    /// guide.
    pub secret: FactorSecret,
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
    /// §7.4 RECOMMENDS T ≤ 10. Default: 5. A value of 0 is
    /// treated as the default, never as "no limit".
    #[serde(default = "default_max_hotp_attempts")]
    pub max_attempts: u8,
}

fn default_max_hotp_attempts() -> u8 {
    5
}

impl Default for HotpConfig {
    fn default() -> Self {
        Self {
            secret: FactorSecret::Plain(crate::secret::ZeroizedString::new("")),
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
    // RFC 4226 §5.3 requires at least six digits; a shorter code is
    // brute-forceable in a handful of attempts, and a length of 0 makes the
    // code "0" match every counter.
    if !(MIN_OTP_DIGITS..=MAX_HOTP_DIGITS).contains(&length) {
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
    // `checked_add` guards against `counter + window` overflowing near
    // `u64::MAX`: debug builds would panic, release builds would silently
    // wrap to 0 and compare against the counter-0 code, a real
    // authentication bypass under adversarial inputs. On overflow we
    // stop iterating; matched stays whatever it was on prior iterations.
    let mut matched: Option<u64> = None;
    // Compare numbers, not strings: the supplied code is read once, and each
    // window step is a `u64` rather than a freshly allocated padded string.
    // A code is `length` ASCII digits and nothing else (a sign or a space
    // would otherwise parse), so equal values mean equal padded codes.
    let trimmed_code = code.trim();
    let supplied = (trimmed_code.len() == length
        && trimmed_code.bytes().all(|b| b.is_ascii_digit()))
    .then(|| trimmed_code.parse::<u64>().ok())
    .flatten();
    let supplied_value = supplied.unwrap_or(u64::MAX);
    for offset in 0..=window {
        let Some(candidate_counter) = counter.checked_add(offset) else {
            break;
        };
        let expected = hotp_value(&secret_bytes, candidate_counter, length, algorithm);
        let is_match = supplied.is_some() && bool::from(expected.ct_eq(&supplied_value));
        if is_match && matched.is_none() {
            matched = Some(candidate_counter);
        }
    }

    matched
}

/// Generate an HOTP code per RFC 4226 as a zero-padded decimal string.
#[cfg(test)]
pub(crate) fn hotp_generate(
    secret: &[u8],
    counter: u64,
    digits: usize,
    algorithm: HotpAlgorithm,
) -> String {
    format!(
        "{:0>width$}",
        hotp_value(secret, counter, digits, algorithm),
        width = digits,
    )
}

/// The HOTP code per RFC 4226 as a number below `10^digits`.
///
/// 1. HMAC(secret, counter_be_bytes) → digest (length depends on algorithm)
/// 2. Dynamic truncation → 31-bit integer
/// 3. Modulo 10^digits
///
/// Supports SHA-1 (RFC 4226), SHA-256, and SHA-512 variants.
fn hotp_value(secret: &[u8], counter: u64, digits: usize, algorithm: HotpAlgorithm) -> u64 {
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
    u64::from(binary) % modulus
}

#[cfg(test)]
mod tests;
