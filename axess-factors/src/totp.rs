//! TOTP: Time-Based One-Time Passwords (RFC 6238).
//!
//! Time-stepped HOTP variant; pair with the application's session clock
//! so the `now` parameter passed to `verify_totp` is the same `Clock` the
//! rest of axess uses (production: `SystemClock`; tests: `MockClock`).
//!
//! Re-exports [`TotpAlgorithm`] and [`TOTP`] from `totp-rs` so applications
//! that hold the algorithm enum on a config struct don't need a direct
//! dependency on the upstream crate.

use crate::otp_algorithm::OtpAlgorithm;
use crate::secret::ZeroizedString;
use crate::{MAX_TOTP_DIGITS, MIN_OTP_SECRET_BYTES};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use totp_rs::{Algorithm as TotpAlgorithm, TOTP};

// ── TotpConfig ───────────────────────────────────────────────────────────────

/// TOTP factor configuration (RFC 6238).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Shared secret (raw bytes, base32-encoded for provisioning URIs). Zeroized on drop.
    pub secret: ZeroizedString,
    /// Number of digits in the generated code (typically 6).
    pub digits: u8,
    /// Length of one TOTP step in seconds (RFC 6238 default is 30).
    pub period_secs: u32,
    /// HMAC algorithm used for code derivation.
    pub algorithm: OtpAlgorithm,
    /// Number of past steps accepted to tolerate clock drift behind the server.
    pub past_window: u32,
    /// Number of future steps accepted to tolerate clock drift ahead of the server.
    pub future_window: u32,
    /// The last validated step counter; prevents code replay.
    pub last_step: Option<u64>,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret: ZeroizedString::new(""),
            digits: 6,
            period_secs: 30,
            algorithm: OtpAlgorithm::Sha1,
            past_window: 1,
            // Accept one step of forward clock drift by default.
            // Phones running a few seconds ahead of the server (very common
            //; NTP-synced phones drift forward across time-zone changes,
            // and the OS clock is often a few hundred ms ahead of the
            // server) would otherwise see "wrong code" rejections on
            // valid codes. Symmetric with `past_window: 1`.
            future_window: 1,
            last_step: None,
        }
    }
}

/// Default TOTP code length in decimal digits (RFC 6238 §1.2 recommended 6).
pub const TOTP_LENGTH: usize = 6;
/// Default TOTP time-step in seconds (RFC 6238 §5.2 recommended 30).
pub const TOTP_PERIOD: u64 = 30;

/// Maximum TOTP time-step window in either direction. Accepting codes from
/// more than 2 steps away (60s with a 30s period) significantly increases
/// replay risk. Values beyond this are silently clamped.
const MAX_TOTP_WINDOW: u64 = 2;

/// Tunable parameters for [`verify_totp`]. All fields are optional and fall
/// back to RFC 6238 defaults when set to `None`/`SHA1`.
#[derive(Debug, Clone, Copy)]
pub struct TotpVerifyParams {
    /// Number of digits in the TOTP code (default 6).
    pub length: Option<usize>,
    /// Time step in seconds (default 30).
    pub period: Option<u64>,
    /// Number of past time steps to also check (default 1).
    pub past_window: Option<u64>,
    /// Number of future time steps to also check (default 1).
    pub future_window: Option<u64>,
    /// HMAC algorithm (default SHA-1 per RFC 6238).
    pub algorithm: TotpAlgorithm,
}

impl Default for TotpVerifyParams {
    fn default() -> Self {
        Self {
            length: None,
            period: None,
            past_window: None,
            future_window: None,
            algorithm: TotpAlgorithm::SHA1,
        }
    }
}

/// Verify a TOTP code against a secret at a given time.
///
/// # Arguments
/// * `secret` - The shared secret used to generate the TOTP codes.
/// * `code` - The TOTP code to verify.
/// * `now` - Verification timestamp. Pass `clock.now()` (where `clock`
///   is an `axess_clock::Clock`) so DST tests can pin time by swapping
///   in a `MockClock`; production callers using `SystemClock` end up
///   with wall-clock semantics identical to the previous `SystemTime`
///   signature.
/// * `params` - Tunable parameters; use [`TotpVerifyParams::default`] for RFC 6238 defaults.
pub fn verify_totp(
    secret: &str,
    code: &str,
    now: chrono::DateTime<chrono::Utc>,
    params: TotpVerifyParams,
) -> Option<u64> {
    let TotpVerifyParams {
        length,
        period,
        past_window,
        future_window,
        algorithm,
    } = params;

    let sanitized_code = code.trim();
    if sanitized_code.is_empty() {
        return None;
    }

    let length = length.unwrap_or(TOTP_LENGTH);
    if length > MAX_TOTP_DIGITS {
        return None;
    }
    let time_step = period.unwrap_or(TOTP_PERIOD);
    // Clamp windows to a safe maximum. Accepting codes from more than 2
    // steps away (60s with 30s period) significantly increases replay risk.
    // Log when the configured window is silently clamped; operators
    // running legacy hardware tokens with larger drift specs would
    // otherwise see cryptic "wrong code" rejections with no signal that
    // their config is being narrowed at the verify call.
    let raw_past = past_window.unwrap_or(1);
    let raw_future = future_window.unwrap_or(1);
    if raw_past > MAX_TOTP_WINDOW {
        tracing::warn!(
            requested_past_window = raw_past,
            max = MAX_TOTP_WINDOW,
            "TOTP past_window clamped; codes from beyond the safe drift bound \
             will be rejected without further explanation; reduce past_window or \
             investigate the time-source skew on the hardware token"
        );
    }
    if raw_future > MAX_TOTP_WINDOW {
        tracing::warn!(
            requested_future_window = raw_future,
            max = MAX_TOTP_WINDOW,
            "TOTP future_window clamped; see past_window note"
        );
    }
    let past_window = raw_past.min(MAX_TOTP_WINDOW);
    let future_window = raw_future.min(MAX_TOTP_WINDOW);

    let secret_trimmed = secret.trim();
    // Wrap the uppercase copy in Zeroizing so it's cleared on drop.
    let secret_upper = Zeroizing::new(secret_trimmed.to_ascii_uppercase());
    let decoded = Zeroizing::new(
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret_upper)
            .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret_upper))
            .or_else(|| hex::decode(secret_trimmed).ok())?,
    );

    // Enforce RFC 4226 §4 R6 minimum secret length. A short
    // secret destroys brute-force resistance and must not be silently
    // accepted at verify time.
    if decoded.len() < MIN_OTP_SECRET_BYTES {
        return None;
    }

    // totp-rs stores the secret internally; pass a copy from the Zeroizing wrapper.
    // The TOTP struct is short-lived (dropped at end of this function).
    let totp = TOTP::new(algorithm, length, 0, time_step, decoded.to_vec()).ok()?;

    // Negative timestamps (pre-1970) cannot map to a TOTP step under
    // RFC 6238; reject rather than wrap silently into the future.
    let seconds: u64 = now.timestamp().try_into().ok()?;
    let current_step = seconds / time_step;

    let check_candidate = |step: u64| -> Option<u64> {
        let timestamp_secs = step.saturating_mul(time_step);
        let expected = totp.generate(timestamp_secs);
        if expected.as_bytes().ct_eq(sanitized_code.as_bytes()).into() {
            Some(step)
        } else {
            None
        }
    };

    if let Some(step) = check_candidate(current_step) {
        return Some(step);
    }

    for offset in 1..=future_window {
        if let Some(candidate_step) = current_step.checked_add(offset)
            && let Some(step) = check_candidate(candidate_step)
        {
            return Some(step);
        }
    }

    for offset in 1..=past_window {
        if let Some(candidate_step) = current_step.checked_sub(offset)
            && let Some(step) = check_candidate(candidate_step)
        {
            return Some(step);
        }
    }

    None
}

fn percent_encode_component(input: &str) -> String {
    const UNRESERVED: [u8; 66] =
        *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        if UNRESERVED.contains(&byte) {
            encoded.push(byte as char);
        } else {
            write!(&mut encoded, "%{:02X}", byte).expect("write! to String cannot fail");
        }
    }
    encoded
}

/// Generate a random 160-bit TOTP secret using the provided RNG, encoded
/// as base32 (RFC 4648, no padding).
///
/// Takes any `axess_rng::SecureRng`: pass `axess_rng::SystemRng` in
/// production for OS entropy, or `axess_rng::testing::MockRng` in tests
/// for deterministic simulation. Routing entropy through `SecureRng`
/// (rather than `rand::Rng` directly) is what keeps TOTP enrollment
/// paths DST-compatible across the whole axess stack.
pub fn generate_totp_secret<R: axess_rng::SecureRng>(rng: &R) -> String {
    let mut bytes = [0u8; 20];
    rng.fill_bytes(&mut bytes);
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
}

/// Build the standard `otpauth://totp/...` URI a TOTP authenticator app
/// scans to provision a credential. `label` and `issuer` are
/// percent-encoded per RFC 3986. `digits` is clamped to a minimum of 1
/// and `period` to a minimum of 5 seconds; values below those bounds
/// produce nonsensical authenticators.
pub fn build_totp_uri(
    label: &str,
    issuer: &str,
    secret: &str,
    digits: usize,
    period: u64,
) -> String {
    let label_enc = percent_encode_component(label);
    let issuer_enc = percent_encode_component(issuer);
    let digits = digits.max(1);
    let period = period.max(5);
    format!(
        "otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&digits={digits}&period={period}",
        issuer = issuer_enc,
        label = label_enc,
        secret = secret,
        digits = digits,
        period = period
    )
}

#[cfg(test)]
mod tests {
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
        let totp = TOTP::new(TotpAlgorithm::SHA1, 6, 0, 30, raw.to_vec()).unwrap();
        let t: u64 = 1_700_000_000;
        let code = totp.generate(t);
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
    /// RFC 6238 §1.2's 6..=8 digit range in `TOTP::new`.
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
}
