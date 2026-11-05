//! TOTP: Time-Based One-Time Passwords (RFC 6238).
//!
//! Time-stepped HOTP variant; pair with the application's session clock
//! so the `now` parameter passed to `verify_totp` is the same `Clock` the
//! rest of axess uses (production: `SystemClock`; tests: `MockClock`).
//!
//! A TOTP code is the HOTP value of RFC 4226 at the counter
//! `floor(t / step)` (RFC 6238 §4.2); [`TotpAlgorithm`] names the HMAC.

use crate::factor_secret::FactorSecret;
use crate::otp_algorithm::OtpAlgorithm;
use crate::otp_core::{HotpAlgorithm, hotp_value};
use crate::{MAX_TOTP_DIGITS, MIN_OTP_DIGITS, MIN_OTP_SECRET_BYTES};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The HMAC a TOTP code is derived with (RFC 6238 §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1, the RFC default and what every authenticator app takes.
    SHA1,
    /// HMAC-SHA-256.
    SHA256,
    /// HMAC-SHA-512.
    SHA512,
}

impl TotpAlgorithm {
    /// The name `otpauth://` URIs carry in `algorithm=`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SHA1 => "SHA1",
            Self::SHA256 => "SHA256",
            Self::SHA512 => "SHA512",
        }
    }

    fn hotp(self) -> HotpAlgorithm {
        match self {
            Self::SHA1 => HotpAlgorithm::Sha1,
            Self::SHA256 => HotpAlgorithm::Sha256,
            Self::SHA512 => HotpAlgorithm::Sha512,
        }
    }
}

impl std::fmt::Display for TotpAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The TOTP code for the time `seconds` as a number below `10^digits`:
/// HOTP at the counter `seconds / step` (RFC 6238 §4.2).
fn totp_value(
    secret: &[u8],
    seconds: u64,
    step: u64,
    digits: usize,
    algorithm: TotpAlgorithm,
) -> u64 {
    hotp_value(secret, seconds / step, digits, algorithm.hotp())
}

// ── TotpConfig ───────────────────────────────────────────────────────────────

/// TOTP factor configuration (RFC 6238).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Shared secret (raw bytes, base32-encoded for provisioning URIs). Plain
    /// text is zeroized in memory on drop, redacted in `Debug`, and written to
    /// the store as it stands; seal it with a `FactorSecretCipher` to keep it
    /// encrypted at rest. See the OTP secret section of the password and TOTP
    /// guide.
    pub secret: FactorSecret,
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
            secret: FactorSecret::Plain(crate::secret::ZeroizedString::new("")),
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
    // RFC 6238 inherits RFC 4226's floor of six digits; a shorter code is
    // brute-forceable, and a zero period would divide by zero below.
    if !(MIN_OTP_DIGITS..=MAX_TOTP_DIGITS).contains(&length) {
        return None;
    }
    let time_step = period.unwrap_or(TOTP_PERIOD);
    if time_step == 0 {
        return None;
    }
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

    // Wrap the uppercase copy in Zeroizing so it's cleared on drop.
    let secret_upper = Zeroizing::new(secret.trim().to_ascii_uppercase());
    let decoded = Zeroizing::new(
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret_upper).or_else(
            || base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret_upper),
        )?,
    );

    // Enforce RFC 4226 §4 R6 minimum secret length. A short
    // secret destroys brute-force resistance and must not be silently
    // accepted at verify time.
    if decoded.len() < MIN_OTP_SECRET_BYTES {
        return None;
    }

    // Negative timestamps (pre-1970) cannot map to a TOTP step under
    // RFC 6238; reject rather than wrap silently into the future.
    let seconds: u64 = now.timestamp().try_into().ok()?;
    let current_step = seconds / time_step;

    let check_candidate = |step: u64| -> Option<u64> {
        let timestamp_secs = step.saturating_mul(time_step);
        // Zero-padded to `length`; compare with `ConstantTimeEq` to keep the
        // compare timing-safe.
        let expected = format!(
            "{:0>length$}",
            totp_value(&decoded, timestamp_secs, time_step, length, algorithm)
        );
        if bool::from(expected.as_bytes().ct_eq(sanitized_code.as_bytes())) {
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
    // The raw draw is the secret itself; wipe it once it is encoded.
    let mut bytes = Zeroizing::new([0u8; 20]);
    rng.fill_bytes(&mut *bytes);
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &*bytes)
}

/// The shortest period, in seconds, an `otpauth://` URI is built for.
const MIN_TOTP_URI_PERIOD: u64 = 5;

/// Build the standard `otpauth://totp/...` URI a TOTP authenticator app
/// scans to provision a credential, for an HMAC-SHA1 secret. `label` and
/// `issuer` are percent-encoded per RFC 3986.
///
/// Returns `None` when `digits` is outside the 6 to 8 range [`verify_totp`]
/// accepts or `period` is under 5 seconds (authenticator apps do not take a
/// shorter one): such a configuration is refused, not clamped into an
/// authenticator whose codes the server would verify with other parameters
/// than the ones shown to the user. See [`build_totp_uri_with_algorithm`] for
/// SHA-256 and SHA-512 secrets.
pub fn build_totp_uri(
    label: &str,
    issuer: &str,
    secret: &str,
    digits: usize,
    period: u64,
) -> Option<String> {
    build_totp_uri_with_algorithm(label, issuer, secret, digits, period, TotpAlgorithm::SHA1)
}

/// Like [`build_totp_uri`], with the HMAC algorithm written into the URI as
/// `algorithm=`, so an authenticator that honours it computes the same codes
/// the server verifies. Refuses (`None`) the configurations
/// [`build_totp_uri`] refuses.
pub fn build_totp_uri_with_algorithm(
    label: &str,
    issuer: &str,
    secret: &str,
    digits: usize,
    period: u64,
    algorithm: TotpAlgorithm,
) -> Option<String> {
    if !(MIN_OTP_DIGITS..=MAX_TOTP_DIGITS).contains(&digits) || period < MIN_TOTP_URI_PERIOD {
        return None;
    }
    let label_enc = percent_encode_component(label);
    let issuer_enc = percent_encode_component(issuer);
    Some(format!(
        "otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}",
        issuer = issuer_enc,
        label = label_enc,
        secret = secret,
        algorithm = algorithm.as_str(),
        digits = digits,
        period = period
    ))
}

#[cfg(test)]
mod tests;
