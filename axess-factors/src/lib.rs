#[cfg(feature = "hotp")]
pub use libreauth::oath::HOTPBuilder;
#[cfg(feature = "password")]
pub use password_auth::{generate_hash as generate_password_hash, verify_password};
#[cfg(feature = "totp")]
use rand::RngCore;
#[cfg(feature = "totp")]
use std::fmt::Write;
#[cfg(feature = "totp")]
use std::time::SystemTime;
#[cfg(feature = "hotp")]
use subtle::ConstantTimeEq;
#[cfg(feature = "totp")]
pub use totp_rs::{Algorithm as TotpAlgorithm, TOTP};
#[cfg(feature = "hotp")]
use zeroize::Zeroizing;

pub const HOTP_LENGTH: usize = 6;
pub const TOTP_LENGTH: usize = 6;
pub const TOTP_PERIOD: u64 = 30;

/// Verify a TOTP code against a secret at a given time.
///
/// # Arguments
/// * `secret` - The shared secret used to generate the TOTP codes.
/// * `code` - The TOTP code to verify.
/// * `now` - The current time to use for verification.
/// * `length` - The number of characters in the TOTP code.
/// * `period` - The time step in seconds (default is 30).
/// * `past_window` - The number of past time steps to check.
/// * `future_window` - The number of future time steps to check.
#[cfg(feature = "totp")]
pub fn verify_totp(
    secret: &str,
    code: &str,
    now: SystemTime,
    length: Option<usize>,
    period: Option<u64>,
    past_window: Option<u64>,
    future_window: Option<u64>,
) -> Option<u64> {
    use std::time::UNIX_EPOCH;

    let sanitized_code = code.trim();
    if sanitized_code.is_empty() {
        return None;
    }

    let length = length.unwrap_or(TOTP_LENGTH);
    let time_step = period.unwrap_or(TOTP_PERIOD);
    let past_window = past_window.unwrap_or(1);
    let future_window = future_window.unwrap_or(1);

    let secret_trimmed = secret.trim();
    let secret_upper = secret_trimmed.to_ascii_uppercase();
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret_upper)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret_upper))
        .or_else(|| hex::decode(secret_trimmed).ok())?;

    let totp = TOTP::new(TotpAlgorithm::SHA1, length, 0, time_step, decoded).ok()?;

    let seconds = now.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let current_step = seconds / time_step;

    let check_candidate = |step: u64| -> Option<u64> {
        let timestamp_secs = step.saturating_mul(time_step);
        let expected = totp.generate(timestamp_secs);
        if expected == sanitized_code {
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

/// Verify an HOTP code with a window of acceptable counter values.
///
/// # Arguments
/// * `secret` - The shared secret (base32 or hex encoded)
/// * `code` - The HOTP code to verify
/// * `counter` - The expected counter value
/// * `length` - Number of digits in the code
/// * `window` - Number of future counter values to check (0 = exact match only)
///
/// # Returns
/// `Some(used_counter)` if verification succeeds (the actual counter that matched),
/// `None` if verification fails
#[cfg(feature = "hotp")]
pub fn verify_hotp(
    secret: &str,
    code: &str,
    counter: u64,
    length: usize,
    window: u64,
) -> Option<u64> {
    // Normalize secret for base32 (uppercase, try with and without padding)
    let secret_trimmed = secret.trim();
    let secret_upper = secret_trimmed.to_ascii_uppercase();
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret_upper)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret_upper))
        .or_else(|| hex::decode(secret_trimmed).ok())?;

    // Wrap the owned bytes so they get zeroed on drop
    let secret_bytes = Zeroizing::new(decoded);

    // Try each counter value in the window
    for offset in 0..=window {
        let candidate_counter = counter + offset;

        let hotp = HOTPBuilder::new()
            .key(secret_bytes.as_ref()) // pass as slice
            .output_len(length)
            .counter(candidate_counter)
            .finalize();

        if let Ok(hotp) = hotp {
            let expected = hotp.generate();
            // constant-time compare to avoid timing leaks
            if expected.as_bytes().ct_eq(code.trim().as_bytes()).into() {
                return Some(candidate_counter);
            }
        }
    }

    None
}

#[cfg(feature = "totp")]
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

#[cfg(feature = "totp")]
pub fn generate_totp_secret() -> String {
    let mut bytes = [0u8; 20];
    rand::rng().fill_bytes(&mut bytes);
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
}

#[cfg(feature = "totp")]
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
