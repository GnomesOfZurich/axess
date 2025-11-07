// #[cfg(feature = "hotp")]
// use base32;
// #[cfg(feature = "hotp")]
// use hex;
#[cfg(feature = "hotp")]
pub use libreauth::oath::HOTPBuilder;
#[cfg(feature = "password")]
pub use password_auth::{generate_hash as generate_password_hash, verify_password};
#[cfg(feature = "totp")]
use std::time::SystemTime;
#[cfg(feature = "hotp")]
use subtle::ConstantTimeEq;
#[cfg(feature = "totp")]
pub use totp_rs::{Algorithm as TotpAlgorithm, TOTP};
#[cfg(feature = "hotp")]
use zeroize::Zeroizing;

/// Verify a TOTP code against a secret at a given time.
///
/// # Arguments
/// * `secret` - The shared secret used to generate the TOTP codes.
/// * `code` - The TOTP code to verify.
/// * `now` - The current time to use for verification.
/// * `length` - The number of characters in the TOTP code.
/// * `past_window` - The number of past time steps to check.
/// * `future_window` - The number of future time steps to check.
#[cfg(feature = "totp")]
pub fn verify_totp(
    secret: &str,
    code: &str,
    now: SystemTime,
    length: usize,
    past_window: u64,
    future_window: u64,
) -> Option<u64> {
    use std::time::UNIX_EPOCH;

    let sanitized_code = code.trim();
    if sanitized_code.is_empty() {
        return None;
    }

    let secret_trimmed = secret.trim();
    let secret_upper = secret_trimmed.to_ascii_uppercase();
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret_upper)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret_upper))
        .or_else(|| hex::decode(secret_trimmed).ok())?;

    let totp = TOTP::new(TotpAlgorithm::SHA1, length, 0, 30, decoded).ok()?;

    let seconds = now.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let current_step = seconds / 30;

    let check_candidate = |step: u64| -> Option<u64> {
        let timestamp_secs = step.saturating_mul(30);
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
