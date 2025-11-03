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
#[cfg(feature = "totp")]
pub fn verify_totp(secret: &str, code: &str, now: SystemTime, length: usize) -> bool {
    // Create TOTP safely and return false on any construction/check error
    match TOTP::new(
        TotpAlgorithm::SHA1,
        length,
        30,
        1,
        secret.as_bytes().to_vec(),
    ) {
        Ok(totp) => {
            let now_unix = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            totp.check(code, now_unix)
        }
        Err(_) => false,
    }
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
