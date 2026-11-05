//! The HOTP computation (RFC 4226) that both [`hotp`](crate::hotp) and
//! [`totp`](crate::totp) stand on: RFC 6238 is this function applied to a
//! time step.

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

/// The HOTP code per RFC 4226 as a number below `10^digits`.
///
/// 1. HMAC(secret, counter_be_bytes) → digest (length depends on algorithm)
/// 2. Dynamic truncation → 31-bit integer
/// 3. Modulo 10^digits
///
/// Supports SHA-1 (RFC 4226), SHA-256, and SHA-512 variants.
pub(crate) fn hotp_value(
    secret: &[u8],
    counter: u64,
    digits: usize,
    algorithm: HotpAlgorithm,
) -> u64 {
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
