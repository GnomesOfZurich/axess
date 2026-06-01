//! HMAC algorithm choice shared by [`TotpConfig`](crate::totp::TotpConfig)
//! and [`HotpConfig`](crate::hotp::HotpConfig).
//!
//! Not collapsed with the verifier-internal [`TotpAlgorithm`](crate::totp::TotpAlgorithm)
//! and [`HotpAlgorithm`](crate::hotp::HotpAlgorithm); those are the
//! per-verifier algorithm tags (one a `totp-rs` re-export with `SHA1`
//! casing, the other a hand-rolled enum with `Sha1` casing). This enum
//! is the storage shape that round-trips through `FactorConfig` and the
//! adopter-facing JSON. Unifying the three is a separate concern.

use serde::{Deserialize, Serialize};

/// The HMAC algorithm used for OTP generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum OtpAlgorithm {
    /// HMAC-SHA1: the only algorithm guaranteed by RFC 6238 for interop.
    #[default]
    Sha1,
    /// HMAC-SHA256: supported by most modern authenticator apps.
    Sha256,
    /// HMAC-SHA512: supported by some authenticators.
    Sha512,
}
