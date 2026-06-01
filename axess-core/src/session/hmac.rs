//! HMAC-SHA256 type alias and constructor shared across session-bound
//! HMAC users:
//!
//! - `crate::session::binding`: fingerprint HMAC over UA / IP material.
//! - `crate::session::layer`: cookie HMAC + HKDF sub-key derivation.
//! - `crate::session::refresh`: refresh-token pepper hashing.
//! - `crate::middleware::csrf`: CSRF token signing.
//! - `crate::device::fingerprint`: device-fingerprint pepper hashing.
//!
//! `new_signer` centralises the `new_from_slice(...).expect(...)` init
//! so the panic message is identical at every site and a future change
//! (e.g. tightening to a typed key newtype) lands in one place.

use hmac::{Hmac, KeyInit};
use sha2::Sha256;

/// HMAC-SHA256 instantiated for axess.
pub(crate) type HmacSha256 = Hmac<Sha256>;

/// Initialise an [`HmacSha256`] for the given key.
///
/// HMAC accepts keys of any length, so `new_from_slice` only fails on
/// internal mismatch; the `.expect` is unreachable on every supported
/// platform. Centralising the init guarantees the panic message is
/// identical at every call site.
pub(crate) fn new_signer(key: &[u8]) -> HmacSha256 {
    HmacSha256::new_from_slice(key).expect("HMAC accepts any key length")
}
