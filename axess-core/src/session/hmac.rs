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

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

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

/// Finish `mac` into a 32-byte key.
///
/// For a derivation whose output is itself a key: the output is written
/// into a buffer that is zeroed on drop, and the HMAC output it is copied
/// from is zeroed before this returns, so the derivation leaves no plain
/// copy of the key where it ran.
pub(crate) fn finalize_key(mac: HmacSha256) -> Zeroizing<[u8; 32]> {
    let mut tag = mac.finalize().into_bytes();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&tag);
    tag.as_mut_slice().zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key a derivation finishes into is the HMAC output, in a buffer
    /// that wipes itself.
    #[test]
    fn a_derived_key_is_the_hmac_output_in_a_zeroizing_buffer() {
        let mut plain = new_signer(b"a key");
        plain.update(b"a label");
        let expected: [u8; 32] = plain.finalize().into_bytes().into();

        let mut mac = new_signer(b"a key");
        mac.update(b"a label");
        let key: Zeroizing<[u8; 32]> = finalize_key(mac);

        assert_eq!(*key, expected);
    }

    /// The hash states an HMAC keeps its key in, and the output it finishes
    /// into, wipe themselves when dropped: each carries the marker only with
    /// the `zeroize` feature of its crate on.
    #[test]
    fn the_keyed_hash_states_are_zeroed_on_drop() {
        fn zeroed_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroed_on_drop::<sha2::block_api::Sha256VarCore>();
        zeroed_on_drop::<sha1::block_api::Sha1Core>();
        zeroed_on_drop::<hmac::digest::CtOutput<HmacSha256>>();
    }
}
