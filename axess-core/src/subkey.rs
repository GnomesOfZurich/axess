//! Per-record subkeys: the seal that is not bounded by the random-nonce limit.
//!
//! AES-GCM under one key with random 96-bit nonces must stay below about 2^32
//! seals (NIST SP 800-38D, section 8.3). A bound blob is instead sealed under
//! a key derived for that one record,
//!
//! ```text
//! subkey = HMAC-SHA256(key, "axess.subkey.v1" || 0x00 || salt || aad)
//! blob   = magic' || salt (16 bytes) || AES-256-GCM(subkey, nonce = 0, aad)
//! ```
//!
//! where `salt` is drawn fresh for every seal. The subkey encrypts exactly one
//! message, so a fixed nonce is safe and the per-key budget never applies; the
//! only collision that matters is two seals of one row id drawing the same
//! 128-bit salt. The record's AAD (format label and row id) is part of the
//! derivation, so a blob also opens only under the row it was sealed for.
//! The marker `magic'` is the format's marker with the top bit of its last
//! byte set, so a reader tells the two layouts apart before decrypting.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axess_rng::SecureRng;
use hmac::Mac;
use zeroize::Zeroizing;

/// The seal or open failed: a wrong key, row or salt, or a damaged blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SubkeyError;

/// Length of the per-record salt.
pub(crate) const SALT_LEN: usize = 16;

const DOMAIN: &[u8] = b"axess.subkey.v1";

/// The subkey for the record `(salt, aad)` under `key`.
pub(crate) fn derive(key: &[u8; 32], salt: &[u8], aad: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = crate::session::hmac::new_signer(key);
    mac.update(DOMAIN);
    mac.update(&[0]);
    mac.update(salt);
    mac.update(aad);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Seal `plaintext` as `salt || ciphertext` under a fresh subkey.
pub(crate) fn seal(
    key: &[u8; 32],
    rng: &dyn SecureRng,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SubkeyError> {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let subkey = derive(key, &salt, aad);
    let cipher = Aes256Gcm::new_from_slice(&subkey[..]).map_err(|_| SubkeyError)?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::default(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SubkeyError)?;
    let mut out = Vec::with_capacity(SALT_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open `salt || ciphertext` under `key`, or fail.
pub(crate) fn open(key: &[u8; 32], aad: &[u8], body: &[u8]) -> Result<Vec<u8>, SubkeyError> {
    if body.len() <= SALT_LEN {
        return Err(SubkeyError);
    }
    let (salt, ciphertext) = body.split_at(SALT_LEN);
    let subkey = derive(key, salt, aad);
    let cipher = Aes256Gcm::new_from_slice(&subkey[..]).map_err(|_| SubkeyError)?;
    cipher
        .decrypt(
            &Nonce::default(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SubkeyError)
}
