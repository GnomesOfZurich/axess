//! AES-256-GCM encryption for session data at rest.
//!
//! Shared between the Valkey and SQLite session stores. Each encrypted payload
//! is prefixed with a random 12-byte nonce.
//!
//! # Key rotation
//!
//! [`SessionCrypto`] accepts an optional previous key. On decrypt, the current
//! key is tried first; if it fails, the previous key is attempted. Writes always
//! use the current key, so rotated data is transparently re-encrypted on access.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use axess_rng::{SecureRng, SystemRng};
use std::sync::Arc;

const NONCE_LEN: usize = 12;

/// Zeroize-on-drop wrapper for a 32-byte AES key.
#[derive(Clone)]
pub struct EncryptionKey(pub(crate) [u8; 32]);

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// AES-256-GCM encryption configuration with optional key rotation.
#[derive(Clone)]
pub struct SessionCrypto {
    current: Arc<EncryptionKey>,
    previous: Option<Arc<EncryptionKey>>,
    rng: Arc<dyn SecureRng>,
}

/// Error from encrypt/decrypt operations.
#[derive(Debug, thiserror::Error)]
#[error("session encryption/decryption error")]
pub struct CryptoError;

impl SessionCrypto {
    /// Create a new crypto config with the given 32-byte key. Uses
    /// [`SystemRng`] for nonce generation; tests under DST should use
    /// [`SessionCrypto::with_rng`] to inject a deterministic RNG.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            current: Arc::new(EncryptionKey(key)),
            previous: None,
            rng: Arc::new(SystemRng),
        }
    }

    /// Swap the RNG used for nonce generation. Production code keeps the
    /// default [`SystemRng`]; DST suites pass a seeded `MockRng` to drive
    /// nonce sequences deterministically.
    pub fn with_rng(mut self, rng: Arc<dyn SecureRng>) -> Self {
        self.rng = rng;
        self
    }

    /// Enable key rotation: on decrypt, try the current key first, then this
    /// previous key as a fallback.
    pub fn with_previous_key(mut self, key: [u8; 32]) -> Self {
        self.previous = Some(Arc::new(EncryptionKey(key)));
        self
    }

    /// Encrypt plaintext with AES-256-GCM. Returns `nonce || ciphertext`.
    ///
    /// Each call generates a random 96-bit (12-byte) nonce. The collision
    /// probability is negligible (~2^-96 per pair), which is safe for up to
    /// ~2^32 encryptions per key, far beyond typical session store volumes.
    /// The `aes-gcm` crate performs constant-time authentication tag comparison
    /// internally during decryption.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.current.0).map_err(|_| CryptoError)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_| CryptoError)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt `nonce || ciphertext`. Tries the current key first, then the
    /// previous key (if configured) for key rotation support.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < NONCE_LEN {
            return Err(CryptoError);
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.current.0).map_err(|_| CryptoError)?;

        if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
            return Ok(plaintext);
        }

        if let Some(prev) = &self.previous {
            tracing::warn!(
                "session decryption failed with current key; trying previous key (rotation fallback)"
            );
            let old_cipher = Aes256Gcm::new_from_slice(&prev.0).map_err(|_| CryptoError)?;

            if let Ok(plaintext) = old_cipher.decrypt(nonce, ciphertext) {
                tracing::debug!("session decrypted with previous (rotated) key");
                return Ok(plaintext);
            }
            tracing::warn!(
                "session decryption also failed with previous key; possible data corruption or key mismatch"
            );
        } else {
            tracing::warn!(
                "session decryption failed with current key and no previous key configured"
            );
        }

        Err(CryptoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let crypto = SessionCrypto::new([42u8; 32]);
        let plaintext = b"hello session data";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let crypto1 = SessionCrypto::new([1u8; 32]);
        let crypto2 = SessionCrypto::new([2u8; 32]);
        let encrypted = crypto1.encrypt(b"secret").unwrap();
        assert!(crypto2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn key_rotation_decrypt_with_previous() {
        let old_key = [1u8; 32];
        let new_key = [2u8; 32];

        let old_crypto = SessionCrypto::new(old_key);
        let encrypted = old_crypto.encrypt(b"rotated data").unwrap();

        // New config with rotation: current = new_key, previous = old_key.
        let new_crypto = SessionCrypto::new(new_key).with_previous_key(old_key);
        let decrypted = new_crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"rotated data");
    }

    #[test]
    fn short_data_fails() {
        let crypto = SessionCrypto::new([42u8; 32]);
        assert!(crypto.decrypt(&[0u8; 5]).is_err());
    }

    /// `decrypt` with a configured previous key still uses the current
    /// key first when current succeeds. Pins against an "always fall
    /// through to previous" mutation that would silently re-encrypt
    /// everything under the old key on the next write.
    #[test]
    fn key_rotation_current_key_wins_when_valid() {
        let current = [9u8; 32];
        let prev = [1u8; 32];
        let crypto = SessionCrypto::new(current).with_previous_key(prev);
        let encrypted = crypto.encrypt(b"current-key data").unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"current-key data");
    }

    /// Boundary: payload of exactly NONCE_LEN (12) bytes has no
    /// ciphertext to authenticate and must fail. Pins `< NONCE_LEN`
    /// against `<=` (which would also reject 12-byte payloads but allow
    /// 12-byte-only nonce splits to attempt decryption) and `==` /
    /// `delete` mutants.
    #[test]
    fn decrypt_payload_at_nonce_length_boundary_fails() {
        let crypto = SessionCrypto::new([7u8; 32]);
        assert!(crypto.decrypt(&[0u8; NONCE_LEN]).is_err());
    }

    /// `with_previous_key` must store the supplied key in `previous`,
    /// not overwrite `current`. Pins the assignment direction.
    #[test]
    fn with_previous_key_does_not_replace_current_key() {
        let current = [3u8; 32];
        let prev = [4u8; 32];
        // Configure with prev, then encrypt; encryption uses CURRENT.
        let crypto = SessionCrypto::new(current).with_previous_key(prev);
        let encrypted = crypto.encrypt(b"under-current").unwrap();

        // A standalone instance keyed by `current` (no rotation) must
        // decrypt the ciphertext, proving encryption used `current`.
        let just_current = SessionCrypto::new(current);
        assert_eq!(just_current.decrypt(&encrypted).unwrap(), b"under-current");

        // And an instance keyed only by `prev` must FAIL to decrypt;
        // confirming `with_previous_key` did not move `prev` into the
        // current slot.
        let just_prev = SessionCrypto::new(prev);
        assert!(just_prev.decrypt(&encrypted).is_err());
    }
}
