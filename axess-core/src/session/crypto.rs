//! AES-256-GCM encryption for session data at rest.
//!
//! Shared between the Valkey and SQLite session stores. Each encrypted payload
//! is prefixed with a random 12-byte nonce.
//!
//! # Key rotation
//!
//! [`SessionCrypto`] accepts an optional previous key. On decrypt, the current
//! key is tried first; if it fails, the previous key is attempted. Writes always
//! use the current key. A row sealed under the previous key is re-sealed only
//! when it is next written: reading it does not rewrite it, so a row that is
//! only ever read stays under the previous key until it expires. Keep the
//! previous key configured for at least one session lifetime after the
//! rotation, and retire it after that.
//!
//! # Blobs from before row binding
//!
//! Every blob the stores write names the row it belongs to in its AAD (the
//! additional authenticated data of the AES-GCM seal). A blob written by an earlier release carries no marker
//! and no binding, so it opens under any row id, which is exactly what an
//! attacker with write access to the store (or a restored backup) needs to
//! move a sealed row from one id to another. [`LegacyBlobs`] says what to do
//! with such blobs: [`Accept`](LegacyBlobs::Accept), the default, reads them
//! and the stores re-seal them in the bound format the next time the row is
//! written; [`Reject`](LegacyBlobs::Reject) refuses them, which a deployment
//! sets once its rows have aged out (one session lifetime after the upgrade,
//! for sessions). Reject fails closed: a refused row reads as a
//! decryption failure and the user signs in again.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
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

/// Whether blobs written before row binding (no marker, empty AAD) are read.
///
/// See the module documentation. Marked blobs are never affected: they are
/// always opened under their row's AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LegacyBlobs {
    /// Read a blob without the format marker under the empty AAD and let
    /// the store re-seal it in the bound format. The default, so an upgrade
    /// keeps existing rows readable.
    #[default]
    Accept,
    /// Refuse a blob without the format marker. Set it once no legacy rows
    /// remain; a row that is left reads as a decryption failure.
    Reject,
}

/// AES-256-GCM encryption configuration with optional key rotation.
#[derive(Clone)]
pub struct SessionCrypto {
    current: Arc<EncryptionKey>,
    previous: Option<Arc<EncryptionKey>>,
    rng: Arc<dyn SecureRng>,
    legacy: LegacyBlobs,
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
            legacy: LegacyBlobs::default(),
        }
    }

    /// Choose whether blobs written before row binding are read. See
    /// [`LegacyBlobs`]; the default is [`LegacyBlobs::Accept`].
    pub fn with_legacy_blobs(mut self, policy: LegacyBlobs) -> Self {
        self.legacy = policy;
        self
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
    #[deprecated(
        since = "0.11.0",
        note = "seals with an empty AAD, so the ciphertext is not bound to the row it is stored in; use `encrypt_with_aad` with the row identity"
    )]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt_unbound(plaintext)
    }

    /// Seal with an empty AAD. Kept for writing pre-binding fixtures; the
    /// public [`encrypt`](Self::encrypt) is deprecated in favour of
    /// [`encrypt_with_aad`](Self::encrypt_with_aad).
    pub(crate) fn encrypt_unbound(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt_with_aad(&[], plaintext)
    }

    /// Encrypt plaintext with AES-256-GCM, authenticating `aad` alongside it.
    /// Returns `nonce || ciphertext`. The same `aad` must be supplied to
    /// [`decrypt_with_aad`](Self::decrypt_with_aad); the AAD itself is not
    /// stored in the output.
    pub fn encrypt_with_aad(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.current.0).map_err(|_| CryptoError)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| CryptoError)?;

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt `nonce || ciphertext`. Tries the current key first, then the
    /// previous key (if configured) for key rotation support.
    #[deprecated(
        since = "0.11.0",
        note = "opens only ciphertext sealed with an empty AAD, which is not bound to its row; use `decrypt_with_aad` with the row identity"
    )]
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_unbound(data)
    }

    /// Open a pre-binding blob (empty AAD). Used only for the legacy read
    /// path of the bound formats.
    pub(crate) fn decrypt_unbound(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_with_aad(&[], data)
    }

    /// Decrypt `nonce || ciphertext` that was sealed with the same `aad`.
    /// Tries the current key first, then the previous key. A mismatched
    /// `aad` fails authentication exactly like a wrong key.
    pub fn decrypt_with_aad(&self, aad: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < NONCE_LEN {
            return Err(CryptoError);
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce_bytes).map_err(|_| CryptoError)?;

        let cipher = Aes256Gcm::new_from_slice(&self.current.0).map_err(|_| CryptoError)?;

        if let Ok(plaintext) = cipher.decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        ) {
            return Ok(plaintext);
        }

        if let Some(prev) = &self.previous {
            tracing::warn!(
                "session decryption failed with current key; trying previous key (rotation fallback)"
            );
            let old_cipher = Aes256Gcm::new_from_slice(&prev.0).map_err(|_| CryptoError)?;

            if let Ok(plaintext) = old_cipher.decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            ) {
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

/// A storage context whose encrypted blobs are bound to the row they live in.
///
/// A sealed blob is `magic || nonce || ciphertext`, where the AES-GCM
/// additional authenticated data is `label || 0x00 || row_id`. The row id is
/// not stored in the blob; it is supplied again on open, so a blob copied into
/// a row with a different id fails authentication. A row id made of several
/// parts is length-prefixed (see `device_row_id`) so two different part
/// lists can never concatenate to the same bytes.
#[derive(Clone, Copy)]
pub(crate) struct BoundFormat {
    /// Four-byte format marker written at the start of every sealed blob.
    magic: [u8; 4],
    /// Domain-separation label authenticated as part of the AAD.
    label: &'static [u8],
}

impl BoundFormat {
    /// Session data, bound to the session id.
    pub(crate) const SESSION: Self = Self {
        magic: *b"AXS\x01",
        label: b"axess.session.v1",
    };

    /// Device bindings, bound to the tenant and device id (length-prefixed).
    #[cfg(any(test, feature = "sqlite", feature = "postgres", feature = "mysql"))]
    pub(crate) const DEVICE_BINDINGS: Self = Self {
        magic: *b"AXD\x02",
        label: b"axess.device-bindings.v2",
    };

    /// The device-bindings format of 0.11.0: the tenant and device id were
    /// joined with a single zero byte. Still read, and replaced by
    /// [`DEVICE_BINDINGS`](Self::DEVICE_BINDINGS) on the next write.
    #[cfg(any(test, feature = "sqlite", feature = "postgres", feature = "mysql"))]
    pub(crate) const DEVICE_BINDINGS_V1: Self = Self {
        magic: *b"AXD\x01",
        label: b"axess.device-bindings.v1",
    };

    /// A whole device row in the Valkey store, bound to the tenant and
    /// device id (length-prefixed).
    #[cfg(any(test, feature = "valkey"))]
    pub(crate) const DEVICE_ROW: Self = Self {
        magic: *b"AXR\x02",
        label: b"axess.device-row.v2",
    };

    /// The device-row format of 0.11.0 (zero-byte joined ids). Still read.
    #[cfg(any(test, feature = "valkey"))]
    pub(crate) const DEVICE_ROW_V1: Self = Self {
        magic: *b"AXR\x01",
        label: b"axess.device-row.v1",
    };

    /// True when `data` starts with this format's marker.
    #[cfg(test)]
    pub(crate) fn marks(&self, data: &[u8]) -> bool {
        data.starts_with(&self.magic)
    }

    /// AAD bytes: `label || 0x00 || row_id`.
    pub(crate) fn aad(&self, row_id: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.label.len() + 1 + row_id.len());
        aad.extend_from_slice(self.label);
        aad.push(0);
        aad.extend_from_slice(row_id);
        aad
    }
}

/// Row identity of a device row: each of the tenant and device id as a
/// big-endian `u32` length followed by its UTF-8 bytes.
#[cfg(any(
    test,
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
pub(crate) fn device_row_id(tenant: &str, device: &str) -> Vec<u8> {
    let mut id = Vec::with_capacity(8 + tenant.len() + device.len());
    for part in [tenant, device] {
        id.extend_from_slice(&(part.len() as u32).to_be_bytes());
        id.extend_from_slice(part.as_bytes());
    }
    id
}

/// The row identity the 0.11.0 device formats bound: tenant and device id
/// joined with one zero byte. Kept only to read those rows.
#[cfg(any(
    test,
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
pub(crate) fn device_row_id_v1(tenant: &str, device: &str) -> Vec<u8> {
    let mut id = Vec::with_capacity(tenant.len() + 1 + device.len());
    id.extend_from_slice(tenant.as_bytes());
    id.push(0);
    id.extend_from_slice(device.as_bytes());
    id
}

/// Result of [`SessionCrypto::open_bound`].
pub(crate) struct Opened {
    /// The decrypted plaintext.
    pub(crate) plaintext: Vec<u8>,
    /// True when the blob is not in the current bound format: an earlier
    /// bound format, or no marker and no binding at all. The caller re-seals
    /// it.
    pub(crate) stale: bool,
}

impl SessionCrypto {
    /// Encrypt `plaintext` bound to `row_id`: `magic || nonce || ciphertext`
    /// with AAD `label || 0x00 || row_id` (see [`BoundFormat`]).
    pub(crate) fn seal_bound(
        &self,
        format: BoundFormat,
        row_id: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let body = self.encrypt_with_aad(&format.aad(row_id), plaintext)?;
        let mut out = Vec::with_capacity(format.magic.len() + body.len());
        out.extend_from_slice(&format.magic);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Open a blob for `row_id`.
    ///
    /// A blob that starts with the current format's marker is only ever tried
    /// under that format's AAD. A blob that starts with the marker of one of
    /// the `earlier` formats is tried under that format's AAD and the row id
    /// it paired with (an earlier release derived the id differently), and is
    /// flagged `stale`. A blob with none of these markers is a pre-binding
    /// blob: it is refused under [`LegacyBlobs::Reject`], and otherwise tried
    /// under the empty AAD and flagged `stale`. No marked blob ever falls
    /// back to the empty AAD.
    pub(crate) fn open_bound(
        &self,
        format: BoundFormat,
        row_id: &[u8],
        earlier: &[(BoundFormat, Vec<u8>)],
        data: &[u8],
    ) -> Result<Opened, CryptoError> {
        if let Some(body) = data.strip_prefix(&format.magic[..]) {
            return Ok(Opened {
                plaintext: self.decrypt_with_aad(&format.aad(row_id), body)?,
                stale: false,
            });
        }
        for (old, old_id) in earlier {
            if let Some(body) = data.strip_prefix(&old.magic[..]) {
                return Ok(Opened {
                    plaintext: self.decrypt_with_aad(&old.aad(old_id), body)?,
                    stale: true,
                });
            }
        }
        if self.legacy == LegacyBlobs::Reject {
            tracing::warn!("refusing a blob without a row binding (legacy blobs are rejected)");
            return Err(CryptoError);
        }
        Ok(Opened {
            plaintext: self.decrypt_unbound(data)?,
            stale: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let crypto = SessionCrypto::new([42u8; 32]);
        let plaintext = b"hello session data";
        let encrypted = crypto.encrypt_unbound(plaintext).unwrap();
        let decrypted = crypto.decrypt_unbound(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let crypto1 = SessionCrypto::new([1u8; 32]);
        let crypto2 = SessionCrypto::new([2u8; 32]);
        let encrypted = crypto1.encrypt_unbound(b"secret").unwrap();
        assert!(crypto2.decrypt_unbound(&encrypted).is_err());
    }

    #[test]
    fn key_rotation_decrypt_with_previous() {
        let old_key = [1u8; 32];
        let new_key = [2u8; 32];

        let old_crypto = SessionCrypto::new(old_key);
        let encrypted = old_crypto.encrypt_unbound(b"rotated data").unwrap();

        // New config with rotation: current = new_key, previous = old_key.
        let new_crypto = SessionCrypto::new(new_key).with_previous_key(old_key);
        let decrypted = new_crypto.decrypt_unbound(&encrypted).unwrap();
        assert_eq!(decrypted, b"rotated data");
    }

    #[test]
    fn short_data_fails() {
        let crypto = SessionCrypto::new([42u8; 32]);
        assert!(crypto.decrypt_unbound(&[0u8; 5]).is_err());
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
        let encrypted = crypto.encrypt_unbound(b"current-key data").unwrap();
        let decrypted = crypto.decrypt_unbound(&encrypted).unwrap();
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
        assert!(crypto.decrypt_unbound(&[0u8; NONCE_LEN]).is_err());
    }

    /// `with_previous_key` must store the supplied key in `previous`,
    /// not overwrite `current`. Pins the assignment direction.
    #[test]
    fn with_previous_key_does_not_replace_current_key() {
        let current = [3u8; 32];
        let prev = [4u8; 32];
        // Configure with prev, then encrypt; encryption uses CURRENT.
        let crypto = SessionCrypto::new(current).with_previous_key(prev);
        let encrypted = crypto.encrypt_unbound(b"under-current").unwrap();

        // A standalone instance keyed by `current` (no rotation) must
        // decrypt the ciphertext, proving encryption used `current`.
        let just_current = SessionCrypto::new(current);
        assert_eq!(
            just_current.decrypt_unbound(&encrypted).unwrap(),
            b"under-current"
        );

        // And an instance keyed only by `prev` must FAIL to decrypt;
        // confirming `with_previous_key` did not move `prev` into the
        // current slot.
        let just_prev = SessionCrypto::new(prev);
        assert!(just_prev.decrypt_unbound(&encrypted).is_err());
    }
}

#[cfg(test)]
mod bound_tests;
