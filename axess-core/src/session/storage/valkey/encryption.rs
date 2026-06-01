//! Encryption-at-rest plumbing for the Valkey session backend.
//!
//! The primitive AES-256-GCM round-trip and key-rotation logic lives in
//! [`SessionCrypto`](crate::session::crypto::SessionCrypto), and the
//! MessagePack + AES-GCM combined encode/decode pipeline lives in
//! [`SessionCodec`](crate::session::storage::session_codec::SessionCodec):
//! the same codec contract the SQL backends use, so all three encrypted
//! backends share one implementation.
//!
//! This module exposes thin factory helpers so the
//! [`ValkeySessionStore`](super::ValkeySessionStore) constructors can
//! build a codec without spreading codec/crypto wiring details across
//! the store module.

use crate::session::crypto::SessionCrypto;
use crate::session::storage::session_codec::SessionCodec;

/// Build a [`SessionCodec`] configured for AES-256-GCM encryption at
/// rest with the given 32-byte key.
pub(super) fn encrypted_codec(key: [u8; 32]) -> SessionCodec {
    SessionCodec::encrypted(SessionCrypto::new(key))
}

/// Build a [`SessionCodec`] configured for AES-256-GCM encryption at
/// rest with key-rotation support: writes use `current_key`, reads try
/// `current_key` first and fall back to `previous_key` if decryption
/// fails.
pub(super) fn encrypted_codec_with_rotation(
    current_key: [u8; 32],
    previous_key: [u8; 32],
) -> SessionCodec {
    SessionCodec::encrypted(SessionCrypto::new(current_key).with_previous_key(previous_key))
}

/// Build a [`SessionCodec`] that stores session data unencrypted
/// (development / testing only).
pub(super) fn plaintext_codec() -> SessionCodec {
    SessionCodec::plaintext()
}
