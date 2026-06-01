//! Payload-level encryption primitives.
//!
//! The envelope itself does not enforce encryption. Producers that
//! want broker-opaque payloads wrap their value in an [`EncryptedBlob`]
//! and place it in [`EventBody::Encrypted`](crate::EventBody::Encrypted);
//! subscribers without the key still see envelope metadata (id,
//! kind, time, tenant, subject, actor, status) for routing and
//! auditing without ever decrypting the payload contents.
//!
//! Field-level tokenization for sensitive data inside an otherwise
//! clear payload (PAN, email, factor secrets) is handled separately
//! by axess's `PiiToken` / `DevicePiiStore` primitives; orthogonal
//! to the envelope's encryption choice.

use axess_strings::ShortString;

/// Reference to a key in a KMS / key registry. The envelope crate
/// stores only the id; key material lives wherever your KMS does.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct KeyId(pub ShortString);

impl KeyId {
    /// Construct from any string slice.
    #[inline]
    pub fn new(s: &str) -> Self {
        Self(ShortString::new(s))
    }

    /// Construct from a `&'static str` without allocating.
    #[inline]
    pub const fn from_static(s: &'static str) -> Self {
        Self(ShortString::from_static(s))
    }

    /// Borrow as `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// AEAD algorithm identifier on an encrypted payload. Two values
/// today; extend via a new variant + `envelope_version` bump when a
/// third is added.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AeadAlgorithm {
    /// AES-256 in GCM mode (NIST SP 800-38D). Hardware-accelerated on
    /// most modern CPUs.
    Aes256Gcm,
    /// ChaCha20 with Poly1305 (RFC 8439). Constant-time without
    /// dedicated hardware; preferred on platforms lacking AES-NI.
    ChaCha20Poly1305,
}

/// Encrypted payload bytes. Replaces a clear payload in the
/// [`EventBody`](crate::EventBody) for events that should remain
/// opaque to brokers and unauthorised subscribers.
///
/// Decryption produces the plaintext bytes; the recipient knows what
/// type to deserialise as via the envelope's
/// [`kind`](crate::Event::kind) field.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedBlob {
    /// KMS reference for the key the payload was encrypted under.
    pub key_id: KeyId,
    /// AEAD algorithm in use.
    pub algorithm: AeadAlgorithm,
    /// AEAD nonce (96 bits; standard for both supported algorithms).
    pub nonce: [u8; 12],
    /// Authenticated ciphertext, including the AEAD tag.
    pub ciphertext: Vec<u8>,
}
