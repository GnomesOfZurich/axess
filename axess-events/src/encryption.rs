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

use crate::id::{EventId, TenantId};
use crate::kind::KindTag;
use crate::subject::{EventSubject, EventSubjectRef};

/// Reference to a key in a KMS / key registry. The envelope crate
/// stores only the id; key material lives wherever your KMS does.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct KeyId(ShortString);

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

/// Associated data to seal an [`EncryptedBlob`] under, binding the
/// ciphertext to the envelope it travels in.
///
/// An AEAD without associated data authenticates the payload and nothing
/// around it: a broker or store that can rewrite envelope metadata can move
/// a valid ciphertext into another event, tenant or subject and the
/// recipient decrypts it without complaint. Pass this value as the AAD when
/// sealing (`aes-gcm`'s and `chacha20poly1305`'s `Payload { msg, aad }`) and
/// again when opening, built from the envelope's own fields, and a blob moved
/// to any other id, kind, tenant or subject fails authentication.
///
/// The encoding is injective: every field is length-prefixed, an absent
/// tenant or subject is distinct from any present one, and a label and
/// version lead, so a future change to the field set cannot collide with
/// this one.
#[must_use]
pub fn envelope_aad(
    id: &EventId,
    kind: &KindTag,
    tenant: Option<&TenantId>,
    subject: Option<&EventSubject>,
) -> Vec<u8> {
    fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(bytes);
    }
    let mut buf = Vec::with_capacity(96);
    put(&mut buf, b"axess-events/envelope-aad/v1");
    put(&mut buf, id.as_bytes());
    put(&mut buf, kind.as_str().as_bytes());
    match tenant {
        Some(t) => {
            buf.push(1);
            put(&mut buf, t.as_bytes());
        }
        None => buf.push(0),
    }
    match subject.map(EventSubject::as_ref) {
        None => buf.push(0),
        Some(EventSubjectRef::User(u)) => {
            buf.push(1);
            put(&mut buf, u.as_bytes());
        }
        Some(EventSubjectRef::Tenant(t)) => {
            buf.push(2);
            put(&mut buf, t.as_bytes());
        }
        Some(EventSubjectRef::Device(d)) => {
            buf.push(3);
            put(&mut buf, d.as_bytes());
        }
        Some(EventSubjectRef::Session(s)) => {
            buf.push(4);
            put(&mut buf, s.as_bytes());
        }
        Some(EventSubjectRef::Other { kind, id }) => {
            buf.push(5);
            put(&mut buf, kind.as_bytes());
            put(&mut buf, id.as_bytes());
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::UserId;

    #[test]
    fn aad_differs_when_any_envelope_field_differs() {
        let id = EventId::NIL;
        let kind = KindTag::from_static("a.b.v1");
        let tenant = TenantId::from_bytes([1; 16]);
        let user = EventSubject::User(UserId::from_bytes([2; 16]));
        let base = envelope_aad(&id, &kind, Some(&tenant), Some(&user));

        let other_id = EventId::from_bytes([9; 16]);
        let other_kind = KindTag::from_static("a.b.v2");
        let other_tenant = TenantId::from_bytes([3; 16]);
        let other_user = EventSubject::User(UserId::from_bytes([4; 16]));
        let tenant_subject = EventSubject::Tenant(TenantId::from_bytes([2; 16]));

        for changed in [
            envelope_aad(&other_id, &kind, Some(&tenant), Some(&user)),
            envelope_aad(&id, &other_kind, Some(&tenant), Some(&user)),
            envelope_aad(&id, &kind, Some(&other_tenant), Some(&user)),
            envelope_aad(&id, &kind, None, Some(&user)),
            envelope_aad(&id, &kind, Some(&tenant), Some(&other_user)),
            envelope_aad(&id, &kind, Some(&tenant), None),
            // Same 16 bytes, different subject class.
            envelope_aad(&id, &kind, Some(&tenant), Some(&tenant_subject)),
        ] {
            assert_ne!(changed, base);
        }
        assert_eq!(
            envelope_aad(&id, &kind, Some(&tenant), Some(&user)),
            base,
            "deterministic"
        );
    }
}
