//! Payload-level encryption primitives.
//!
//! The envelope itself does not enforce encryption. Producers that
//! want broker-opaque payloads wrap their value in an [`EncryptedBlob`]
//! and place it in [`EventBody::Encrypted`];
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
use crate::kind::{EventPayload, KindTag};
use crate::status::EventStatus;
use crate::subject::{EventSubject, EventSubjectRef};
use crate::trace::TraceContext;
use crate::{Event, EventBody};

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
/// [`EventBody`] for events that should remain
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
///
/// This is the first AAD tag and authenticates only the four fields above.
/// The event's `status`, `actor`, `time_micros`, `envelope_version` and
/// `trace_context`, and the blob's `algorithm` and `key_id`, are not bound:
/// someone who can write the store but holds no key can change them and the
/// payload still decrypts. It is deprecated for sealing: seal new events
/// under [`envelope_aad_for`] (or [`envelope_aad_v2`]), and open any event
/// with [`open_aads_for`], which tries the second tag first and this one
/// second. This crate does no sealing itself; the AAD an adopter's seal path
/// passes is the AAD it asks one of these functions for.
///
/// # Panics
///
/// If a field is longer than `u32::MAX` bytes: a length that saturated
/// would let two different oversized fields share one encoding.
#[deprecated(
    since = "0.18.0",
    note = "binds only id, kind, tenant and subject; seal under `envelope_aad_for` and open with `open_aads_for`"
)]
#[must_use]
pub fn envelope_aad(
    id: &EventId,
    kind: &KindTag,
    tenant: Option<&TenantId>,
    subject: Option<&EventSubject>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);
    put(&mut buf, b"axess-events/envelope-aad/v1");
    put(&mut buf, id.as_bytes());
    put(&mut buf, kind.as_str().as_bytes());
    put_tenant(&mut buf, tenant);
    put_subject(&mut buf, subject);
    buf
}

/// Every envelope field a reader acts on, for [`envelope_aad_v2`].
///
/// A producer that is about to seal a payload has these in hand (the key and
/// algorithm it chose, the event it is building); a reader that holds a
/// stored [`Event`] with an [`EventBody::Encrypted`] body gets the same value
/// from [`envelope_aad_for`].
#[derive(Clone, Copy, Debug)]
pub struct EnvelopeFields<'a> {
    /// The event id.
    pub id: &'a EventId,
    /// The envelope schema version, as in [`Event::envelope_version`].
    pub envelope_version: u8,
    /// Microseconds since the Unix epoch, as in [`Event::time_micros`].
    pub time_micros: i64,
    /// The tenant scope.
    pub tenant: Option<&'a TenantId>,
    /// The kind tag.
    pub kind: &'a KindTag,
    /// Who the event is about.
    pub subject: Option<&'a EventSubject>,
    /// Who initiated the event.
    pub actor: Option<&'a EventSubject>,
    /// The W3C trace context.
    pub trace_context: Option<&'a TraceContext>,
    /// The outcome bucket.
    pub status: EventStatus,
    /// The key the payload is sealed under.
    pub key_id: &'a KeyId,
    /// The AEAD algorithm the payload is sealed with.
    pub algorithm: AeadAlgorithm,
}

/// Associated data under the second AAD tag: [`envelope_aad`]'s fields and
/// every other envelope field a reader acts on (status, actor, time,
/// envelope version, trace context, and the blob's algorithm and key id).
///
/// With [`envelope_aad`] alone, someone who can write the event store but
/// holds no key can rewrite `status`, `actor` or `time_micros` and the
/// payload still decrypts: the audit record reads differently from what was
/// written. Sealed under this value, a changed field fails authentication.
///
/// The encoding is injective in the same way as [`envelope_aad`]'s and leads
/// with its own label (`axess-events/envelope-aad/v2`), so a v1 and a v2
/// value never collide. Events sealed under the first tag stay readable: a
/// reader tries [`envelope_aad_for`] first and [`envelope_aad`] second, and
/// accepts a v1 success knowing that only the v1 fields were authenticated.
///
/// # Panics
///
/// If a field is longer than `u32::MAX` bytes, as for [`envelope_aad`].
#[must_use]
pub fn envelope_aad_v2(fields: &EnvelopeFields<'_>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160);
    put(&mut buf, b"axess-events/envelope-aad/v2");
    put(&mut buf, fields.id.as_bytes());
    buf.push(fields.envelope_version);
    buf.extend_from_slice(&fields.time_micros.to_be_bytes());
    put(&mut buf, fields.kind.as_str().as_bytes());
    put_tenant(&mut buf, fields.tenant);
    put_subject(&mut buf, fields.subject);
    put_subject(&mut buf, fields.actor);
    match fields.trace_context {
        None => buf.push(0),
        Some(t) => {
            buf.push(1);
            buf.extend_from_slice(&t.trace_id);
            buf.extend_from_slice(&t.span_id);
            buf.push(t.flags);
        }
    }
    buf.push(match fields.status {
        EventStatus::Success => 1,
        EventStatus::Failure => 2,
        EventStatus::Info => 3,
    });
    put(&mut buf, fields.key_id.as_str().as_bytes());
    buf.push(match fields.algorithm {
        AeadAlgorithm::Aes256Gcm => 1,
        AeadAlgorithm::ChaCha20Poly1305 => 2,
    });
    buf
}

/// The second-tag associated data of a stored event, read from the event's
/// own fields and its blob. `None` when the body is
/// [`EventBody::Clear`]: there is no ciphertext to open.
///
/// To read an event of either generation, open the blob under this value
/// and, if that fails, under [`envelope_aad`] built from the same event.
#[must_use]
pub fn envelope_aad_for<P: EventPayload>(event: &Event<P>) -> Option<Vec<u8>> {
    let EventBody::Encrypted(blob) = &event.body else {
        return None;
    };
    Some(envelope_aad_v2(&EnvelopeFields {
        id: &event.id,
        envelope_version: event.envelope_version,
        time_micros: event.time_micros,
        tenant: event.tenant_id.as_ref(),
        kind: &event.kind,
        subject: event.subject.as_ref(),
        actor: event.actor.as_ref(),
        trace_context: event.trace_context.as_ref(),
        status: event.status,
        key_id: &blob.key_id,
        algorithm: blob.algorithm,
    }))
}

/// The associated data to try, in order, when opening an encrypted event:
/// the second tag, then the first for events sealed before the second
/// existed. `None` when the body is [`EventBody::Clear`].
///
/// A success under the first entry means every field a reader acts on was
/// authenticated. A success under the second authenticated only id, kind,
/// tenant and subject, as it did when the event was sealed.
#[must_use]
pub fn open_aads_for<P: EventPayload>(event: &Event<P>) -> Option<[Vec<u8>; 2]> {
    let v2 = envelope_aad_for(event)?;
    #[allow(deprecated)]
    let v1 = envelope_aad(
        &event.id,
        &event.kind,
        event.tenant_id.as_ref(),
        event.subject.as_ref(),
    );
    Some([v2, v1])
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = field_len(bytes.len()).expect("an AAD field is longer than u32::MAX bytes");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn put_tenant(buf: &mut Vec<u8>, tenant: Option<&TenantId>) {
    match tenant {
        Some(t) => {
            buf.push(1);
            put(buf, t.as_bytes());
        }
        None => buf.push(0),
    }
}

fn put_subject(buf: &mut Vec<u8>, subject: Option<&EventSubject>) {
    match subject.map(EventSubject::as_ref) {
        None => buf.push(0),
        Some(EventSubjectRef::User(u)) => {
            buf.push(1);
            put(buf, u.as_bytes());
        }
        Some(EventSubjectRef::Tenant(t)) => {
            buf.push(2);
            put(buf, t.as_bytes());
        }
        Some(EventSubjectRef::Device(d)) => {
            buf.push(3);
            put(buf, d.as_bytes());
        }
        Some(EventSubjectRef::Session(s)) => {
            buf.push(4);
            put(buf, s.as_bytes());
        }
        Some(EventSubjectRef::Other { kind, id }) => {
            buf.push(5);
            put(buf, kind.as_bytes());
            put(buf, id.as_bytes());
        }
    }
}

/// The length prefix of an AAD field, or `None` when it does not fit.
fn field_len(len: usize) -> Option<u32> {
    u32::try_from(len).ok()
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::id::UserId;

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn a_field_over_four_gib_has_no_length_prefix() {
        assert_eq!(field_len(u32::MAX as usize), Some(u32::MAX));
        assert_eq!(field_len(u32::MAX as usize + 1), None);
    }

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
