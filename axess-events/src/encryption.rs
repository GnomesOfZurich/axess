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

use std::time::SystemTime;

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

/// Associated data to seal an [`EncryptedBlob`] under, binding the
/// ciphertext to the envelope it travels in: the second AAD tag.
///
/// An AEAD without associated data authenticates the payload and nothing
/// around it: a broker or store that can rewrite envelope metadata can move
/// a valid ciphertext into another event, tenant or subject and the
/// recipient decrypts it without complaint. Pass this value as the AAD when
/// sealing (`aes-gcm`'s and `chacha20poly1305`'s `Payload { msg, aad }`) and
/// again when opening, built from the envelope's own fields, and a blob
/// whose event was changed in any field a reader acts on fails
/// authentication: the id, kind, tenant and subject, and the status, actor,
/// time, envelope version, trace context, and the blob's algorithm and key
/// id. This crate does no sealing itself; the AAD an adopter's seal path
/// passes is the AAD it asks this function, or [`envelope_aad_for`], for.
///
/// The encoding is injective: every field is length-prefixed, an absent
/// tenant, subject, actor or trace context is distinct from any present one,
/// and a label and version lead (`axess-events/envelope-aad/v2`), so a
/// future change to the field set cannot collide with this one.
///
/// The first tag, which events sealed before 0.18.0 carry, bound only the
/// id, kind, tenant and subject: someone who can write the event store but
/// holds no key can rewrite the `status`, `actor` or `time_micros` of such
/// an event and the payload still decrypts. Nothing seals under it any
/// more, and a reader refuses it unless it names the opt-in: see
/// [`FirstTag`] and [`open_aads_for`].
///
/// # Panics
///
/// If a field is longer than `u32::MAX` bytes: a length that saturated
/// would let two different oversized fields share one encoding.
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
/// Seal under this value, and open under it: it is the only associated
/// data a reader tries by default. A reader that still holds events sealed
/// under the first tag names that with [`FirstTag`] and opens with the
/// values [`open_aads_for`] lists.
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

/// Whether a reader tries the first AAD tag, which authenticated only id,
/// kind, tenant and subject, when the second fails.
///
/// The default is [`Reject`](Self::Reject): only an event sealed under the
/// second tag opens. An event sealed under the first tag can have its
/// status, actor or time rewritten at rest and still open under it, so a
/// reader that accepts the first tag accepts such a rewrite, and says so by
/// name: [`Accept`](Self::Accept), or [`AcceptUntil`](Self::AcceptUntil)
/// with the instant the acceptance ends. The cutoff is on the reader's
/// clock, not the event's own time: the first tag does not authenticate the
/// event's time, so a cutoff on it would be rewritten with the field it is
/// meant to protect. Both the cutoff and the reader's clock are a
/// [`SystemTime`], not a number: a count of seconds read against a cutoff
/// in microseconds would have accepted the first tag for good.
///
/// # Events sealed under the first tag
///
/// Releases before 0.18.0 sealed under the first tag. This crate computes
/// associated data and holds neither a key nor a store, so it cannot move
/// such events to the second tag; the process that holds the key does, once,
/// before its readers run under the default:
///
/// 1. Read each stored event whose body is [`EventBody::Encrypted`] and open
///    it with the values `open_aads_for(&event, FirstTag::Accept, now)`
///    lists, in order.
/// 2. An event that opens under the first value is sealed under the second
///    tag already; leave it.
/// 3. An event that opens only under the second value was sealed under the
///    first tag: seal its plaintext again under [`envelope_aad_for`] with a
///    fresh nonce and write the event back.
/// 4. An event that opens under neither is damaged or was sealed under
///    another key; it is not a first-tag event and the pass does not fix it.
///
/// The re-seal binds the fields as the store holds them at that moment. It
/// cannot show that a status, an actor or a time is the one originally
/// written, since the first tag never authenticated them; it stops them
/// changing unnoticed from then on. Events past retention need no pass.
/// While writers of an earlier release still seal under the first tag (a
/// rolling upgrade), readers name [`AcceptUntil`](Self::AcceptUntil) with
/// the end of that window and the pass runs after the last such writer is
/// gone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FirstTag {
    /// Never try the first tag: only an event sealed under the second
    /// opens. The default.
    #[default]
    Reject,
    /// Try the first tag while the reader's clock is before this instant,
    /// and refuse it from then on: the opt-in for a rolling upgrade or a
    /// re-seal pass with a known end.
    AcceptUntil(SystemTime),
    /// Try the first tag after the second, with no end date: the opt-in for
    /// the pass that re-seals such events, and for a reader that must open
    /// them before that pass has run.
    Accept,
}

impl FirstTag {
    /// Whether a reader whose clock reads `now` tries the first tag.
    #[must_use]
    pub fn accepts_at(self, now: SystemTime) -> bool {
        match self {
            Self::Reject => false,
            Self::AcceptUntil(cutoff) => now < cutoff,
            Self::Accept => true,
        }
    }
}

/// The associated data to try, in order, when opening an encrypted event
/// under a [`FirstTag`] policy read at `now`, the reader's clock: the second
/// tag, then the first while the policy accepts it. `None` when the body is
/// [`EventBody::Clear`].
///
/// This is the entry for a reader that names an accepting policy. A reader
/// under the default needs no clock and no list: it opens under the one
/// value [`envelope_aad_for`] returns, which is also all this function
/// lists under [`FirstTag::Reject`], whatever the clock reads. A success under
/// the first entry means every field a reader acts on was authenticated. A
/// success under the second, which only an accepting policy lists,
/// authenticated only id, kind, tenant and subject, as it did when the
/// event was sealed: a status, actor or time rewritten at rest still opens.
/// A reader that fails to open an event under every value listed holds a
/// rewritten event, a damaged one, or one sealed under the first tag that
/// the policy refuses; all three are refused, by design.
#[must_use]
pub fn open_aads_for<P: EventPayload>(
    event: &Event<P>,
    first_tag: FirstTag,
    now: SystemTime,
) -> Option<Vec<Vec<u8>>> {
    let mut aads = vec![envelope_aad_for(event)?];
    if first_tag.accepts_at(now) {
        aads.push(first_tag_aad(event));
    }
    Some(aads)
}

/// The first-tag AAD of a stored event, read from its own fields: the id,
/// kind, tenant and subject, and nothing else. Kept to open events sealed
/// before the second tag existed, for a reader that names [`FirstTag`];
/// nothing seals under it.
fn first_tag_aad<P: EventPayload>(event: &Event<P>) -> Vec<u8> {
    first_tag_aad_of(
        &event.id,
        &event.kind,
        event.tenant_id.as_ref(),
        event.subject.as_ref(),
    )
}

/// The first-tag encoding of the four fields it binds.
fn first_tag_aad_of(
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
        // The 16 bytes an event of an earlier release recorded, under the tag
        // it was sealed with: such an event opens only when exactly these
        // bytes are rebuilt, which no mapping of the id to its key could do.
        Some(EventSubjectRef::Session(recorded)) => {
            buf.push(4);
            put(buf, recorded.as_bytes());
        }
        Some(EventSubjectRef::Other { kind, id }) => {
            buf.push(5);
            put(buf, kind.as_bytes());
            put(buf, id.as_bytes());
        }
        Some(EventSubjectRef::SessionKey(key)) => {
            buf.push(6);
            put(buf, key.as_bytes());
        }
    }
}

/// The length prefix of an AAD field, or `None` when it does not fit.
fn field_len(len: usize) -> Option<u32> {
    u32::try_from(len).ok()
}

#[cfg(test)]
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
    fn the_first_tag_aad_differs_when_any_field_it_binds_differs() {
        let id = EventId::NIL;
        let kind = KindTag::from_static("a.b.v1");
        let tenant = TenantId::from_bytes([1; 16]);
        let user = EventSubject::User(UserId::from_bytes([2; 16]));
        let base = first_tag_aad_of(&id, &kind, Some(&tenant), Some(&user));

        let other_id = EventId::from_bytes([9; 16]);
        let other_kind = KindTag::from_static("a.b.v2");
        let other_tenant = TenantId::from_bytes([3; 16]);
        let other_user = EventSubject::User(UserId::from_bytes([4; 16]));
        let tenant_subject = EventSubject::Tenant(TenantId::from_bytes([2; 16]));

        for changed in [
            first_tag_aad_of(&other_id, &kind, Some(&tenant), Some(&user)),
            first_tag_aad_of(&id, &other_kind, Some(&tenant), Some(&user)),
            first_tag_aad_of(&id, &kind, Some(&other_tenant), Some(&user)),
            first_tag_aad_of(&id, &kind, None, Some(&user)),
            first_tag_aad_of(&id, &kind, Some(&tenant), Some(&other_user)),
            first_tag_aad_of(&id, &kind, Some(&tenant), None),
            // Same 16 bytes, different subject class.
            first_tag_aad_of(&id, &kind, Some(&tenant), Some(&tenant_subject)),
        ] {
            assert_ne!(changed, base);
        }
        assert_eq!(
            first_tag_aad_of(&id, &kind, Some(&tenant), Some(&user)),
            base,
            "deterministic"
        );
    }
}
