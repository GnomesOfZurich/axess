//! [`EventSubject`]: the entity an event is *about* or *initiated by*.
//!
//! Two envelope fields use this type: `subject` (whose state changed,
//! who failed an attempt) and `actor` (who initiated). They differ for
//! impersonation (`actor` = admin, `subject` = impersonated user) and
//! for autonomous flows (`actor` = system principal).

use crate::id::{DeviceId, SessionKey, TenantId, UserId};
use crate::kind::KindTag;
use axess_strings::ShortString;

// The definitions sit in a private module because rkyv's derive writes a
// second public type beside each, `EventSubjectResolver` and
// `RecordedSessionIdResolver`, whose fields it does not document. A
// resolver has no use by name (it is `<T as rkyv::Archive>::Resolver`), so
// it gets no path, and the documented names are exported from here.
mod owned {
    use crate::id::{DeviceId, SessionId, SessionKey, TenantId, UserId};
    use crate::kind::KindTag;
    use axess_strings::ShortString;

    /// The id of a session as an event written before 0.20.0 recorded it.
    ///
    /// A value of this type comes from one place: the reader of a stored
    /// event (the `serde` and `rkyv` decoders of
    /// [`EventSubject`](crate::EventSubject)). It has no constructor, from
    /// a `SessionId`, a `Uuid`, bytes or text, so a new event cannot name a
    /// session by an id; it names it by its key
    /// ([`EventSubject::SessionKey`](crate::EventSubject::SessionKey)).
    ///
    /// Why nothing else can build one:
    ///
    /// 1. Its field is private to this module, and this module holds no
    ///    function that makes one from another value: no `new`, no `From`,
    ///    no `TryFrom`, no `FromStr`, no `Default`. `Clone` and `Copy` copy
    ///    one that exists.
    /// 2. The only functions that return one are the two derived decoders,
    ///    `serde::Deserialize` and `rkyv::Deserialize`, and each turns
    ///    stored bytes into the value: they are the reader of stored events.
    /// 3. [`EventSubject::as_ref`](crate::EventSubject::as_ref) lends a
    ///    recorded id and
    ///    [`EventSubjectRef::to_owned`](crate::EventSubjectRef::to_owned)
    ///    copies the one it was lent.
    ///
    /// So code that holds a `SessionId` can put it into an event only by
    /// writing it out in the stored form and reading that back, and no API
    /// of the session layer hands out the id of a live session.
    /// `Serialize` stays on purpose: an event read from one store is written
    /// to another unchanged; what the type forbids is building one, not
    /// carrying one. `serde(transparent)` keeps the text an earlier event
    /// holds (`{"Session":"<uuid>"}`), and the `rkyv` form is the 16 bytes a
    /// `SessionId` archives as.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    #[cfg_attr(
        feature = "rkyv",
        derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
    )]
    pub struct RecordedSessionId(SessionId);

    impl RecordedSessionId {
        /// The key of the recorded session: the name the records of this
        /// release give the same session, so events of both forms
        /// correlate.
        #[must_use]
        pub fn key(&self) -> SessionKey {
            SessionKey::of(&self.0)
        }

        /// The 16 bytes the event recorded, which the associated data of a
        /// sealed event authenticated.
        #[must_use]
        pub fn as_bytes(&self) -> &[u8; 16] {
            self.0.as_bytes()
        }

        /// A recorded id for this crate's own tests, which need an event of
        /// the earlier form without a stored one to read.
        #[cfg(test)]
        pub(crate) fn recorded(id: SessionId) -> Self {
            Self(id)
        }
    }

    /// Tagged identifier for an entity referenced by an event.
    ///
    /// The typed variants cover the identifiers shared across the
    /// workspace (a session by its key, or by the id an earlier event
    /// recorded); [`EventSubject::Other`] is the escape hatch for
    /// domain-specific subjects (governance object id, valuation grid id,
    /// …) that the envelope crate doesn't need to understand.
    ///
    /// Owned form: use in envelope fields and anywhere the subject
    /// out-lives the event borrow. For zero-allocation *introspection* on
    /// the hot path: routing, per-tenant filtering, tracing, fan-out:
    /// see the borrowed pair [`EventSubjectRef`](crate::EventSubjectRef) and
    /// [`EventSubject::as_ref`].
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(
        feature = "rkyv",
        derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
    )]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum EventSubject {
        /// Subject is a user.
        User(UserId),
        /// Subject is a tenant (cross-tenant operations only).
        Tenant(TenantId),
        /// Subject is a device.
        Device(DeviceId),
        /// Subject is a session, named by the id an event written before
        /// 0.20.0 recorded. Read from a stored event; it cannot be built.
        Session(RecordedSessionId),
        /// Subject is a session, named by its key.
        SessionKey(SessionKey),
        /// Domain-specific subject. `kind` describes the entity class
        /// (e.g. `"governance.constraint"`); `id` is its opaque
        /// identifier in that domain.
        Other {
            /// Entity-class discriminator.
            kind: KindTag,
            /// Domain-opaque identifier.
            id: ShortString,
        },
    }
}

#[cfg(feature = "rkyv")]
pub use owned::{ArchivedEventSubject, ArchivedRecordedSessionId};
pub use owned::{EventSubject, RecordedSessionId};

impl EventSubject {
    /// Borrowed view of this subject. Cheap: each typed variant projects
    /// to a `&`-reference; the `Other` variant's `KindTag`/`ShortString`
    /// deref to `&str`.
    ///
    /// Prefer this over hand-constructing an [`EventSubjectRef`] when
    /// you already hold an owned [`EventSubject`]. Consumers that need
    /// to *build* a subject from an unowned payload field construct
    /// [`EventSubjectRef`] directly.
    #[must_use]
    pub fn as_ref(&self) -> EventSubjectRef<'_> {
        match self {
            EventSubject::User(id) => EventSubjectRef::User(id),
            EventSubject::Tenant(id) => EventSubjectRef::Tenant(id),
            EventSubject::Device(id) => EventSubjectRef::Device(id),
            EventSubject::Session(id) => EventSubjectRef::Session(id),
            EventSubject::SessionKey(key) => EventSubjectRef::SessionKey(key),
            EventSubject::Other { kind, id } => EventSubjectRef::Other {
                kind: kind.as_str(),
                id: id.as_str(),
            },
        }
    }
}

impl<'a> From<&'a EventSubject> for EventSubjectRef<'a> {
    fn from(s: &'a EventSubject) -> Self {
        s.as_ref()
    }
}

/// Borrowed view of an [`EventSubject`]: the zero-allocation pair for
/// hot-path subject introspection.
///
/// Every non-trivial event-bus consumer needs to answer *"what is this
/// event about?"* cheaply: for routing, per-tenant filtering,
/// distributed-log fan-out, tracing spans, per-subject bucketing.
/// [`EventSubjectRef`] is the primitive those consumers reach for.
///
/// Owned↔borrowed pairing mirrors the standard-library idiom
/// ([`String`]/[`str`], [`std::path::PathBuf`]/[`std::path::Path`],
/// [`Vec<T>`]/`[T]`): [`EventSubject`] stores; [`EventSubjectRef`]
/// borrows.
///
/// The variants mirror [`EventSubject`] one-to-one so pattern-match
/// consumers keep type discipline, a `User`-subject event is never
/// mistaken for an `Other`-subject event just because both got squashed
/// into a `{kind: &str, id: &str}` shape.
///
/// # Constructing
///
/// From an owned subject you already hold, use [`EventSubject::as_ref`]
/// or the `From<&EventSubject>` impl. When *building* a subject from a
/// payload's own field (a `String` or `ShortString` you'd rather not
/// clone into an owned `EventSubject`), construct the borrowed form
/// directly: the payload's inherent
/// [`EventPayload::subject_ref`](crate::EventPayload::subject_ref)
/// method typically returns
/// `EventSubjectRef::Other { kind: "Instrument", id: &v.instrument_id }`
/// or similar.
///
/// # Compatibility
///
/// [`EventSubjectRef`] intentionally derives neither `serde` nor `rkyv`:
/// it is a transient *view*, never a wire type. Only the owned
/// [`EventSubject`] is serialisable. If a consumer needs to persist a
/// subject seen through this ref, call [`EventSubjectRef::to_owned`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventSubjectRef<'a> {
    /// Subject is a user.
    User(&'a UserId),
    /// Subject is a tenant (cross-tenant operations only).
    Tenant(&'a TenantId),
    /// Subject is a device.
    Device(&'a DeviceId),
    /// Subject is a session, named by the id an event written before 0.20.0
    /// recorded; mirrors [`EventSubject::Session`].
    Session(&'a RecordedSessionId),
    /// Subject is a session, named by its key.
    SessionKey(&'a SessionKey),
    /// Domain-opaque subject; mirrors [`EventSubject::Other`]. `kind`
    /// discriminates entity class (e.g. `"Instrument"`, `"Case"`,
    /// `"governance.constraint"`); `id` is the class-scoped identifier.
    Other {
        /// Entity-class discriminator.
        kind: &'a str,
        /// Domain-opaque identifier within that class.
        id: &'a str,
    },
}

impl EventSubjectRef<'_> {
    /// Materialise the borrowed view into an owned [`EventSubject`].
    /// Allocates for the `Other` variant (its `kind`/`id` bytes become
    /// `KindTag`/`ShortString`); the typed variants copy their
    /// identifier by value.
    #[must_use]
    pub fn to_owned(&self) -> EventSubject {
        match *self {
            EventSubjectRef::User(id) => EventSubject::User(*id),
            EventSubjectRef::Tenant(id) => EventSubject::Tenant(*id),
            EventSubjectRef::Device(id) => EventSubject::Device(*id),
            EventSubjectRef::Session(id) => EventSubject::Session(*id),
            EventSubjectRef::SessionKey(key) => EventSubject::SessionKey(*key),
            EventSubjectRef::Other { kind, id } => EventSubject::Other {
                kind: KindTag::new(kind),
                id: ShortString::new(id),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_identity::mint_v4_default;
    use std::collections::HashMap;

    fn some_user() -> UserId {
        UserId::from_uuid(mint_v4_default())
    }
    fn some_tenant() -> TenantId {
        TenantId::from_uuid(mint_v4_default())
    }
    fn some_device() -> DeviceId {
        DeviceId::from_uuid(mint_v4_default())
    }
    fn some_recorded_session() -> RecordedSessionId {
        RecordedSessionId::recorded(crate::id::SessionId::from_uuid(mint_v4_default()))
    }
    fn some_session_key() -> SessionKey {
        SessionKey::of(&crate::id::SessionId::from_uuid(mint_v4_default()))
    }

    #[test]
    fn as_ref_projects_typed_variants_by_reference() {
        let u = some_user();
        let subj = EventSubject::User(u);
        match subj.as_ref() {
            EventSubjectRef::User(id) => assert_eq!(id, &u),
            other => panic!("expected User, got {other:?}"),
        }
    }

    #[test]
    fn as_ref_projects_other_as_borrowed_str_pair() {
        let subj = EventSubject::Other {
            kind: KindTag::new("Instrument"),
            id: ShortString::new("inst-aapl-123"),
        };
        match subj.as_ref() {
            EventSubjectRef::Other { kind, id } => {
                assert_eq!(kind, "Instrument");
                assert_eq!(id, "inst-aapl-123");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn as_ref_roundtrips_every_variant() {
        let subjects = [
            EventSubject::User(some_user()),
            EventSubject::Tenant(some_tenant()),
            EventSubject::Device(some_device()),
            EventSubject::Session(some_recorded_session()),
            EventSubject::SessionKey(some_session_key()),
            EventSubject::Other {
                kind: KindTag::new("Case"),
                id: ShortString::new("case-42"),
            },
        ];
        for original in &subjects {
            let roundtripped = original.as_ref().to_owned();
            assert_eq!(&roundtripped, original, "roundtrip lost data");
        }
    }

    #[test]
    fn from_ref_impl_matches_as_ref() {
        let subj = EventSubject::Tenant(some_tenant());
        let via_as_ref: EventSubjectRef<'_> = subj.as_ref();
        let via_from: EventSubjectRef<'_> = (&subj).into();
        assert_eq!(via_as_ref, via_from);
    }

    #[test]
    fn event_subject_ref_is_hashable_for_per_subject_bucketing() {
        // Consumers key hash-maps by subject for per-subject counters,
        // rate limits, dedup: verify the Hash derive stands up.
        let u = some_user();
        let t = some_tenant();
        let subjects = [
            EventSubject::User(u),
            EventSubject::Tenant(t),
            EventSubject::Other {
                kind: KindTag::new("Instrument"),
                id: ShortString::new("inst-a"),
            },
        ];
        let mut counts: HashMap<EventSubjectRef<'_>, usize> = HashMap::new();
        for s in &subjects {
            *counts.entry(s.as_ref()).or_default() += 1;
        }
        assert_eq!(
            counts.len(),
            3,
            "three distinct subjects should not collide"
        );
        for &n in counts.values() {
            assert_eq!(n, 1);
        }
    }

    #[test]
    fn event_subject_ref_is_copy() {
        // Consumers pattern-match then log/route in the same scope;
        // `Copy` keeps the ergonomics off: no manual clones on the
        // borrowed view.
        let u = some_user();
        let subj = EventSubject::User(u);
        let borrowed = subj.as_ref();
        let also_borrowed = borrowed; // Copy
        assert_eq!(borrowed, also_borrowed);
    }
}
