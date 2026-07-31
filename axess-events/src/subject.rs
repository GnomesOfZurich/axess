//! [`EventSubject`]: the entity an event is *about* or *initiated by*.
//!
//! Two envelope fields use this type: `subject` (whose state changed,
//! who failed an attempt) and `actor` (who initiated). They differ for
//! impersonation (`actor` = admin, `subject` = impersonated user) and
//! for autonomous flows (`actor` = system principal).

// Module-level `allow(missing_docs)` covers the rkyv-generated
// `ArchivedEventSubject` and `EventSubjectResolver` types; rkyv 0.8
// emits undocumented variant fields on the resolver enum and the
// `attr(...)` helper does not propagate down into them. Every type
// authored here is fully documented by hand.
#![allow(missing_docs)]

use crate::id::{DeviceId, SessionId, TenantId, UserId};
use crate::kind::KindTag;
use axess_strings::ShortString;

/// Tagged identifier for an entity referenced by an event.
///
/// The first four variants cover the typed identifiers shared across
/// the workspace; [`EventSubject::Other`] is the escape hatch for
/// domain-specific subjects (governance object id, valuation grid id,
/// …) that the envelope crate doesn't need to understand.
///
/// Owned form: use in envelope fields and anywhere the subject
/// out-lives the event borrow. For zero-allocation *introspection* on
/// the hot path — routing, per-tenant filtering, tracing, fan-out —
/// see the borrowed pair [`EventSubjectRef`] and [`EventSubject::as_ref`].
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
    /// Subject is a session.
    Session(SessionId),
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

impl EventSubject {
    /// Borrowed view of this subject. Cheap: five variants each project
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

/// Borrowed view of an [`EventSubject`] — the zero-allocation pair for
/// hot-path subject introspection.
///
/// Every non-trivial event-bus consumer needs to answer *"what is this
/// event about?"* cheaply — for routing, per-tenant filtering,
/// distributed-log fan-out, tracing spans, per-subject bucketing.
/// [`EventSubjectRef`] is the primitive those consumers reach for.
///
/// Owned↔borrowed pairing mirrors the standard-library idiom
/// ([`String`]/[`str`], [`std::path::PathBuf`]/[`std::path::Path`],
/// [`Vec<T>`]/`[T]`): [`EventSubject`] stores; [`EventSubjectRef`]
/// borrows.
///
/// The variants mirror [`EventSubject`] one-to-one so pattern-match
/// consumers keep type discipline — a `User`-subject event is never
/// mistaken for an `Other`-subject event just because both got squashed
/// into a `{kind: &str, id: &str}` shape.
///
/// # Constructing
///
/// From an owned subject you already hold, use [`EventSubject::as_ref`]
/// or the `From<&EventSubject>` impl. When *building* a subject from a
/// payload's own field (a `String` or `ShortString` you'd rather not
/// clone into an owned `EventSubject`), construct the borrowed form
/// directly — the payload's inherent
/// [`EventPayload::subject_ref`](crate::EventPayload::subject_ref)
/// method typically returns
/// `EventSubjectRef::Other { kind: "Instrument", id: &v.instrument_id }`
/// or similar.
///
/// # Compatibility
///
/// [`EventSubjectRef`] intentionally derives neither `serde` nor `rkyv`
/// — it is a transient *view*, never a wire type. Only the owned
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
    /// Subject is a session.
    Session(&'a SessionId),
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
    /// `KindTag`/`ShortString`); the four typed variants clone their
    /// identifier by value.
    #[must_use]
    pub fn to_owned(&self) -> EventSubject {
        match *self {
            EventSubjectRef::User(id) => EventSubject::User(*id),
            EventSubjectRef::Tenant(id) => EventSubject::Tenant(*id),
            EventSubjectRef::Device(id) => EventSubject::Device(*id),
            EventSubjectRef::Session(id) => EventSubject::Session(*id),
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
    fn some_session() -> SessionId {
        SessionId::from_uuid(mint_v4_default())
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
            EventSubject::Session(some_session()),
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
        // rate limits, dedup — verify the Hash derive stands up.
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
        // `Copy` keeps the ergonomics off — no manual clones on the
        // borrowed view.
        let u = some_user();
        let subj = EventSubject::User(u);
        let borrowed = subj.as_ref();
        let also_borrowed = borrowed; // Copy
        assert_eq!(borrowed, also_borrowed);
    }
}
