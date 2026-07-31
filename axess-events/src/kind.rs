//! Event taxonomy: [`KindTag`] (wire-form discriminator) and
//! [`EventPayload`] (the trait every domain payload type implements).
//!
//! The envelope crate holds **no** central `EventKind` enum: that
//! would couple every domain to a single registry. Instead each domain
//! defines its own typed kind enum (e.g. axess's `AuthEventKind`,
//! platform governance's `GovernanceEventKind`) and projects it onto a
//! [`KindTag`] for the wire. Routing-before-decode in brokers reads
//! `KindTag`; subscribers that own the typed enum pattern-match on it
//! after decoding the payload.

use axess_strings::ShortString;
use core::fmt;

use crate::subject::EventSubjectRef;

/// Wire-form event kind discriminator. A short, hashable, comparable
/// string like `"auth.login_attempt.v2"`.
///
/// Backed by [`ShortString`] (Umbra-style 16-byte stack repr): inline
/// for tags ≤ 12 bytes, refcounted heap for longer, zero-allocation
/// for `&'static str` constants. Cardinality across the org is small
/// (O(100s)); volume per kind is high. This is the workload
/// `ShortString` is built for.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KindTag(ShortString);

impl KindTag {
    /// Construct from any string slice. Allocates iff the tag exceeds
    /// 12 bytes; for compile-time-known tags use [`KindTag::from_static`].
    #[inline]
    pub fn new(s: &str) -> Self {
        Self(ShortString::new(s))
    }

    /// Construct from a `&'static str` without allocating, in `const`
    /// context if needed.
    #[inline]
    pub const fn from_static(s: &'static str) -> Self {
        Self(ShortString::from_static(s))
    }

    /// Borrow the wire form as `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for KindTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for KindTag {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<ShortString> for KindTag {
    fn from(s: ShortString) -> Self {
        Self(s)
    }
}

/// Trait implemented by every domain-specific event payload enum.
///
/// The single required method is [`EventPayload::kind_tag`]: the
/// payload tells the envelope what kind it is. The envelope then
/// stores the [`KindTag`] for routing-before-decode (subscribers can
/// dispatch without deserialising the full payload).
///
/// # Implementing
///
/// Domains typically define a `<Domain>EventKind` enum with a
/// `Display` impl that yields the dotted-string form
/// (`"auth.login_attempt.v2"`), then implement this trait on the
/// payload enum:
///
/// ```ignore
/// pub enum AuthEventKind {
///     LoginAttemptV1,
///     DeviceFirstSeenV1,
/// }
/// impl core::fmt::Display for AuthEventKind { /* dotted form */ }
///
/// pub enum AuthEventPayload {
///     LoginAttempt { factor_kind: FactorKind, /* … */ },
///     DeviceFirstSeen { fingerprint_hash: FingerprintHash, /* … */ },
/// }
/// impl AuthEventPayload {
///     fn kind(&self) -> AuthEventKind { /* match self … */ }
/// }
/// impl axess_events::EventPayload for AuthEventPayload {
///     fn kind_tag(&self) -> axess_events::KindTag {
///         axess_events::KindTag::new(&self.kind().to_string())
///     }
///     #[cfg(feature = "serde")]
///     fn to_inner_json(&self) -> serde_json::Value {
///         match self {
///             Self::LoginAttempt(v) => serde_json::to_value(v).unwrap_or_default(),
///             Self::DeviceFirstSeen(v) => serde_json::to_value(v).unwrap_or_default(),
///         }
///     }
/// }
/// ```
pub trait EventPayload: Clone + fmt::Debug + Send + Sync + 'static {
    /// Wire-form discriminator for this payload value.
    fn kind_tag(&self) -> KindTag;

    /// JSON projection of the *inner* variant value, i.e. the struct
    /// that the matched variant wraps, not the enum tag.
    ///
    /// Subscribers that need a flat JSON shape (rule engines, SIEM
    /// forwarders, audit-log columns) call this to avoid hand-rolling
    /// per-domain `match` ladders. The default `serde_json::to_value`
    /// on the enum itself would yield the externally tagged form
    /// `{"MarkUpdated": {...}}`; this method returns just the inner
    /// `{...}`.
    ///
    /// Implementations are mechanical: one `match` arm per variant
    /// returning `serde_json::to_value(inner).unwrap_or_default()`.
    /// Kept manual rather than derive-macroed: enums are small (≤10
    /// variants), the implementation is one line per variant, and a
    /// derive macro would force every consumer to pull `syn`/`quote`
    /// for marginal savings.
    #[cfg(feature = "serde")]
    fn to_inner_json(&self) -> serde_json::Value;

    /// The entity this event is *about*, borrowed for zero-allocation
    /// introspection. Default `None` for payloads without a
    /// well-defined subject; override in payload enums that carry an
    /// identifier a subscriber would filter by.
    ///
    /// Fills the hot-path gap that [`EventSubject`](crate::EventSubject)
    /// (owned, envelope-level) doesn't cover: per-tick routing,
    /// per-tenant fan-out, per-subject bucketing, tracing-span tagging.
    /// See [`EventSubjectRef`] for the borrowed-vs-owned rationale.
    ///
    /// Override example — a payload carrying an instrument id:
    ///
    /// ```ignore
    /// use axess_events::{EventPayload, EventSubjectRef, KindTag};
    ///
    /// impl EventPayload for MyPayload {
    ///     fn kind_tag(&self) -> KindTag { /* … */ }
    ///     #[cfg(feature = "serde")]
    ///     fn to_inner_json(&self) -> serde_json::Value { /* … */ }
    ///
    ///     fn subject_ref(&self) -> Option<EventSubjectRef<'_>> {
    ///         Some(match self {
    ///             Self::BarrierBreached(v) =>
    ///                 EventSubjectRef::Other { kind: "Instrument", id: &v.instrument_id },
    ///             Self::ApprovalRequested(v) =>
    ///                 EventSubjectRef::Other { kind: &v.target_type, id: &v.target_id },
    ///         })
    ///     }
    /// }
    /// ```
    #[inline]
    fn subject_ref(&self) -> Option<EventSubjectRef<'_>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_writes_as_str() {
        let tag = KindTag::new("auth.login_attempt.v2");
        assert_eq!(format!("{tag}"), "auth.login_attempt.v2");
    }

    #[test]
    fn from_str_carries_payload() {
        let tag: KindTag = "auth.login_attempt.v2".into();
        assert_eq!(tag.as_str(), "auth.login_attempt.v2");
    }

    #[test]
    fn from_short_string_carries_payload() {
        let s = ShortString::new("auth.session.cycled.v1");
        let tag: KindTag = s.into();
        assert_eq!(tag.as_str(), "auth.session.cycled.v1");
    }
}
