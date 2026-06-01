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
