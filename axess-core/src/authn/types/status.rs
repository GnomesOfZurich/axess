//! What put an account in a non-nominal state, and why it says so.
//!
//! A [`StatusDetail`] travels with every `Pending`, `Suspended`,
//! `Terminated` and `Archived` [`EntityState`](super::EntityState). Its
//! `reason` is prose for a screen; its [`cause`](StatusDetail::cause) is the
//! machine-readable fact an eligibility decision reads, so that nobody keys
//! a security decision on the spelling of a sentence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// What put an account in a non-nominal state.
///
/// An administrative disablement and a lockout look alike on a login screen
/// (both refuse) and must not look alike to a recovery flow: the account a
/// lockout holds is exactly who recovery exists for, and the account an
/// operator disabled must never pass. The cause tells them apart without
/// reading [`StatusDetail::reason`]. The questions a decision asks are
/// [`EntityState::is_administratively_disabled`](super::EntityState::is_administratively_disabled)
/// and [`EntityState::can_self_recover`](super::EntityState::can_self_recover).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StatusCause {
    /// An operator's act (`suspend_user`, a console, a compliance hold). It
    /// ends when an operator ends it, or at `until` when the operator set
    /// one.
    Administrative,
    /// The account awaits activation: an email, a document check, a first
    /// login. `activate_user` ends it.
    Verification,
    /// A store materialises a failed-attempt lockout as a stored state.
    ///
    /// The library itself never writes this cause: its lockout is derived
    /// from the failure counter at every gate before a verifier runs and is
    /// never an `EntityState`. The variant exists so a store that keeps a
    /// lock in its status column can say so, and so a reader never has to
    /// infer a lockout from `reason` or from a missing `until`.
    Lockout,
    /// The account is closed; a `Terminated` or `Archived` state carries it.
    Closure,
    /// An adopter's own cause under a short machine key (`"billing"`,
    /// `"legal-hold"`). A row written before the cause existed reads as
    /// [`unspecified`](Self::unspecified). No eligibility question answers
    /// yes to an `Other` cause.
    Other(Arc<str>),
}

impl StatusCause {
    /// The cause a row stored without one reads as: `Other("unspecified")`.
    ///
    /// Neither [`is_administratively_disabled`](super::EntityState::is_administratively_disabled)
    /// nor [`can_self_recover`](super::EntityState::can_self_recover) says
    /// yes to it, so an old row fails closed until a write states its cause.
    pub fn unspecified() -> Self {
        StatusCause::Other("unspecified".into())
    }
}

/// Details attached to a non-nominal entity state.
///
/// Build one with the constructor that names its cause,
/// [`administrative`](Self::administrative), [`verification`](Self::verification),
/// [`lockout`](Self::lockout), [`closure`](Self::closure) or
/// [`other`](Self::other), and [`with_until`](Self::with_until) for a timed
/// one. The fields are public so a store that reads its own columns can
/// build the literal; a literal must state its `cause`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusDetail {
    /// What put the account in this state. A row serialised before this
    /// field existed reads as [`StatusCause::unspecified`].
    #[serde(default = "StatusCause::unspecified")]
    pub cause: StatusCause,
    /// Human-readable reason for the non-nominal state, for display only;
    /// a decision reads `cause`.
    pub reason: Arc<str>,
    /// When this state was entered.
    pub since: DateTime<Utc>,
    /// Optional expiry: `None` means indefinite.
    pub until: Option<DateTime<Utc>>,
}

impl StatusDetail {
    fn with_cause(cause: StatusCause, reason: impl Into<Arc<str>>, since: DateTime<Utc>) -> Self {
        StatusDetail {
            cause,
            reason: reason.into(),
            since,
            until: None,
        }
    }

    /// An operator's act ([`StatusCause::Administrative`]), indefinite until
    /// [`with_until`](Self::with_until) sets an end.
    pub fn administrative(reason: impl Into<Arc<str>>, since: DateTime<Utc>) -> Self {
        Self::with_cause(StatusCause::Administrative, reason, since)
    }

    /// Awaiting activation ([`StatusCause::Verification`]).
    pub fn verification(reason: impl Into<Arc<str>>, since: DateTime<Utc>) -> Self {
        Self::with_cause(StatusCause::Verification, reason, since)
    }

    /// A lockout a store materialises as a state ([`StatusCause::Lockout`]).
    /// The library never builds one; see the variant.
    pub fn lockout(reason: impl Into<Arc<str>>, since: DateTime<Utc>) -> Self {
        Self::with_cause(StatusCause::Lockout, reason, since)
    }

    /// A closed account ([`StatusCause::Closure`]).
    pub fn closure(reason: impl Into<Arc<str>>, since: DateTime<Utc>) -> Self {
        Self::with_cause(StatusCause::Closure, reason, since)
    }

    /// An adopter's own cause under `key` ([`StatusCause::Other`]).
    pub fn other(
        key: impl Into<Arc<str>>,
        reason: impl Into<Arc<str>>,
        since: DateTime<Utc>,
    ) -> Self {
        Self::with_cause(StatusCause::Other(key.into()), reason, since)
    }

    /// Set the end of the state: `Some(t)` for a timed suspension, `None`
    /// for an indefinite one. A `Suspended` state whose `until` has passed
    /// reads as `Active` through
    /// [`EntityState::effective_at`](super::EntityState::effective_at).
    #[must_use]
    pub fn with_until(mut self, until: Option<DateTime<Utc>>) -> Self {
        self.until = until;
        self
    }
}

#[cfg(test)]
mod tests;
