//! The audit sink of the session layer.
//!
//! The layer ends a signed-in session (an authenticated one, or one in a
//! step-up of it) by its own decision in these cases, each a
//! [`SessionEndReason`]: the session outlived an absolute age cap, the
//! registry no longer holds it (for an impersonation, no longer holds the
//! administrator's entry either), it was revoked while its id rotated, the
//! registry could not track its rotated id, the store could not rotate it,
//! or device keys are required and it was still not bound to one when its
//! registration window closed. The session validator ends a session the
//! registry no longer holds, or whose tenant the identity store does not
//! confirm, through the same protocol. All of them happen on a request of the
//! client's, inside the layer, where no service is on the call path to
//! record them. The layer therefore tells a [`SessionEndAudit`] about every
//! session it ends.
//!
//! The row comes first, the ending second. The layer calls the sink while
//! the session's row is still stored, and removes the row only when the
//! sink answered `Ok`. A sink that fails leaves the session unended: its
//! row stays, and the next request that presents it is judged again. A
//! session past an age cap, gone from the registry, or past its key
//! registration window unbound is refused by every such request, and ended
//! by the first that finds the sink answering. The
//! work is done in a task of its own, so a request dropped half-way can
//! neither remove a row whose ending was not recorded nor leave a recorded
//! one behind.
//!
//! One ending is one call. A session the layer ends is first claimed with a
//! compare-and-swap on its row
//! ([`SessionData::ending`](crate::session::SessionData::ending)), which
//! one of several requests carrying the same cookie wins; the others are
//! refused the session and report nothing. That holds at the load, at the
//! device-key check, and at the finish of a request: a rotation the
//! registry or the store refused, and an ending a handler or the session
//! validator asked for. A row that is no longer stored under the key the
//! ending names was moved or ended by another request, which recorded what
//! it did, and nothing is recorded for it again; only a rotation the store
//! failed after removing the row records that ending after the fact.
//!
//! The claim is the decision to end the session and keeps the reason. A
//! request that finds a claim older than its lease finishes the ending for
//! that reason: the session is not judged again and never served. That is
//! where one ending can have a second call: the first request's sink
//! answered and its removal failed, or the request stopped in between, and
//! the request that finishes calls the sink again. Both calls name the same
//! session, user, tenant and reason, so the session's key identifies the
//! ending to a sink that must record it once.

use crate::authn::ids::{TenantId, UserId};
use crate::session::id::SessionKey;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Why the session layer ended a session.
///
/// Serialised as its tag ([`as_str`](Self::as_str)): the claim the layer
/// writes on a session it is ending keeps the reason, so a request that
/// finishes the ending records the same one
/// ([`EndingClaim`](crate::session::EndingClaim)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SessionEndReason {
    /// The session outlived the absolute age cap
    /// ([`SessionLayer::with_max_session_age`](crate::session::SessionLayer::with_max_session_age)).
    #[serde(rename = "session_age_cap")]
    AgeCap,
    /// The impersonation the session carries outlived the impersonation age
    /// cap
    /// ([`SessionLayer::with_max_impersonation_age`](crate::session::SessionLayer::with_max_impersonation_age)).
    #[serde(rename = "impersonation_age_cap")]
    ImpersonationAgeCap,
    /// The registry no longer holds the session: it was kicked, or every
    /// session of its user was ended.
    #[serde(rename = "session_not_registered")]
    NotRegistered,
    /// The registry no longer holds the entry an impersonation registered
    /// under its administrator, whose sessions were ended.
    #[serde(rename = "impersonation_not_registered")]
    ImpersonationNotRegistered,
    /// The session was revoked while a request was rotating its id, so the
    /// rotated id was ended with it.
    #[serde(rename = "session_revoked_during_rotation")]
    RevokedDuringRotation,
    /// The registry could not register or confirm the session's rotated id,
    /// and the layer does not keep a session the registry does not track
    /// ([`UnknownLiveness::Reject`](crate::session::UnknownLiveness::Reject)).
    #[serde(rename = "session_not_tracked")]
    NotTracked,
    /// The store could not move the session to its rotated id (it failed, or
    /// concurrent requests kept writing the row), and the layer does not
    /// keep the old id for a session whose state changed. A request that
    /// changed who the session is (the start or the end of an
    /// impersonation) ends two sessions this way, the stored one and the
    /// one that was to replace it, and each has its call.
    #[serde(rename = "session_rotation_failed")]
    RotationFailed,
    /// Device keys are required (`KeyBindingPolicy::Require`) and the
    /// session was still not bound to a key when its registration window,
    /// which runs from its login, had passed.
    #[serde(rename = "key_binding_required")]
    KeyBindingRequired,
    /// The identity store did not confirm the tenant the session names for
    /// its user: it names another tenant, no longer knows the user, or could
    /// not answer. The session validator's tenant check ends such a session.
    #[serde(rename = "session_tenant_not_confirmed")]
    TenantNotConfirmed,
}

impl SessionEndReason {
    /// The stable tag of the reason, which the audit row carries in
    /// `error`: `session_age_cap`, `impersonation_age_cap`,
    /// `session_not_registered`, `impersonation_not_registered`,
    /// `session_revoked_during_rotation`, `session_not_tracked`,
    /// `session_rotation_failed`, `key_binding_required` or
    /// `session_tenant_not_confirmed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgeCap => "session_age_cap",
            Self::ImpersonationAgeCap => "impersonation_age_cap",
            Self::NotRegistered => "session_not_registered",
            Self::ImpersonationNotRegistered => "impersonation_not_registered",
            Self::RevokedDuringRotation => "session_revoked_during_rotation",
            Self::NotTracked => "session_not_tracked",
            Self::RotationFailed => "session_rotation_failed",
            Self::KeyBindingRequired => "key_binding_required",
            Self::TenantNotConfirmed => "session_tenant_not_confirmed",
        }
    }

    /// Whether the session ended because of its age (an age cap) rather than
    /// because something revoked it or it could not be kept.
    pub fn is_expiry(self) -> bool {
        matches!(self, Self::AgeCap | Self::ImpersonationAgeCap)
    }
}

/// One session the session layer is ending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerSessionEnded {
    /// The user the session is signed in as; for a session in a step-up,
    /// the user of the login the step-up began from.
    pub user_id: UserId,
    /// The tenant the session signed in to, read from the session
    /// itself, so the row has its tenant whether or not the user can still
    /// be looked up.
    pub tenant_id: TenantId,
    /// The session that is ended, by the key its row is stored under at
    /// that moment: the name the session table, the registry and the logs
    /// give it, never the value its cookie carried. A session ended while
    /// its key rotated is named by its new key once the row moved there,
    /// and by its old key when the store could not move it. A session no
    /// row ever held (a login whose rotation failed) is named by the key it
    /// was to get, the one its login registered.
    pub session_id: SessionKey,
    /// The administrator acting as `user_id`, when the session carries an
    /// impersonation, whatever the reason it ended for.
    pub impersonator: Option<UserId>,
    /// Why the layer ends it.
    pub reason: SessionEndReason,
}

/// Where the session layer records the sessions it ends.
///
/// [`AuthnService::session_end_audit`](crate::authn::service::AuthnService::session_end_audit)
/// is the implementation that writes one audit row per ending; an
/// application with its own sink implements the trait instead. Every
/// [`SessionLayer`](crate::session::SessionLayer) constructor takes one, and
/// [`UnrecordedSessionEnds`] is the named way to record nothing.
///
/// The sink is called before the session is ended: its row is still stored,
/// and is removed only when this returns `Ok`. On `Err` the layer logs the
/// error and leaves the session stored. A session met at the load is
/// refused for that request; one that was to be ended at the finish of a
/// request keeps its cookie; either way the next request that presents it
/// is judged again, and ends it if the sink answers then.
/// A session that cannot exist whatever the sink answers (its rotation
/// failed before any row was written for it) is the one exception: the sink
/// is told first all the same, and an `Err` is logged at `error`.
pub trait SessionEndAudit: Send + Sync + 'static {
    /// Record that the layer is ending `ended`.
    fn session_ended<'a>(
        &'a self,
        ended: &'a LayerSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// The sink that records nothing: the named opt-out of the audit rows the
/// layer writes for the sessions it ends.
///
/// With it those endings leave a log line and no audit row, which is the
/// right choice for a test, and for a deployment that records them some
/// other way. [`insecure`](Self::insecure) builds it and says so in the log.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnrecordedSessionEnds;

impl UnrecordedSessionEnds {
    /// The sink to hand a [`SessionLayer`](crate::session::SessionLayer)
    /// that records no audit row for the sessions it ends. Logs an error,
    /// as a layer built without a registry does: a production layer passes
    /// [`AuthnService::session_end_audit`](crate::authn::service::AuthnService::session_end_audit).
    pub fn insecure() -> Arc<dyn SessionEndAudit> {
        tracing::error!(
            "a session layer was built with UnrecordedSessionEnds: the sessions it ends \
             (an age cap, a registry entry gone, a failed rotation, a device key required \
             and missing) leave no audit row"
        );
        Arc::new(Self)
    }
}

impl SessionEndAudit for UnrecordedSessionEnds {
    fn session_ended<'a>(
        &'a self,
        _: &'a LayerSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(std::future::ready(Ok(())))
    }
}
