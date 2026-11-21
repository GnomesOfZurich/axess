//! [`AuthFlow`]: what the factor step a session is waiting for belongs to.

use super::{AuthState, Impersonation};
use crate::authn::ids::{TenantId, UserId};
use axess_clock::Timestamp;
use serde::{Deserialize, Serialize};

/// What a pending factor step is for.
///
/// A login in progress and a step-up are both a session in
/// [`AuthState::Authenticating`], and both finish through `verify_factor`.
/// This says which one the session is in. It is set by the transition that
/// opened the step (`begin_login` and the passwordless finish open a login,
/// `begin_step_up` a step-up) and by nothing else, and it is what
/// `AuthSession::step_up_pending` reads, so a route that finishes a step-up
/// never verifies a factor for a login, whatever the login's method is
/// called.
///
/// Written as `login`, or `{"step_up": {"signed_in_at": ...}}`, for every
/// pending state: a stored pending state without it is not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFlow {
    /// A login: nobody is signed in on the session until its last step is
    /// verified.
    #[default]
    Login,
    /// A step-up: the session was signed in and is asked for another
    /// factor; the factors and proofs of its login are carried through it.
    /// Until the factor is verified the session is still the signed-in one
    /// it began from, and the session layer checks it as that session on
    /// every load: its registry entry, and the age caps.
    StepUp {
        /// The `signed_in_at` of the signed-in state the step-up began from:
        /// when its login completed. The absolute age cap runs from it while
        /// the step-up is open, and the state the step-up finishes in keeps
        /// it.
        signed_in_at: Timestamp,
    },
}

impl AuthFlow {
    /// Whether this is [`Login`](Self::Login).
    pub fn is_login(&self) -> bool {
        matches!(self, Self::Login)
    }
}

/// The signed-in session a stored state stands for, as the session layer
/// checks it on load: `user_id`'s registry entry, the absolute age cap from
/// `signed_in_at` (its login), and the impersonation cap from the
/// impersonator's `since`. The records of the sessions the layer ends and
/// rotates name the user, the tenant and the administrator from it, and the
/// device-key gate reads it too: the registration window runs from
/// `signed_in_at`, and the tenant is the one a binding and a registration
/// must name.
pub(crate) struct SignedIn<'a> {
    pub(crate) user_id: &'a UserId,
    pub(crate) tenant_id: &'a TenantId,
    pub(crate) signed_in_at: &'a Timestamp,
    pub(crate) impersonator: Option<&'a Impersonation>,
}

impl AuthState {
    /// The signed-in session this state stands for: an `Authenticated`
    /// state, or a step-up of one, which is still that session while it
    /// waits for its factor (its id stays registered, and it carries the
    /// user, the login's time and the impersonation). `None` for a
    /// guest, a login in progress and a pending workflow, which no registry
    /// holds yet.
    pub(crate) fn signed_in(&self) -> Option<SignedIn<'_>> {
        match self {
            AuthState::Authenticated {
                user_id,
                tenant_id,
                signed_in_at,
                impersonator,
                ..
            }
            | AuthState::Authenticating {
                user_id,
                tenant_id,
                impersonator,
                flow: AuthFlow::StepUp { signed_in_at },
                ..
            } => Some(SignedIn {
                user_id,
                tenant_id,
                signed_in_at,
                impersonator: impersonator.as_ref(),
            }),
            _ => None,
        }
    }

    /// The person at the browser of a signed-in session (authenticated, or
    /// in a step-up of that session): the administrator of an
    /// impersonation, else the signed-in user. `None` for a guest, a login
    /// in progress and a pending workflow, whose user is not proven.
    ///
    /// A device, its key, its binding to the session and its trust belong
    /// to this person. Under impersonation the browser is the
    /// administrator's, so nothing about it is recorded for the user the
    /// session runs as. A step-up is still the signed-in session it began
    /// from, so its device stays this person's while the step is open.
    pub(crate) fn person_at_browser(&self) -> Option<UserId> {
        let signed_in = self.signed_in()?;
        Some(
            signed_in
                .impersonator
                .map_or(*signed_in.user_id, |by| by.admin),
        )
    }
}

impl AuthState {
    /// Keep the login time of the session this `Authenticated` state took
    /// over, so a change of who the session is (an impersonation) does not
    /// restart its absolute age cap. Never later than the state's own
    /// `authn_time`. Returns `false`, changing nothing, from any other state.
    pub(crate) fn keep_signed_in_at(&mut self, at: Timestamp) -> bool {
        let AuthState::Authenticated {
            authn_time,
            signed_in_at,
            ..
        } = self
        else {
            return false;
        };
        *signed_in_at = at.min(*authn_time);
        true
    }
}

/// The method name the pending state of a step-up carries, for audit rows
/// and logs. It is a label: no decision reads it, and a stored login method
/// may carry the same name.
pub(crate) const STEP_UP_LABEL: &str = "step-up";
