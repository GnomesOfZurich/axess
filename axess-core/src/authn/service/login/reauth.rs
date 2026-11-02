//! Step-up: ask an already authenticated session for another factor.
//!
//! [`begin_step_up`](crate::authn::service::RequestAuthnService::begin_step_up)
//! moves an `Authenticated` session back into `Authenticating` with the
//! requested factors as its remaining step. The ordinary
//! `prepare_factor` and `verify_factor` calls then drive it, and finishing
//! the step yields an `Authenticated` session again, with a fresh
//! authentication time and every factor completed so far.

use crate::authn::{
    error::AuthnError,
    factor::{FactorKind, FactorStep},
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};
use crate::session::extractor::AuthSession;
use chrono::{DateTime, Utc};

/// The method name a step-up runs under; it names no stored method.
const STEP_UP_METHOD: &str = "step-up";

impl AuthSession {
    /// Whether the session is authenticated and its authentication (or last
    /// step-up) was no more than `max_age` before `now`.
    ///
    /// Pass the service's clock reading as `now`. A `false` is the cue to
    /// call `begin_step_up`.
    pub async fn authenticated_within(
        &self,
        max_age: std::time::Duration,
        now: DateTime<Utc>,
    ) -> bool {
        let Some(snapshot) = self.snapshot().await else {
            return false;
        };
        (now - snapshot.authn_time)
            .to_std()
            .is_ok_and(|age| age <= max_age)
    }

    /// Whether the session is authenticated and `kind` is among the factors
    /// it has completed.
    pub async fn has_completed_factor(&self, kind: &FactorKind) -> bool {
        matches!(
            self.auth_state().await,
            crate::session::data::AuthState::Authenticated { factors_completed, .. }
                if factors_completed.contains(kind)
        )
    }
}

impl<I, F> crate::authn::service::RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Ask an authenticated session for another factor before a sensitive
    /// action.
    ///
    /// `factors` are alternatives: the user completes any one of them. Only
    /// the factors the user has enrolled are asked for (a factor nobody can
    /// satisfy would leave the session unable to finish); when none of them
    /// is enrolled the call is [`AuthnError::NoFlow`] and the session is
    /// left as it was. The session must be `Authenticated`; any other state
    /// is `NoFlow`, as is an empty `factors`. It becomes `Authenticating`
    /// with that single step remaining and every factor completed so far
    /// remembered, and the step is stamped like a login: a password
    /// replaced while it is open drops it. Drive it with
    /// [`prepare_factor`](Self::prepare_factor) and
    /// [`verify_factor`](Self::verify_factor): a wrong code is an ordinary
    /// failure (counted, audited, lockout applies), and the right one
    /// returns [`FactorOutcome::Authenticated`](crate::authn::service::FactorOutcome::Authenticated)
    /// with `factors_completed` holding the earlier factors and the new one,
    /// a later authentication time, and a rotated session id. The answer
    /// is the first enrolled factor of `factors`, the one to prompt for.
    ///
    /// Until the step is finished the session is not authenticated, so an
    /// abandoned step-up ends the session's access: the caller shows the
    /// prompt on a dedicated page rather than inline.
    ///
    /// Gate the sensitive action with
    /// [`authenticated_within`](AuthSession::authenticated_within) or
    /// [`has_completed_factor`](AuthSession::has_completed_factor) and call
    /// this when it says no.
    #[tracing::instrument(skip(self, session))]
    pub async fn begin_step_up(
        &self,
        session: &AuthSession,
        factors: Vec<FactorKind>,
    ) -> Result<FactorKind, AuthnError<I::Error>> {
        if factors.is_empty() {
            return Err(AuthnError::NoFlow);
        }
        let Some(snapshot) = session.snapshot().await else {
            return Err(AuthnError::NoFlow);
        };
        let (user_id, tenant_id) = (snapshot.user_id, snapshot.tenant_id);

        // Only a factor the user can complete is asked for.
        let scope = AuthnScope::User { tenant_id, user_id };
        let mut enrolled = Vec::with_capacity(factors.len());
        for kind in factors {
            let present = self
                .inner
                .factors
                .resolve_factor(&scope, kind.clone())
                .await
                .map_err(AuthnError::Store)?
                .is_some();
            if present {
                enrolled.push(kind);
            } else {
                tracing::debug!(user_id = %user_id, factor = %kind, "step-up: factor not enrolled");
            }
        }
        let Some(first) = enrolled.first().cloned() else {
            tracing::warn!(user_id = %user_id, "step-up refused: none of the factors is enrolled");
            return Err(AuthnError::NoFlow);
        };
        let step = if enrolled.len() == 1 {
            FactorStep::Required(first.clone())
        } else {
            FactorStep::AnyOf(enrolled)
        };
        let steps = vec![step];

        // The stamp is computed from the store before the state moves, and
        // written in the same critical section as the move: a session
        // logged out or cleared meanwhile is refused there, and a refusal
        // leaves no stamp behind.
        let stamp = self
            .stamp_for_steps(&user_id, &tenant_id, STEP_UP_METHOD, &steps)
            .await?;
        {
            let mut guard = session.0.0.write().await;
            let same_user = guard.data.auth_state.user_id() == Some(&user_id)
                && guard.data.auth_state.tenant_id() == Some(&tenant_id);
            if !same_user || !guard.data.auth_state.begin_step_up(steps) {
                return Err(AuthnError::NoFlow);
            }
            guard.set_custom_value(super::flow::FLOW_KEY.to_owned(), stamp);
            guard.modified = true;
        }
        Ok(first)
    }
}
