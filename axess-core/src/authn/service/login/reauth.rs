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
};
use crate::session::extractor::AuthSession;
use chrono::{DateTime, Utc};

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
    /// `factors` are alternatives: the user completes any one of them. The
    /// session must be `Authenticated`; any other state is
    /// [`AuthnError::NoFlow`], as is an empty `factors`. It becomes
    /// `Authenticating` with that single step remaining and every factor
    /// completed so far remembered. Drive it with
    /// [`prepare_factor`](Self::prepare_factor) and
    /// [`verify_factor`](Self::verify_factor): a wrong code is an ordinary
    /// failure (counted, audited, lockout applies), and the right one
    /// returns [`FactorOutcome::Authenticated`](crate::authn::service::FactorOutcome::Authenticated)
    /// with `factors_completed` holding the earlier factors and the new one,
    /// a later authentication time, and a rotated session id.
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
        let first = factors[0].clone();
        let step = if factors.len() == 1 {
            FactorStep::Required(first.clone())
        } else {
            FactorStep::AnyOf(factors)
        };

        let (user_id, tenant_id) = {
            let guard = session.0.0.write().await;
            let ids = match guard
                .data
                .auth_state
                .user_id()
                .zip(guard.data.auth_state.tenant_id())
            {
                Some((u, t)) if guard.data.auth_state.is_authenticated() => (*u, *t),
                _ => return Err(AuthnError::NoFlow),
            };
            // The stamp is computed from the store before the state moves.
            ids
        };
        let epoch = self
            .credential_epoch(&user_id, &tenant_id, "step-up")
            .await?;
        self.stamp_flow(session, "step-up", epoch).await;
        {
            let mut guard = session.0.0.write().await;
            if !guard.data.auth_state.begin_step_up(vec![step]) {
                return Err(AuthnError::NoFlow);
            }
            guard.modified = true;
        }
        Ok(first)
    }
}
