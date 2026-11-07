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
    ///
    /// The age is that of the session's `authn_time`, the moment the most
    /// recent factor completed. After a step-up it is the step-up's, so it
    /// says nothing about how long ago an earlier factor (the password of
    /// the original login) was verified.
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

    /// Whether the session is authenticated and `kind` was verified no more
    /// than `max_age` before `now`: the factor's own time, not the session's
    /// `authn_time`. After a step-up with TOTP, the password of the original
    /// login is as old as that login. A `false` is the cue to call
    /// `begin_step_up` with `kind`.
    pub async fn completed_factor_within(
        &self,
        kind: &FactorKind,
        max_age: std::time::Duration,
        now: DateTime<Utc>,
    ) -> bool {
        self.auth_state()
            .await
            .factor_completed_at(kind)
            .is_some_and(|at| (now - at).to_std().is_ok_and(|age| age <= max_age))
    }

    /// Whether the session is authenticated and `kind` is among the factors
    /// it has completed.
    ///
    /// A factor from the original login still counts after a step-up,
    /// however long ago it was verified. For freshness of one factor use
    /// [`completed_factor_within`](Self::completed_factor_within); for that of
    /// the most recent factor, [`authenticated_within`](Self::authenticated_within).
    pub async fn has_completed_factor(&self, kind: &FactorKind) -> bool {
        matches!(
            self.auth_state().await,
            crate::session::data::AuthState::Authenticated { factors_completed, .. }
                if factors_completed.iter().any(|(k, _)| k == kind)
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
    ///
    /// A FIDO2 factor runs [`Fido2Options::login_ceremony`](crate::authn::factor::Fido2Options::login_ceremony);
    /// [`begin_step_up_for`](Self::begin_step_up_for) names the ceremony.
    #[tracing::instrument(skip(self, session))]
    pub async fn begin_step_up(
        &self,
        session: &AuthSession,
        factors: Vec<FactorKind>,
    ) -> Result<FactorKind, AuthnError<I::Error>> {
        self.begin_step_up_with(session, factors, None).await
    }

    /// Begin the step-up a refusal named: the factor of `step_up` and, for a
    /// FIDO2 step-up, the ceremony it names, which the step's
    /// [`prepare_factor`](Self::prepare_factor) challenge runs instead of
    /// the login ceremony.
    ///
    /// `step_up` is what `require_authz!` or
    /// [`AuthzSession::require_with_step_up`](crate::authz::AuthzSession::require_with_step_up)
    /// answered (`StepUp::from_str` of the `step_up` field). A client that
    /// sends back a weaker one gains nothing: the action is decided again on
    /// what the step-up recorded. Otherwise as [`begin_step_up`](Self::begin_step_up)
    /// with one factor.
    #[tracing::instrument(skip(self, session))]
    pub async fn begin_step_up_for(
        &self,
        session: &AuthSession,
        step_up: &crate::authn::assurance::StepUp,
    ) -> Result<FactorKind, AuthnError<I::Error>> {
        self.begin_step_up_with(
            session,
            vec![step_up.factor_kind()],
            step_up.fido2_ceremony(),
        )
        .await
    }

    async fn begin_step_up_with(
        &self,
        session: &AuthSession,
        factors: Vec<FactorKind>,
        ceremony: Option<&crate::authn::factor::Fido2Ceremony>,
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
            let same_user = guard.data.auth_state.pending_user_id() == Some(&user_id)
                && guard.data.auth_state.tenant_id() == Some(&tenant_id);
            if !same_user || !guard.data.auth_state.is_authenticated() {
                return Err(AuthnError::NoFlow);
            }
            // The step-up's own ceremony, or none so the login ceremony
            // applies, written before the state moves: a ceremony that does
            // not fit the session refuses the step-up and leaves the session
            // as it was.
            let key = crate::session::data::STEP_UP_CEREMONY_KEY;
            match ceremony {
                Some(ceremony) => {
                    if !guard.set_custom_value(key.to_owned(), serde_json::json!(ceremony)) {
                        return Err(AuthnError::NoFlow);
                    }
                }
                None => {
                    if let Some(custom) = guard.data.custom.as_object_mut() {
                        custom.remove(key);
                    }
                }
            }
            if !guard.data.auth_state.begin_step_up(steps) {
                return Err(AuthnError::NoFlow);
            }
            guard.set_custom_value(super::flow::FLOW_KEY.to_owned(), stamp);
            guard.modified = true;
        }
        Ok(first)
    }
}
