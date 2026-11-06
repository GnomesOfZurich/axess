//! The gate every passkey enrolment and removal passes: the session must be
//! the user's own, and the account must be one that may log in.

use super::RequestAuthnService;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::FactorKind,
    ids::UserId,
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;

/// What a credential change does, which decides which sessions may make it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CredentialChange {
    /// Beginning or finishing a registration: a session pending signup for
    /// the user may make it, so a signup enrols its first passkey.
    Enrolment,
    /// Deleting a credential: only a fully authenticated session may.
    Removal,
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Audit and name the refusal of a passkey ceremony for an account that
    /// may not log in. A lockout carries `Locked` (with its `until`), the
    /// other non-active states a `Failure` tagged `NotActive`, so a dashboard
    /// separates brute-force probes from administrative-state mismatches.
    /// `event` is the kind of the operation refused: `FactorEnabled` for
    /// beginning an enrolment, `FactorSetup` for finishing one,
    /// `FactorDisabled` for a deletion and `FactorVerified` for a login, so
    /// the refusal sits beside the operation's own rows. A failed audit
    /// write is returned in place of the refusal.
    pub(super) async fn refuse_inactive_account(
        &self,
        user: &crate::authn::types::User,
        status: crate::authn::types::EntityState,
        event: AuthEventType,
        session: Option<&AuthSession>,
    ) -> AuthnError<I::Error> {
        let builder = if status.is_suspended() {
            AuthEventBuilder::locked(event)
        } else {
            AuthEventBuilder::failure(event).with_error(AuthFailureReason::NotActive)
        };
        let mut builder = builder
            .attributed_to(&user.id, &user.tenant_id)
            .with_factor(FactorKind::Fido2);
        if let Some(session) = session {
            builder = builder.with_session(session.session_id().await);
        }
        if let Err(e) = self.emit_audit(builder).await {
            return e;
        }
        if let crate::authn::types::EntityState::Suspended(detail) = &status {
            self.inner.metrics.auth_flow.account_locked();
            return AuthnError::Locked {
                until: detail.until,
            };
        }
        AuthnError::NotActive(status)
    }

    /// Require that `session` may enrol or remove passkeys for `user`.
    ///
    /// The session must be [`Authenticated`](crate::session::data::AuthState::Authenticated)
    /// as that very user (same id and tenant); for an
    /// [`Enrolment`](CredentialChange::Enrolment) a session pending signup
    /// for that user also passes, so a signup can enrol its first passkey,
    /// where a [`Removal`](CredentialChange::Removal) needs the full
    /// authentication. A `User` the caller built or fetched is never trusted
    /// on its own: a handler that looks a user up by a request parameter
    /// cannot enrol a passkey on someone else's account. An impersonated
    /// session is refused, whoever it is authenticated as, unless the service
    /// was built with
    /// [`with_impersonated_credential_changes_allowed`](crate::authn::service::AuthnServiceBuilder::with_impersonated_credential_changes_allowed):
    /// an administrator does not change a user's credentials in their name,
    /// and the refusal row names the administrator as actor. With
    /// [`Fido2Options::max_authn_age`](crate::authn::factor::Fido2Options::max_authn_age)
    /// set, an authentication older than it is refused and must step up
    /// first. A refusal writes a failed audit row naming the reason and
    /// answers [`AuthnError::Impersonated`] for an impersonated session,
    /// [`AuthnError::NoFlow`] otherwise.
    pub(super) async fn require_enrolment_context(
        &self,
        user: &crate::authn::types::User,
        session: &AuthSession,
        event: AuthEventType,
        change: CredentialChange,
    ) -> Result<(), AuthnError<I::Error>> {
        use crate::session::data::{AuthState, WorkflowKind};
        // An administrator impersonating the user is the user's session to
        // every other check; a factor they enrol or delete is a credential
        // change the user never made, so it is refused unless the deployment
        // opted in. Every refusal row of such a session names the
        // administrator.
        let (authn_time, impersonator) = match session.auth_state().await {
            AuthState::Authenticated {
                user_id,
                tenant_id,
                authn_time,
                impersonator,
                ..
            } if user_id == user.id && tenant_id == user.tenant_id => {
                (Some(authn_time), impersonator.map(|i| i.admin))
            }
            AuthState::PendingWorkflow {
                user_id,
                tenant_id,
                workflow,
            } if change == CredentialChange::Enrolment
                && workflow.kind == WorkflowKind::Signup
                && user_id == user.id
                && tenant_id == user.tenant_id =>
            {
                (None, None)
            }
            _ => {
                return self
                    .refuse_credential_change(
                        user,
                        session,
                        event,
                        AuthFailureReason::EnrolmentContext,
                        None,
                    )
                    .await;
            }
        };
        if impersonator.is_some() && !self.inner.impersonated_credential_changes {
            return self
                .refuse_credential_change(
                    user,
                    session,
                    event,
                    AuthFailureReason::Impersonated,
                    impersonator,
                )
                .await;
        }
        if let (Some(limit), Some(at)) = (self.inner.fido2_options.max_authn_age, authn_time) {
            let age = self.inner.clock.now().signed_duration_since(at);
            let limit = chrono::Duration::from_std(limit).unwrap_or(chrono::Duration::MAX);
            if age > limit {
                return self
                    .refuse_credential_change(
                        user,
                        session,
                        event,
                        AuthFailureReason::AuthnTooOld,
                        impersonator,
                    )
                    .await;
            }
        }
        Ok(())
    }

    /// The failed audit row and the error a refused credential change
    /// answers with: [`Impersonated`](AuthnError::Impersonated) for the
    /// impersonation refusal, [`NoFlow`](AuthnError::NoFlow) otherwise. A row
    /// written under impersonation names the administrator (`impersonator`)
    /// as actor.
    async fn refuse_credential_change(
        &self,
        user: &crate::authn::types::User,
        session: &AuthSession,
        event: AuthEventType,
        reason: AuthFailureReason,
        impersonator: Option<UserId>,
    ) -> Result<(), AuthnError<I::Error>> {
        let error = match reason {
            AuthFailureReason::Impersonated => AuthnError::Impersonated,
            _ => AuthnError::NoFlow,
        };
        let mut builder = AuthEventBuilder::failure(event)
            .attributed_to(&user.id, &user.tenant_id)
            .with_factor(FactorKind::Fido2)
            .with_session(session.session_id().await)
            .with_error(reason);
        if let Some(admin) = impersonator {
            builder = builder.with_actor(admin);
        }
        self.emit_audit(builder).await?;
        Err(error)
    }
}
