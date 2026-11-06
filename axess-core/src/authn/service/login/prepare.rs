//! The step a credential is for, with the account's status enforced first;
//! split out of `verify_factor` so each half stays readable.

use crate::authn::error::AuthnError;
use crate::authn::factor::FactorCredential;
use crate::authn::factor::FactorKind;
use crate::authn::factor::FactorStep;
use crate::authn::service::outcomes::FactorOutcome;
use crate::authn::store::FactorStore;
use crate::authn::store::IdentityStore;
use crate::authn::types::AuthnScope;
use crate::session::extractor::AuthSession;

/// The session key holding the factor the person chose at the current step.
pub(super) const CHOSEN_FACTOR: &str = "axess.factor.chosen";

/// What `prepare_factor_step` resolved for a credential: the factor kind the
/// step takes it as, the user scope, and the factor configuration with where
/// it was found.
pub(super) struct PreparedFactorStep {
    pub(super) current_kind: FactorKind,
    pub(super) user_scope: AuthnScope,
    pub(super) resolved_from: AuthnScope,
    pub(super) config: crate::authn::factor::FactorConfig,
}

impl<I, F> crate::authn::service::RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Record the factor `kind` the person chose (and had prepared) at the
    /// step with `steps_left` steps remaining; `None` forgets a choice.
    /// `false` when the choice could not be kept, in which case the caller
    /// must not hand out a challenge a verification could not match.
    pub(super) async fn record_chosen_factor(
        session: &AuthSession,
        user_id: &crate::authn::ids::UserId,
        steps_left: usize,
        kind: Option<&FactorKind>,
    ) -> bool {
        let Some(kind) = kind else {
            session.remove_custom(CHOSEN_FACTOR).await;
            return true;
        };
        let value = serde_json::json!({
            "kind": kind,
            "user": user_id.to_string(),
            "steps_left": steps_left,
        });
        session.set_custom(CHOSEN_FACTOR, value).await
    }

    /// The factor the person chose for the step with `steps_left` steps
    /// remaining, if one was recorded for this user at this step.
    async fn chosen_factor(
        session: &AuthSession,
        user_id: &crate::authn::ids::UserId,
        steps_left: usize,
    ) -> Option<FactorKind> {
        let value = session.get_custom(CHOSEN_FACTOR).await?;
        if value.get("user")?.as_str()? != user_id.to_string()
            || value.get("steps_left")?.as_u64()? != steps_left as u64
        {
            return None;
        }
        serde_json::from_value(value.get("kind")?.clone()).ok()
    }

    /// The step a credential is for, with the account's status enforced first:
    /// `Err(outcome)` is the answer to give (`Locked`), `Ok` carries the
    /// resolved factor. Split out of `verify_factor` so each half stays
    /// readable.
    pub(super) async fn prepare_factor_step(
        &self,
        credential: &FactorCredential,
        user_id: &crate::authn::ids::UserId,
        tenant_id: &crate::authn::ids::TenantId,
        remaining: &[FactorStep],
        session: &AuthSession,
    ) -> Result<Result<PreparedFactorStep, FactorOutcome>, AuthnError<I::Error>> {
        use crate::authn::service::factor_pipeline::AccountStatusEnforcement;
        match self
            .enforce_account_status(
                user_id,
                tenant_id,
                remaining.first().and_then(FactorStep::primary).cloned(),
                session,
            )
            .await?
        {
            AccountStatusEnforcement::Ok => {}
            AccountStatusEnforcement::Locked { until, .. } => {
                return Ok(Err(FactorOutcome::Locked { until }));
            }
            AccountStatusEnforcement::Throttled { retry_after } => {
                return Ok(Err(FactorOutcome::Throttled { retry_after }));
            }
            AccountStatusEnforcement::NotActive(status) => {
                return Err(AuthnError::NotActive(status));
            }
        }

        // The step's factor the credential is for: the required one, or the
        // choice its shape fits (a recovery code at an `AnyOf([Totp,
        // RecoveryCode])` step). A credential no choice fits is wrong for
        // this step, and fails like a wrong code.
        let step = remaining.first().ok_or(AuthnError::NoFlow)?;
        // The factor the person chose and had prepared (an email code at an
        // `AnyOf([Totp, EmailOtp])` step) is the one the code is checked
        // against, not whichever choice is listed first.
        let chosen = Self::chosen_factor(session, user_id, remaining.len())
            .await
            .filter(|kind| step.accepts(kind) && credential.fits(kind));
        let current_kind = match chosen.or_else(|| step.kind_for(credential)) {
            Some(kind) => kind,
            None => step.primary().cloned().ok_or(AuthnError::NoFlow)?,
        };

        // Runtime resolution: User → Tenant → System, single-query in the store.
        let user_scope = AuthnScope::User {
            tenant_id: *tenant_id,
            user_id: *user_id,
        };
        let resolved = self
            .inner
            .factors
            .resolve_factor(&user_scope, current_kind.clone())
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?;
        Ok(Ok(PreparedFactorStep {
            current_kind,
            user_scope,
            resolved_from: resolved.resolved_from,
            config: resolved.config,
        }))
    }
}
