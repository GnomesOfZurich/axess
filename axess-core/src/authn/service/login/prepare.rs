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
            AccountStatusEnforcement::NotActive(status) => {
                return Err(AuthnError::NotActive(status));
            }
        }

        // The step's factor the credential is for: the required one, or the
        // choice its shape fits (a recovery code at an `AnyOf([Totp,
        // RecoveryCode])` step). A credential no choice fits is wrong for
        // this step, and fails like a wrong code.
        let step = remaining.first().ok_or(AuthnError::NoFlow)?;
        let current_kind = match step.kind_for(credential) {
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
