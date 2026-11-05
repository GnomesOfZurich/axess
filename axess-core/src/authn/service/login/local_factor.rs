//! Verifying a factor against a stored secret (a password hash, a TOTP
//! seed, recovery codes): what [`verify_factor`](super::super::RequestAuthnService::verify_factor)
//! does once the guess is reserved.

use super::super::factor_secrets;
use super::super::outcomes::FactorOutcome;
use super::super::verification::{VerifyOutcome, verify_credential_blocking};
use super::PreparedFactorStep;
use crate::authn::{
    error::AuthnError,
    factor::FactorCredential,
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;

impl<I, F> super::super::RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Open the factor's secret, verify the credential against it, persist
    /// what the verification changed and, on a pass, give back the reserved
    /// guess and advance the flow. A failure is recorded against the guess
    /// `reserved` holds.
    pub(super) async fn verify_local_factor(
        &self,
        credential: &FactorCredential,
        session: &AuthSession,
        user_id: &UserId,
        tenant_id: &TenantId,
        step: PreparedFactorStep,
        reserved: Option<u32>,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let PreparedFactorStep {
            current_kind,
            user_scope,
            resolved_from,
            config,
        } = step;

        let cipher = self.inner.factor_secret_cipher.as_deref();
        let opened = factor_secrets::open(
            cipher,
            &config,
            &resolved_from,
            &user_scope,
            &current_kind,
        )
        .map_err(|e| {
            tracing::error!(error = %e, factor = %current_kind, "factor secret cannot be opened");
            AuthnError::Internal(e.to_string())
        })?;

        self.inner.metrics.factor_attempt();
        let outcome = verify_credential_blocking(
            &self.inner.kdf,
            credential,
            &opened.verify,
            &current_kind,
            self.inner.clock.now(),
            &self.inner.recovery_peppers,
        )
        .await?;

        let close = |updated: crate::authn::factor::FactorConfig| -> Result<crate::authn::factor::FactorConfig, AuthnError<I::Error>> {
            factor_secrets::close(cipher, &opened, updated, &user_scope, &current_kind)
                .map_err(|e| {
                    tracing::error!(error = %e, factor = %current_kind, "factor secret cannot be sealed");
                    AuthnError::Internal(e.to_string())
                })
        };

        if let VerifyOutcome::FailWithUpdate(updated_config) = &outcome {
            let updated_config = close(updated_config.clone())?;
            self.persist_fail_with_update(&user_scope, current_kind.clone(), &updated_config)
                .await?;
        }

        if matches!(
            outcome,
            VerifyOutcome::Fail | VerifyOutcome::FailWithUpdate(_)
        ) {
            return self
                .record_factor_failure_after(reserved, user_id, tenant_id, &current_kind, session)
                .await;
        }

        if let VerifyOutcome::PassWithUpdate(updated_config) = outcome {
            if let crate::authn::factor::FactorConfig::RecoveryCodes(codes) = &updated_config
                && codes.under_previous_pepper
            {
                // The set is sealed under a retired secret and cannot be
                // re-keyed; the application has the user regenerate it.
                self.inner.metrics.recovery_codes_under_previous_pepper();
                tracing::warn!(
                    user_id = %user_id,
                    "recovery code matched under the previous pepper; the set should be regenerated"
                );
            }
            let updated_config = close(updated_config)?;
            let swapped = self
                .persist_pass_with_update(&user_scope, &config, &resolved_from, updated_config)
                .await?;
            if !swapped {
                // Concurrent verification spent the same step/counter
                // first; treat as a replay: audited, counted against the
                // lockout and rejected like any other failed guess.
                return self
                    .record_factor_failure_after(
                        reserved,
                        user_id,
                        tenant_id,
                        &current_kind,
                        session,
                    )
                    .await;
            }
        }

        // Counted once the pass stands: a swap lost to a concurrent request
        // is a failure, answered above.
        self.inner.metrics.factor_success();

        self.release_guess(reserved, user_id).await;
        self.rehash_outdated_password(credential, &config, &resolved_from, user_id, tenant_id)
            .await;

        session
            .advance_factor(
                &current_kind,
                self.inner.clock.now(),
                &self.inner.preserved_custom_keys,
            )
            .await;
        self.complete_factor_step(user_id, tenant_id, session).await
    }
}
