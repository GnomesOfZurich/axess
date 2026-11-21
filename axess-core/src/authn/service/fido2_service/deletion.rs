//! Passkey deletion.

use super::{CredentialChange, RequestAuthnService};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    factor::FactorKind,
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};
use crate::session::extractor::AuthSession;

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Delete a FIDO2 credential by its credential ID.
    ///
    /// `session` must be authenticated as `user`, recently enough for
    /// [`Fido2Options::max_authn_age`](crate::authn::factor::Fido2Options::max_authn_age)
    /// when one is set, and not impersonated; a session pending signup
    /// cannot delete. Any other session is refused with
    /// [`AuthnError::NoFlow`] and a failed audit row, and nothing is deleted.
    /// An account that may not log in is refused as an enrolment is
    /// ([`AuthnError::Locked`] or [`AuthnError::NotActive`], with a
    /// `FactorDisabled` row): its credentials are frozen with it.
    ///
    /// Once the passkey is removed its `FactorDisabled` row is written and
    /// its credential-id claim given back. A row that cannot be written is
    /// the error returned, after the claim was released, and is logged at
    /// error level as a removal without its row; a release the store
    /// refuses is logged and does not fail the call.
    #[tracing::instrument(skip(self, user, session, credential_id))]
    pub async fn delete_fido2_credential(
        &self,
        user: &crate::authn::types::User,
        session: &AuthSession,
        credential_id: &webauthn_rs::prelude::CredentialID,
        min_remaining: usize,
    ) -> Result<bool, AuthnError<I::Error>> {
        self.require_enrolment_context(
            user,
            session,
            AuthEventType::FactorDisabled,
            CredentialChange::Removal,
        )
        .await?;
        let status = self.current_account_status(&user.id).await?;
        if !status.allows_login() {
            return Err(self
                .refuse_inactive_account(user, status, AuthEventType::FactorDisabled, Some(session))
                .await);
        }
        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };
        // A failed read or write is an error to the caller, and `Ok(true)`
        // is returned only once the swap that removes the credential has
        // been committed.
        let removed = self
            .update_fido2_credentials(&user_scope, |credentials| {
                let original_len = credentials.len();
                credentials.retain(|c| c.cred_id() != credential_id);
                if credentials.len() == original_len || credentials.len() < min_remaining {
                    return None;
                }
                Some(())
            })
            .await?;
        if removed.is_none() {
            return Ok(false);
        }
        // The passkey is gone once the swap committed, so the row that says
        // the factor was disabled is written now, before anything that could
        // still fail. A row that cannot be written does not stop the claim
        // from being given back: the passkey is removed either way.
        let audited = self
            .emit_audit(
                AuthEventBuilder::success(AuthEventType::FactorDisabled)
                    .attributed_to(&user.id, &user.tenant_id)
                    .with_factor(FactorKind::Fido2)
                    .with_session(session.session_key().await),
            )
            .await;

        // The id is free to register again, to this user or another. A
        // release the store refuses does not undo the removal: the deletion
        // is a success, and the held id is logged so an operator can free it.
        if let Err(error) = self
            .inner
            .factors
            .release_fido2_credential(&user.tenant_id, &user.id, credential_id.as_slice())
            .await
        {
            tracing::warn!(
                tenant_id = %user.tenant_id,
                user_id = %user.id,
                error = %error,
                "passkey deleted but its credential-id claim could not be released; the id \
                 stays held by this user until the store releases it"
            );
        }

        // The caller learns the row is missing, and the log says what the
        // error alone does not: the passkey is already removed.
        if let Err(error) = audited {
            tracing::error!(
                tenant_id = %user.tenant_id,
                user_id = %user.id,
                error = %error,
                "passkey removed but its FactorDisabled audit row could not be written"
            );
            return Err(error);
        }

        Ok(true)
    }
}
