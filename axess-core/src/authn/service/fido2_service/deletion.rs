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
        // The id is free to register again, to this user or another.
        self.inner
            .factors
            .release_fido2_credential(&user.tenant_id, &user.id, credential_id.as_slice())
            .await
            .map_err(AuthnError::Store)?;

        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::FactorDisabled)
                .attributed_to(&user.id, &user.tenant_id)
                .with_factor(FactorKind::Fido2)
                .with_session(session.session_id().await),
        )
        .await?;

        Ok(true)
    }
}
