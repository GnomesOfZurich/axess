//! Issuing a refresh token to the user a session is authenticated as.

use super::RequestAuthnService;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    ids::DeviceId,
    store::{FactorStore, IdentityStore},
};
use crate::session::Impersonation;
use crate::session::extractor::AuthSession;
use crate::session::refresh::{
    IssueRequest, RefreshError, RefreshToken, RefreshTokenConfig, RefreshTokenStore,
    issue_refresh_token,
};

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Issue a refresh token to the user `session` is authenticated as.
    ///
    /// The session-aware form of
    /// [`issue_refresh_token`]:
    /// the user and tenant are the session's, not the caller's word, and the
    /// token is minted with the service's RNG and clock. Returns the
    /// plaintext (hand it to the client once) and the stored record.
    ///
    /// A session that is not authenticated is refused with
    /// [`AuthnError::NoFlow`]. One an administrator is impersonating
    /// ([`AuthSession::impersonator`]) is refused with
    /// [`AuthnError::Impersonated`] and a failed `LoginAttempt` row with the
    /// reason `impersonated`, naming the administrator as actor: a refresh
    /// token is a credential of the user that would outlive the
    /// impersonation. A service built with
    /// [`with_impersonated_credential_changes_allowed`](crate::authn::service::AuthnServiceBuilder::with_impersonated_credential_changes_allowed)
    /// issues it.
    ///
    /// # Errors
    ///
    /// `NoFlow` and `Impersonated` as above; [`AuthnError::Internal`] for a configuration that
    /// fails [`RefreshTokenConfig::validate`]; [`AuthnError::ExternalService`]
    /// when the store could not write the token; `Store` when the refusal's
    /// audit row could not be written.
    pub async fn issue_refresh_token<S: RefreshTokenStore>(
        &self,
        session: &AuthSession,
        store: &S,
        config: &RefreshTokenConfig,
        device_info: Option<String>,
        device_id: Option<DeviceId>,
    ) -> Result<(String, RefreshToken), AuthnError<I::Error>> {
        // One read of the session: the user and the impersonation are
        // judged on the same state.
        let Some(snapshot) = session.snapshot().await else {
            return Err(AuthnError::NoFlow);
        };
        if let Some(Impersonation { admin, .. }) = snapshot.impersonation
            && !self.inner.impersonated_credential_changes
        {
            tracing::warn!(
                admin = %admin,
                user_id = %snapshot.user_id,
                "refresh token issuance refused: the session is an impersonation"
            );
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                    .attributed_to(&snapshot.user_id, &snapshot.tenant_id)
                    .with_session(snapshot.session_id)
                    .with_actor(admin)
                    .with_error(AuthFailureReason::Impersonated),
            )
            .await?;
            return Err(AuthnError::Impersonated);
        }
        issue_refresh_token(
            IssueRequest {
                user_id: &snapshot.user_id,
                tenant_id: &snapshot.tenant_id,
                device_info,
                family_id: None,
                device_id,
            },
            config,
            store,
            &self.inner.rng,
            self.inner.clock.now(),
        )
        .await
        .map_err(|e| match e {
            RefreshError::InvalidConfig(why) => {
                AuthnError::Internal(format!("invalid refresh token configuration: {why}"))
            }
            RefreshError::Store(source) => {
                // The store's error goes to the log whole, its source chain
                // included; the caller gets the transient-failure variant.
                tracing::error!(
                    error = &source as &dyn std::error::Error,
                    "the refresh token store could not write the token"
                );
                AuthnError::ExternalService(format!("refresh token store: {source}"))
            }
            // Issuance checks the configuration and writes the token; no
            // other refusal can come back from it.
            other => AuthnError::Internal(format!("refresh token issuance failed: {other}")),
        })
    }
}
