//! OAuth refresh-token flow: exchanges a stored refresh token at the IdP
//! for fresh access/ID tokens and updated [`OAuthClaims`].
//!
//! Distinct from the session/HTTP refresh-token flow in
//! [`crate::session::refresh`]: that path issues axess's own refresh
//! tokens against axess sessions; this path delegates to the upstream
//! IdP's `/token` endpoint with the IdP's refresh token.

use crate::authn::service::RequestAuthnService;
use crate::authn::{
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::FactorKind,
    ids::UserId,
    store::{FactorStore, IdentityStore},
};

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Refresh an OAuth token using a stored refresh token.
    ///
    /// Exchanges the refresh token at the IdP's token endpoint for new
    /// access/ID tokens. Validates the new ID token, when the IdP sent one,
    /// and returns it with the rotated tokens.
    ///
    /// # Arguments
    ///
    /// * `provider_name`: Name of the registered OAuth provider.
    /// * `refresh_token`: The refresh token obtained from a previous login
    ///   (stored in [`OAuthClaims::refresh_token`](axess_factors::oauth::OAuthClaims::refresh_token)).
    /// * `expected_subject`: The IdP subject the login recorded
    ///   ([`OAuthClaims::subject`](axess_factors::oauth::OAuthClaims::subject)).
    ///   A response for any other subject is refused (OIDC Core 12.2) and
    ///   audited as a provider rejection.
    /// * `original_nonce`: The `nonce` of the login that produced the refresh
    ///   token (the `nonce` member of
    ///   [`OAuthClaims::additional_claims`](axess_factors::oauth::OAuthClaims::additional_claims)).
    ///   A refresh ID token that carries a nonce must equal it (OIDC Core
    ///   12.2); one without a nonce is accepted, and one with a nonce when
    ///   this is `None` is refused.
    ///
    /// # Returns
    ///
    /// A [`RefreshOutcome`](axess_factors::oauth::RefreshOutcome). Store its
    /// `refresh_token` in place of the one you sent: a rotating IdP has spent
    /// the old one even when the response carries no ID token, in which case
    /// `id_token_claims` is `None` and the claims you already hold stand.
    #[tracing::instrument(skip(self, refresh_token, expected_subject, original_nonce))]
    pub async fn refresh_oauth_token(
        &self,
        provider_name: &str,
        refresh_token: &str,
        expected_subject: &str,
        original_nonce: Option<&str>,
    ) -> Result<axess_factors::oauth::RefreshOutcome, axess_factors::oauth::OAuthError> {
        self.refresh_oauth_token_with_key(
            provider_name,
            refresh_token,
            expected_subject,
            original_nonce,
            None,
        )
        .await
    }

    /// [`refresh_oauth_token`](Self::refresh_oauth_token) for a login whose
    /// tokens are bound to a DPoP key.
    ///
    /// Pass the key the login returned in
    /// [`OAuthClaims::dpop_key`](axess_factors::oauth::OAuthClaims::dpop_key)
    /// (or restored with `DpopKey::from_seed`). The refresh request then
    /// carries a proof signed by it, and the rotated access token is bound to
    /// the same key. A provider configured for DPoP refuses the call without
    /// one, since sending the refresh token unbound would drop the binding.
    #[tracing::instrument(skip(self, refresh_token, expected_subject, original_nonce, dpop_key))]
    pub async fn refresh_oauth_token_with_key(
        &self,
        provider_name: &str,
        refresh_token: &str,
        expected_subject: &str,
        original_nonce: Option<&str>,
        dpop_key: Option<&axess_factors::oauth::DpopKey>,
    ) -> Result<axess_factors::oauth::RefreshOutcome, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        // Every early-return below records a Failure event with a
        // distinguishing reason tag. The original implementation only
        // emitted on the happy path, so SOC dashboards saw no signal for
        // repeated refresh-token failures (a brute-force or
        // stolen-refresh-token signal). Reasons used:
        //   * `token_refresh_no_token`       ; empty refresh_token
        //   * `token_refresh_unknown_provider`; provider_name not registered
        //   * `token_refresh_provider_rejected`; IdP rejected the token
        // Success continues to record `token_refresh` so the two are
        // distinguishable in the audit stream.

        if refresh_token.is_empty() {
            self.record_oauth_refresh_failure(
                AuthFailureReason::TokenRefreshNoToken,
                provider_name,
            )
            .await?;
            return Err(OAuthError::NoRefreshToken);
        }

        let Some(provider) = self.inner.oauth_providers.get(provider_name) else {
            self.record_oauth_refresh_failure(
                AuthFailureReason::TokenRefreshUnknownProvider,
                provider_name,
            )
            .await?;
            return Err(OAuthError::UnknownProvider(provider_name.to_string()));
        };
        let provider = provider.clone();

        let signer = dpop_key.map(|key| axess_factors::oauth::DpopSigner {
            key,
            rng: &*self.inner.rng,
        });
        let outcome = match provider
            .refresh_token_for_subject_with(refresh_token, expected_subject, original_nonce, signer)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                self.record_oauth_refresh_failure(
                    AuthFailureReason::TokenRefreshProviderRejected,
                    provider_name,
                )
                .await?;
                return Err(e);
            }
        };

        let subject_user = UserId::try_new(expected_subject).ok();
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::LoginAttempt)
                .maybe_attributed_to(subject_user.as_ref(), None)
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(provider_name.into()),
                ))
                .with_error(AuthFailureReason::TokenRefresh),
        )
        .await
        .map_err(|e| OAuthError::AuditStore(e.to_string()))?;

        Ok(outcome)
    }

    /// Record an OAuth refresh-token failure audit event.
    ///
    /// Mirrors [`record_oauth_failure`](super::login::RequestAuthnService::record_oauth_failure)
    /// but session-free: the refresh path is called with just a provider
    /// name and a token, with no `AuthSession` to source attribution from.
    async fn record_oauth_refresh_failure(
        &self,
        reason: AuthFailureReason,
        provider_name: &str,
    ) -> Result<(), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;
        // No session in this path → no attribution. `failure(type)`
        // already builds an unattributed shape; `maybe_attributed_to`
        // is unnecessary.
        self.emit_audit(
            AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(provider_name.into()),
                ))
                .with_error(reason),
        )
        .await
        .map_err(|e| OAuthError::AuditStore(e.to_string()))
    }
}
