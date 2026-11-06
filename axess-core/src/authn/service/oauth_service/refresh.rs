//! OAuth refresh-token flow: exchanges a stored refresh token at the IdP
//! for fresh access/ID tokens and updated [`OAuthClaims`].
//!
//! Distinct from the session/HTTP refresh-token flow in
//! [`crate::session::refresh`]: that path issues axess's own refresh
//! tokens against axess sessions; this path delegates to the upstream
//! IdP's `/token` endpoint with the IdP's refresh token.

use super::scoped::Scope;
use crate::authn::service::RequestAuthnService;
use crate::authn::{
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::FactorKind,
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
    ///   token ([`OAuthClaims::nonce`](axess_factors::oauth::OAuthClaims::nonce),
    ///   stored beside the refresh token).
    ///   A refresh ID token that carries a nonce must equal it (OIDC Core
    ///   12.2); one without a nonce is accepted, and one with a nonce when
    ///   this is `None` is refused.
    /// * `dpop_key`: The key the login's tokens are bound to, for a provider
    ///   that binds them to a DPoP key: the one the login returned in
    ///   [`OAuthClaims::dpop_key`](axess_factors::oauth::OAuthClaims::dpop_key),
    ///   or restored with `DpopKey::from_seed`. The refresh request carries a
    ///   proof signed by it, and the rotated access token is bound to the
    ///   same key. `None` for a provider that does not bind.
    ///
    /// # Returns
    ///
    /// A [`RefreshOutcome`](axess_factors::oauth::RefreshOutcome). Store its
    /// `refresh_token` in place of the one you sent: a rotating IdP has spent
    /// the old one even when the response carries no ID token, in which case
    /// `id_token_claims` is `None` and the claims you already hold stand.
    ///
    /// # Errors
    ///
    /// [`OAuthError::DpopKeyRequired`](axess_factors::oauth::OAuthError::DpopKeyRequired)
    /// when the provider binds tokens and `dpop_key` is `None`, refused
    /// before anything is sent and audited as `token_refresh_dpop_key_missing`;
    /// the provider's own errors otherwise.
    #[tracing::instrument(skip(self, refresh_token, expected_subject, original_nonce, dpop_key))]
    pub async fn refresh_oauth_token(
        &self,
        provider_name: &str,
        refresh_token: &str,
        expected_subject: &str,
        original_nonce: Option<&str>,
        dpop_key: Option<&axess_factors::oauth::DpopKey>,
    ) -> Result<axess_factors::oauth::RefreshOutcome, axess_factors::oauth::OAuthError> {
        self.refresh_scoped(
            &Scope::global(),
            provider_name,
            refresh_token,
            expected_subject,
            original_nonce,
            dpop_key,
        )
        .await
    }

    /// The refresh both the by-name methods and [`ScopedOAuth`](super::ScopedOAuth)
    /// run; `scope` says whose provider `provider_name` names.
    pub(super) async fn refresh_scoped(
        &self,
        scope: &Scope,
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
        //   * `token_refresh_dpop_key_missing`; a binding provider, no key
        // Success continues to record `token_refresh` so the two are
        // distinguishable in the audit stream.

        if refresh_token.is_empty() {
            self.record_oauth_refresh_failure(
                AuthFailureReason::TokenRefreshNoToken,
                provider_name,
                scope,
            )
            .await?;
            return Err(OAuthError::NoRefreshToken);
        }

        let provider = match self.scoped_provider(scope, provider_name).await {
            Ok(provider) => provider,
            Err(e) => {
                let reason = if matches!(e, OAuthError::UnknownProvider(_)) {
                    AuthFailureReason::TokenRefreshUnknownProvider
                } else {
                    AuthFailureReason::TokenRefreshProviderRejected
                };
                self.record_oauth_refresh_failure(reason, provider_name, scope)
                    .await?;
                return Err(e);
            }
        };

        let signer = dpop_key.map(|key| axess_factors::oauth::DpopSigner {
            key,
            rng: &*self.inner.rng,
        });
        let outcome = match provider
            .refresh_token(refresh_token, expected_subject, original_nonce, signer)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                // A refusal before anything was sent is the caller's fault,
                // not the IdP's verdict on the token: a SOC reading
                // "provider rejected" would chase a stolen token.
                let reason = if matches!(e, OAuthError::DpopKeyRequired) {
                    AuthFailureReason::TokenRefreshDpopKeyMissing
                } else {
                    AuthFailureReason::TokenRefreshProviderRejected
                };
                self.record_oauth_refresh_failure(reason, provider_name, scope)
                    .await?;
                return Err(e);
            }
        };

        // The IdP subject is never a local user id; the row names the user
        // and tenant the scope was given (`as_user`, `oauth_in_tenant`, or
        // the authenticated session behind `oauth_for_session`).
        let (user, tenant) = scope.attribution();
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::LoginAttempt)
                .maybe_attributed_to(user, tenant)
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
    /// but session-free: the refresh path is called with a provider name and
    /// a token, and the user and tenant the scope was given.
    async fn record_oauth_refresh_failure(
        &self,
        reason: AuthFailureReason,
        provider_name: &str,
        scope: &Scope,
    ) -> Result<(), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;
        let (user, tenant) = scope.attribution();
        self.emit_audit(
            AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                .maybe_attributed_to(user, tenant)
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(provider_name.into()),
                ))
                .with_error(reason),
        )
        .await
        .map_err(|e| OAuthError::AuditStore(e.to_string()))
    }
}
