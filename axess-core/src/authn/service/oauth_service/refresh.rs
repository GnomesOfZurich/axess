//! OAuth refresh-token flow: exchanges a stored refresh token at the IdP
//! for fresh access/ID tokens and updated [`OAuthClaims`].
//!
//! Distinct from the session/HTTP refresh-token flow in
//! [`crate::session::refresh`]: that path issues axess's own refresh
//! tokens against axess sessions; this path delegates to the upstream
//! IdP's `/token` endpoint with the IdP's refresh token.

use crate::authn::service::AuthnService;
use crate::authn::{
    event::{AuthEventBuilder, AuthEventType},
    factor::FactorKind,
    ids::UserId,
    store::{FactorStore, IdentityStore},
};

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Refresh an OAuth token using a stored refresh token.
    ///
    /// Exchanges the refresh token at the IdP's token endpoint for new
    /// access/ID tokens. Validates the new ID token and returns updated
    /// claims (groups, roles, expiry, etc.).
    ///
    /// # Arguments
    ///
    /// * `provider_name`: Name of the registered OAuth provider.
    /// * `refresh_token`: The refresh token obtained from a previous login
    ///   (stored in [`OAuthClaims::refresh_token`](axess_factors::oauth::OAuthClaims::refresh_token)).
    ///
    /// # Returns
    ///
    /// Updated [`OAuthClaims`](axess_factors::oauth::OAuthClaims) with fresh groups, roles, and (if the IdP
    /// rotates refresh tokens) a new refresh token in
    /// [`OAuthClaims::refresh_token`](axess_factors::oauth::OAuthClaims::refresh_token).
    #[tracing::instrument(skip(self, refresh_token))]
    pub async fn refresh_oauth_token(
        &self,
        provider_name: &str,
        refresh_token: &str,
    ) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
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
            self.record_oauth_refresh_failure("token_refresh_no_token", provider_name)
                .await;
            return Err(OAuthError::NoRefreshToken);
        }

        let Some(provider) = self.oauth_providers.get(provider_name) else {
            self.record_oauth_refresh_failure("token_refresh_unknown_provider", provider_name)
                .await;
            return Err(OAuthError::UnknownProvider(provider_name.to_string()));
        };
        let provider = provider.clone();

        let claims = match provider.refresh_token(refresh_token).await {
            Ok(c) => c,
            Err(e) => {
                self.record_oauth_refresh_failure("token_refresh_provider_rejected", provider_name)
                    .await;
                return Err(e);
            }
        };

        let subject_user = UserId::try_new(claims.subject.as_str()).ok();
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::LoginAttempt)
                .maybe_attributed_to(subject_user.as_ref(), None)
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(provider_name.into()),
                ))
                .with_error("token_refresh"),
        )
        .await;

        Ok(claims)
    }

    /// Record an OAuth refresh-token failure audit event.
    ///
    /// Mirrors [`record_oauth_failure`](super::login::AuthnService::record_oauth_failure)
    /// but session-free: the refresh path is called with just a provider
    /// name and a token, with no `AuthSession` to source attribution from.
    async fn record_oauth_refresh_failure(&self, reason: &str, provider_name: &str) {
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
        .await;
    }
}
