//! OIDC UserInfo endpoint passthrough.
//!
//! Thin wrapper: looks up the configured provider, validates the
//! access token isn't empty, delegates to the provider's
//! [`fetch_userinfo`](axess_factors::oauth::OAuthProvider::fetch_userinfo).
//! HTTP 401 / 403 / non-2xx errors are mapped to typed [`OAuthError`]
//! variants so callers can branch on token-expired vs
//! insufficient-scope vs other failures.

use crate::authn::service::AuthnService;
use crate::authn::store::{FactorStore, IdentityStore};

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Fetch additional user claims from the OIDC UserInfo endpoint.
    ///
    /// Calls the provider's UserInfo endpoint using the access token obtained
    /// during login. Returns [`UserInfoClaims`](axess_factors::oauth::UserInfoClaims) with standard OIDC profile
    /// claims plus any provider-specific claims.
    ///
    /// # Arguments
    ///
    /// * `provider_name`: Name of the registered OAuth provider.
    /// * `access_token`: The access token from [`OAuthClaims::access_token`](axess_factors::oauth::OAuthClaims::access_token).
    ///
    /// # Errors
    ///
    /// * [`OAuthError::NoAccessToken`](axess_factors::oauth::OAuthError::NoAccessToken): empty access token.
    /// * [`OAuthError::UnknownProvider`](axess_factors::oauth::OAuthError::UnknownProvider): provider not registered.
    /// * [`OAuthError::AccessTokenExpired`](axess_factors::oauth::OAuthError::AccessTokenExpired): token expired or invalid (HTTP 401).
    /// * [`OAuthError::InsufficientScope`](axess_factors::oauth::OAuthError::InsufficientScope): missing required scope (HTTP 403).
    /// * [`OAuthError::UserInfo`](axess_factors::oauth::OAuthError::UserInfo): other HTTP or parse errors.
    #[tracing::instrument(skip(self, access_token))]
    pub async fn fetch_userinfo(
        &self,
        provider_name: &str,
        access_token: &str,
    ) -> Result<axess_factors::oauth::UserInfoClaims, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        if access_token.is_empty() {
            return Err(OAuthError::NoAccessToken);
        }

        let provider = self
            .oauth_providers
            .get(provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.to_string()))?
            .clone();

        provider.fetch_userinfo(access_token).await
    }
}
