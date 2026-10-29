//! OIDC UserInfo endpoint passthrough.
//!
//! Thin wrapper: looks up the configured provider, validates the
//! access token isn't empty, delegates to the provider's
//! [`fetch_userinfo_for_subject`](axess_factors::oauth::OAuthProvider::fetch_userinfo_for_subject).
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
    /// * `expected_subject`: The `sub` of the ID token the login verified
    ///   ([`OAuthClaims::subject`](axess_factors::oauth::OAuthClaims::subject)).
    ///   A response for any other subject is refused (OIDC Core 5.3.2): a
    ///   substituted token or a mis-routed proxy would otherwise hand back
    ///   another user's profile for the caller to merge or link on.
    ///
    /// # Errors
    ///
    /// * [`OAuthError::SubjectMismatch`](axess_factors::oauth::OAuthError::SubjectMismatch): the response is about another subject.
    /// * [`OAuthError::NoAccessToken`](axess_factors::oauth::OAuthError::NoAccessToken): empty access token.
    /// * [`OAuthError::UnknownProvider`](axess_factors::oauth::OAuthError::UnknownProvider): provider not registered.
    /// * [`OAuthError::AccessTokenExpired`](axess_factors::oauth::OAuthError::AccessTokenExpired): token expired or invalid (HTTP 401).
    /// * [`OAuthError::InsufficientScope`](axess_factors::oauth::OAuthError::InsufficientScope): missing required scope (HTTP 403).
    /// * [`OAuthError::UserInfo`](axess_factors::oauth::OAuthError::UserInfo): other HTTP or parse errors.
    #[tracing::instrument(skip(self, access_token, expected_subject))]
    pub async fn fetch_userinfo(
        &self,
        provider_name: &str,
        access_token: &str,
        expected_subject: &str,
    ) -> Result<axess_factors::oauth::UserInfoClaims, axess_factors::oauth::OAuthError> {
        self.fetch_userinfo_with_key(provider_name, access_token, expected_subject, None)
            .await
    }

    /// [`fetch_userinfo`](Self::fetch_userinfo) for an access token bound to
    /// a DPoP key: the request uses the `DPoP` authorization scheme and
    /// carries a proof signed by `dpop_key` that names the token's hash.
    /// Pass the key the login returned in
    /// [`OAuthClaims::dpop_key`](axess_factors::oauth::OAuthClaims::dpop_key).
    #[tracing::instrument(skip(self, access_token, expected_subject, dpop_key))]
    pub async fn fetch_userinfo_with_key(
        &self,
        provider_name: &str,
        access_token: &str,
        expected_subject: &str,
        dpop_key: Option<&axess_factors::oauth::DpopKey>,
    ) -> Result<axess_factors::oauth::UserInfoClaims, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        if access_token.is_empty() {
            return Err(OAuthError::NoAccessToken);
        }

        let provider = self
            .inner
            .oauth_providers
            .get(provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.to_string()))?
            .clone();

        let signer = dpop_key.map(|key| axess_factors::oauth::DpopSigner {
            key,
            rng: &*self.inner.rng,
        });
        provider
            .fetch_userinfo_for_subject_with(access_token, expected_subject, signer)
            .await
    }
}
