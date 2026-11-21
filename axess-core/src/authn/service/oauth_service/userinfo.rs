//! OIDC UserInfo endpoint passthrough.
//!
//! Thin wrapper: looks up the configured provider, validates the
//! access token isn't empty, delegates to the provider's
//! [`fetch_userinfo`](axess_factors::oauth::OAuthProvider::fetch_userinfo).
//! HTTP 401 / 403 / non-2xx errors are mapped to typed [`OAuthError`]
//! variants so callers can branch on token-expired vs
//! insufficient-scope vs other failures.

use super::scoped::Scope;
use crate::authn::service::AuthnService;
use crate::authn::store::{FactorStore, IdentityStore};

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The UserInfo call of [`ScopedOAuth`](super::ScopedOAuth); `scope` says
    /// whose provider `provider_name` names.
    #[tracing::instrument(
        name = "fetch_userinfo",
        skip(self, scope, provider_name, access_token, expected_subject, dpop_key),
        fields(provider_name = %super::logged_provider_name(provider_name))
    )]
    pub(super) async fn userinfo_scoped(
        &self,
        scope: &Scope,
        provider_name: &str,
        access_token: &str,
        expected_subject: &str,
        dpop_key: Option<&axess_factors::oauth::DpopKey>,
    ) -> Result<axess_factors::oauth::UserInfoClaims, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        if access_token.is_empty() {
            return Err(OAuthError::NoAccessToken);
        }

        let provider = self.scoped_provider(scope, provider_name).await?;

        let signer = dpop_key.map(|key| axess_factors::oauth::DpopSigner {
            key,
            rng: &*self.inner.rng,
        });
        provider
            .fetch_userinfo(access_token, expected_subject, signer)
            .await
    }
}
