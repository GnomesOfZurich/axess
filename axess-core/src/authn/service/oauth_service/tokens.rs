//! Token-side OAuth operations: revocation (RFC 7009), RP-Initiated
//! Logout URL construction, and DPoP proof generation (FAPI 2.0).
//!
//! Each method is a thin pass-through to the configured provider; the
//! security-relevant logic (allowlist enforcement on logout redirects,
//! proof signing for DPoP) lives on the provider implementation itself.

use crate::authn::service::AuthnService;
use crate::authn::store::{FactorStore, IdentityStore};

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Build an RP-Initiated Logout URL for the given provider.
    ///
    /// Returns a URL that the application should redirect the user's browser to
    /// after invalidating the local session. The IdP will terminate its session
    /// and redirect the user back to `post_logout_redirect_uri`.
    ///
    /// Returns `None` if the provider doesn't advertise an `end_session_endpoint`
    /// in its OIDC discovery metadata. A `post_logout_redirect_uri` is
    /// forwarded only when it matches an entry of the provider's configured
    /// allowlist exactly; with no allowlist configured it is dropped.
    ///
    /// # Arguments
    ///
    /// * `provider_name`: Name of the registered OAuth provider.
    /// * `id_token_hint`: The raw ID token JWT from [`OAuthClaims::id_token_hint`](axess_factors::oauth::OAuthClaims::id_token_hint).
    ///   Allows the IdP to identify the session without re-authentication.
    /// * `post_logout_redirect_uri`: Where the IdP redirects after logout.
    /// * `state`: Optional CSRF protection for the post-logout redirect.
    pub fn build_end_session_url(
        &self,
        provider_name: &str,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
    ) -> Option<url::Url> {
        let provider = self.inner.oauth_providers.get(provider_name)?;
        provider.build_end_session_url(id_token_hint, post_logout_redirect_uri, state)
    }

    /// Revoke an access or refresh token at the IdP (RFC 7009).
    ///
    /// Should be called during logout to ensure tokens cannot be reused.
    /// Returns `Ok(())` on successful revocation.
    ///
    /// # Arguments
    ///
    /// * `provider_name`: Name of the registered OAuth provider.
    /// * `token`: The access or refresh token to revoke.
    /// * `token_type_hint`: `"access_token"` or `"refresh_token"` (optional
    ///   but helps the IdP locate the token faster).
    pub async fn revoke_oauth_token(
        &self,
        provider_name: &str,
        token: &str,
        token_type_hint: Option<&str>,
    ) -> Result<(), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        let provider = self
            .inner
            .oauth_providers
            .get(provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.to_string()))?;

        provider.revoke_token(token, token_type_hint).await
    }

    /// A fresh DPoP key for one session, drawn from the service's injected
    /// [`SecureRng`](axess_rng::SecureRng).
    ///
    /// RFC 9449 binds an access token to one key (`cnf.jkt`) and requires
    /// every proof presented with that token to be signed by it. Make one key
    /// when the session starts, keep it for the token's life (the key exports its
    /// scalar for that), and pass it to every
    /// [`generate_dpop_proof`](Self::generate_dpop_proof) call.
    ///
    /// Requires the `fapi` feature.
    #[cfg(feature = "fapi")]
    pub fn new_dpop_key(&self) -> axess_factors::oauth::DpopKey {
        axess_factors::oauth::DpopKey::generate(&*self.inner.rng)
    }

    /// Generate a DPoP proof JWT for an API call to a resource server.
    ///
    /// The proof is signed with `key`, the one key the token is bound to, so
    /// two proofs for different URLs report the same `thumbprint`, which is
    /// the `jkt` of the sender-constrained access token. Include the returned
    /// JWT in the `DPoP` header. Pass `access_token` to add the `ath` claim
    /// that ties the proof to that token.
    ///
    /// The 16 bytes behind the `jti` are drawn from the service's injected
    /// [`SecureRng`](axess_rng::SecureRng), and `iat` is read from its
    /// injected clock, so DST tests get reproducible proofs.
    ///
    /// Requires the `fapi` feature.
    #[cfg(feature = "fapi")]
    pub fn generate_dpop_proof(
        &self,
        provider_name: &str,
        key: &axess_factors::oauth::DpopKey,
        http_method: &str,
        http_url: &str,
        access_token: Option<&str>,
    ) -> Result<axess_factors::oauth::DpopProof, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        let provider = self
            .inner
            .oauth_providers
            .get(provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.to_string()))?;

        let mut jti_bytes = [0u8; 16];
        self.inner.rng.fill_bytes(&mut jti_bytes);
        let iat = self.inner.clock.now().timestamp();

        provider.generate_dpop_proof(key, http_method, http_url, access_token, iat, jti_bytes)
    }
}
