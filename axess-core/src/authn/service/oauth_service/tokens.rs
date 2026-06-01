//! Token-side OAuth operations: revocation (RFC 7009), RP-Initiated
//! Logout URL construction, and DPoP proof generation (FAPI 2.0).
//!
//! Each method is a thin pass-through to the configured provider; the
//! security-relevant logic (allowlist enforcement on logout redirects,
//! ephemeral-key sourcing for DPoP) lives on the provider implementation
//! itself.

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
    /// in its OIDC discovery metadata.
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
        let provider = self.oauth_providers.get(provider_name)?;
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
            .oauth_providers
            .get(provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.to_string()))?;

        provider.revoke_token(token, token_type_hint).await
    }

    /// Generate a DPoP proof JWT for an API call to a resource server.
    ///
    /// The proof binds the request to an ephemeral key pair. Include the
    /// returned JWT in the `DPoP` header. The `thumbprint` should match the
    /// `jkt` claim in the sender-constrained access token.
    ///
    /// The 32 bytes used to derive the ephemeral ES256 key are
    /// drawn from the service's injected [`SecureRng`](axess_rng::SecureRng), so DST tests get
    /// reproducible DPoP keys instead of `OsRng`.
    ///
    /// Requires the `fapi` feature.
    #[cfg(feature = "fapi")]
    pub fn generate_dpop_proof(
        &self,
        provider_name: &str,
        http_method: &str,
        http_url: &str,
        access_token: Option<&str>,
    ) -> Result<axess_factors::oauth::DpopProof, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        let provider = self
            .oauth_providers
            .get(provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.to_string()))?;

        let mut key_seed = [0u8; 32];
        self.rng.fill_bytes(&mut key_seed);

        provider.generate_dpop_proof(http_method, http_url, access_token, key_seed)
    }
}
