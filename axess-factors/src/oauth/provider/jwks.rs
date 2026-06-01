//! JWKS refresh adapter: thin facade over [`crate::oidc::JwksCache`].
//!
//! The single-flight + min-interval coalescing primitive lives in
//! [`crate::oidc`] so the same hardened plumbing is shared with
//! non-OAuth adopters (workload identity, federated IdP verifiers).
//! This facade keeps the call surface on [`OAuthProviderConfig`] and
//! the error type as `OAuthError` at the OAuth boundary.

use super::OAuthProviderConfig;
use crate::oauth::types::OAuthError;

impl OAuthProviderConfig {
    /// Re-fetch the IdP's JWKS via [`JwksCache::refresh`](crate::oidc::JwksCache::refresh).
    ///
    /// Called automatically by the back-channel logout handler when a `kid` is
    /// not found in the cached JWKS (IdP key rotation). Can also be called
    /// proactively on a schedule.
    pub async fn refresh_jwks(&self) -> Result<(), OAuthError> {
        self.jwks_cache
            .refresh()
            .await
            .map_err(|e| OAuthError::Discovery(format!("{e}")))
    }
}
