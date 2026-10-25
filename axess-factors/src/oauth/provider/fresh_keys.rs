//! ID-token verification against the provider's refreshable key set.
//!
//! The key set parsed into the discovery metadata is a snapshot from startup.
//! Verification instead builds its client from [`JwksCache`](crate::oidc::JwksCache),
//! so the cache's maximum age and the refresh loop govern ID tokens as well
//! as logout tokens.

use super::{OAuthProviderConfig, OidcClient};
use crate::oauth::types::OAuthError;
use openidconnect::{ClaimsVerificationError, SignatureVerificationError, core::CoreJsonWebKeySet};

/// The `kid` reported when an ID token's signing key is not in the key set.
/// The verifier does not hand the header back, so the message names the token.
const ID_TOKEN_KID: &str = "(ID token header)";

/// Map a claims verification failure: a signing key missing from the key set
/// is [`OAuthError::UnknownKid`], which callers answer by refreshing; anything
/// else is a validation failure.
pub(super) fn claims_error(e: ClaimsVerificationError) -> OAuthError {
    match e {
        ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::NoMatchingKey,
        ) => OAuthError::UnknownKid(ID_TOKEN_KID.to_string()),
        other => OAuthError::IdTokenValidation(format!("{other}")),
    }
}

impl OAuthProviderConfig {
    /// A client whose verifier holds the cache's current key set.
    ///
    /// Fails with [`OAuthError::JwksExpired`] when that key set is older than
    /// the cache's maximum age.
    fn client_with_cached_keys(&self) -> Result<OidcClient, OAuthError> {
        let handle = self.jwks_cache.fresh_handle().map_err(|e| match e {
            crate::oidc::OidcError::JwksExpired { .. } => OAuthError::JwksExpired,
            other => OAuthError::Discovery(other.to_string()),
        })?;
        let value = {
            let guard = handle.read().unwrap_or_else(|p| p.into_inner());
            serde_json::to_value(&*guard)
        }
        .map_err(|e| OAuthError::Discovery(format!("cached JWKS is not serialisable: {e}")))?;
        let keys: CoreJsonWebKeySet = serde_json::from_value(value)
            .map_err(|e| OAuthError::Discovery(format!("cached JWKS is not a key set: {e}")))?;
        Ok(openidconnect::core::CoreClient::from_provider_metadata(
            self.metadata.clone().set_jwks(keys),
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .set_redirect_uri(self.redirect_url.clone()))
    }

    /// Run an ID-token verification against the cached key set.
    ///
    /// When the key set is past its maximum age, or the token names a key the
    /// set lacks (IdP key rotation), the key set is refreshed once and the
    /// verification runs again; a second failure is the result. A failed
    /// refresh is logged and the retry then fails with the original reason.
    pub(super) async fn with_fresh_keys<T>(
        &self,
        run: impl Fn(&OidcClient) -> Result<T, OAuthError>,
    ) -> Result<T, OAuthError> {
        let first = self.client_with_cached_keys().and_then(|c| run(&c));
        match first {
            Err(OAuthError::UnknownKid(_) | OAuthError::JwksExpired) => {}
            other => return other,
        }
        if let Err(e) = self.refresh_jwks().await {
            tracing::warn!(error = %e, "JWKS refresh before ID-token retry failed");
        }
        self.client_with_cached_keys()
            .and_then(|c| run(&c))
            .map_err(|e| match e {
                OAuthError::UnknownKid(kid) => OAuthError::IdTokenValidation(format!(
                    "no key in the refreshed JWKS matches the ID token ({kid})"
                )),
                other => other,
            })
    }
}
