//! JWTs the issuer signs with the keys it publishes, other than the ID
//! token: the back-channel logout token and the JARM authorization
//! response. Both are checked the same way here: against the cached key set
//! while it is within its maximum age, with `aud` the client id and `iss` the
//! issuer, under the algorithm list the provider accepts.

use super::OAuthProviderConfig;
use crate::jwt::validation::{ALLOWED_ALGORITHMS, JwtError, ValidationConfig, verify_jwt};
use crate::oauth::types::OAuthError;
use std::sync::{Arc, RwLock};

/// The OAuth error for a rejected JWT. The wording names the token by its
/// role in the caller's message, not here.
pub(super) fn jwt_error(e: JwtError) -> OAuthError {
    match e {
        JwtError::UnknownKid(kid) => OAuthError::UnknownKid(kid),
        JwtError::TooLarge { len, max } => {
            OAuthError::IdTokenValidation(format!("JWT too large ({len} bytes, max {max})"))
        }
        JwtError::InvalidHeader(msg) => {
            OAuthError::IdTokenValidation(format!("invalid JWT header: {msg}"))
        }
        JwtError::DisallowedAlgorithm(alg) => {
            OAuthError::IdTokenValidation(format!("disallowed JWT algorithm: {alg:?}"))
        }
        JwtError::MissingKid => {
            OAuthError::IdTokenValidation("JWT has no `kid` header".to_string())
        }
        JwtError::AlgorithmMismatch {
            header_alg,
            jwk_alg,
        } => OAuthError::IdTokenValidation(format!(
            "JWT header alg {header_alg:?} does not match JWK alg {jwk_alg}"
        )),
        JwtError::KeyConstruction(msg) => {
            OAuthError::IdTokenValidation(format!("failed to build key from JWK: {msg}"))
        }
        JwtError::VerificationFailed(msg) => {
            OAuthError::IdTokenValidation(format!("JWT signature verification failed: {msg}"))
        }
    }
}

impl OAuthProviderConfig {
    /// The cached key set, while it is within its maximum age:
    /// [`OAuthError::JwksExpired`] past it, which callers answer by
    /// refreshing the key set.
    pub(super) fn cached_jwks(&self) -> Result<Arc<RwLock<jsonwebtoken::jwk::JwkSet>>, OAuthError> {
        self.jwks_cache.fresh_handle().map_err(|e| match e {
            crate::oidc::OidcError::JwksExpired { .. } => OAuthError::JwksExpired,
            other => OAuthError::Discovery(other.to_string()),
        })
    }

    /// The JWS algorithms a token from the issuer may be signed with: the
    /// provider's pinned list (FAPI, or `with_id_token_signing_algs`), or
    /// the asymmetric defaults.
    pub(super) fn allowed_algs(&self) -> &[jsonwebtoken::Algorithm] {
        match &self.id_token_algs {
            Some(algs) => algs.jwt.as_slice(),
            None => ALLOWED_ALGORITHMS,
        }
    }

    /// Verify a JWT the issuer signed and return its payload: the signature
    /// under a key of the cached set, an `aud` naming the client, an `iss`
    /// equal to the issuer (so a token another issuer signed with a key this
    /// set holds is refused), the time claims under the provider's clock, and
    /// an algorithm from [`allowed_algs`](Self::allowed_algs).
    pub(super) fn verify_issuer_jwt(&self, token: &str) -> Result<serde_json::Value, OAuthError> {
        let handle = self.cached_jwks()?;
        // Recover from a poisoned lock. The data may be stale, but
        // verification then fails with a "no matching kid" error and
        // triggers a refresh.
        let jwks = handle.read().unwrap_or_else(|poisoned| {
            tracing::warn!("JWKS RwLock was poisoned; recovering for read");
            poisoned.into_inner()
        });
        let mut config = ValidationConfig::new();
        config.audience = Some(self.client_id.as_str().to_string());
        config.issuer = Some(self.metadata.issuer().as_str().to_string());
        verify_jwt(token, &jwks, &config, self.allowed_algs(), &*self.clock).map_err(jwt_error)
    }
}
