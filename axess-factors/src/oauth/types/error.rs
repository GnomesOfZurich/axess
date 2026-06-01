//! OAuth/OIDC error enum + transient-vs-permanent classification.

/// Errors returned by OAuth 2.0 / OIDC operations across discovery, token
/// exchange, ID-token validation, and refresh.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// Provider configuration is missing required fields or fails validation.
    #[error("OAuth configuration error: {0}")]
    Config(String),

    /// Failure fetching or parsing the OIDC discovery document.
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),

    /// Token endpoint rejected the authorization code or returned an unparseable response.
    #[error("token exchange failed: {0}")]
    TokenExchange(String),

    /// ID token failed signature, issuer, audience, or claim-set validation.
    #[error("ID token validation failed: {0}")]
    IdTokenValidation(String),

    /// No provider is registered under the requested name.
    #[error("unknown provider: {0}")]
    UnknownProvider(String),

    /// `state` returned by the IdP did not match the value stored at flow start.
    #[error("CSRF state mismatch")]
    CsrfMismatch,

    /// Callback received but no in-progress flow was found in the session.
    #[error("no OAuth flow in progress")]
    NoFlow,

    /// In-progress flow exceeded its TTL before the user completed the IdP redirect.
    #[error("OAuth ceremony expired")]
    Expired,

    /// Required callback parameter is missing or malformed.
    #[error("invalid OAuth callback parameter")]
    InvalidParameter,

    /// IdP rejected the refresh token (RFC 6749 `invalid_grant`).
    #[error("refresh token expired or revoked")]
    RefreshTokenExpired,

    /// Operation requires a refresh token but none is stored for this session.
    #[error("no refresh token provided")]
    NoRefreshToken,

    /// Operation requires an access token but none is stored for this session.
    #[error("no access token provided")]
    NoAccessToken,

    /// UserInfo endpoint call failed.
    #[error("userinfo request failed: {0}")]
    UserInfo(String),

    /// Access token expired or was rejected by the resource server.
    #[error("access token expired or invalid")]
    AccessTokenExpired,

    /// Stored access token lacks the scopes required to call UserInfo.
    #[error("insufficient scope for userinfo endpoint")]
    InsufficientScope,

    /// RFC 8628 device authorization endpoint returned an error.
    #[error("device authorization failed: {0}")]
    DeviceAuthorization(String),

    /// JWT verification failed because the `kid` is not present in
    /// the cached JWKS. Callers (e.g. back-channel logout) match on this
    /// variant to trigger a `refresh_jwks()` + retry, instead of fragile
    /// substring-matching the error message.
    #[error("no key in JWKS matching kid `{0}`; call refresh_jwks() to re-fetch")]
    UnknownKid(String),

    /// RFC 7009 §2.2.1: the authorization server received the
    /// revocation request but does not support the supplied token type
    /// (e.g. it can revoke `refresh_token` but not `access_token`).
    /// Callers should usually log + ignore: a token the AS cannot revoke
    /// is, from its perspective, already "not a valid token".
    #[error("revocation endpoint reports unsupported_token_type")]
    UnsupportedTokenType,

    /// A server-side (5xx) failure from a token endpoint
    /// (revocation / refresh / exchange). Distinct from
    /// [`TokenExchange`](Self::TokenExchange) so callers can distinguish
    /// "AS rejected our request" from "AS is broken right now and a
    /// retry might succeed".
    #[error("token endpoint transient failure (HTTP {status}): {body}")]
    TokenEndpointTransient {
        /// HTTP status code returned by the AS (5xx range).
        status: u16,
        /// Body of the failed response (truncated upstream if large).
        body: String,
    },
}

impl OAuthError {
    /// Hint at whether this error is worth retrying.
    ///
    /// Returns `true` for failures the application can reasonably
    /// retry: 5xx token-endpoint responses, network-shaped discovery
    /// failures, network-shaped userinfo failures. Returns `false` for
    /// permanent semantic rejections (CSRF mismatch, expired ceremony,
    /// invalid parameters, unknown provider, unsupported token type).
    ///
    /// The classification is conservative: anything that *might* be a
    /// permanent state error returns `false`. Callers building retry
    /// loops should still apply per-call backoff and a hard attempt
    /// cap; this is a hint, not an exponential-backoff oracle.
    ///
    /// `Config(_)`, `IdTokenValidation(_)`, and `UnknownKid(_)` are
    /// *not* transient: they indicate misconfiguration or a key
    /// rotation that requires `refresh_jwks()` first, not a blind
    /// retry of the same call.
    ///
    /// # Consumer pattern: retry with capped exponential backoff
    ///
    /// `is_transient()` is the only contract; the caller owns the
    /// backoff schedule, attempt cap, and any jitter. The pattern
    /// below is what axess expects consumers to implement around
    /// any call that can return `OAuthError`:
    ///
    /// ```ignore
    /// use std::time::Duration;
    /// use axess_factors::oauth::OAuthError;
    ///
    /// async fn with_retry<T, F, Fut>(mut op: F) -> Result<T, OAuthError>
    /// where
    ///     F: FnMut() -> Fut,
    ///     Fut: std::future::Future<Output = Result<T, OAuthError>>,
    /// {
    ///     const MAX_ATTEMPTS: u32 = 4;
    ///     let mut delay = Duration::from_millis(250);
    ///     for attempt in 1..=MAX_ATTEMPTS {
    ///         match op().await {
    ///             Ok(v) => return Ok(v),
    ///             Err(e) if e.is_transient() && attempt < MAX_ATTEMPTS => {
    ///                 tokio::time::sleep(delay).await;
    ///                 delay = delay.saturating_mul(2); // 250ms, 500ms, 1s
    ///             }
    ///             Err(e) => return Err(e), // permanent OR cap exhausted
    ///         }
    ///     }
    ///     unreachable!() // loop body always returns
    /// }
    /// ```
    ///
    /// **Do not retry indefinitely.** A permanent error like
    /// `CsrfMismatch` or `Expired` returns `false` so the loop exits
    /// immediately, but a transient classification on a misbehaving
    /// upstream can otherwise spin forever. Always cap attempts and
    /// emit a `tracing::warn!` on each backoff so SOC dashboards see
    /// the upstream degradation.
    pub fn is_transient(&self) -> bool {
        match self {
            // 5xx from a token endpoint.
            Self::TokenEndpointTransient { .. } => true,

            // Network-class wrappers; the inner String carries the
            // reqwest / openidconnect error, which we cannot pattern-match
            // typedly. Treat as transient by convention; an attacker
            // cannot abuse a retry loop here because the AS is the
            // authoritative gate.
            Self::Discovery(_) | Self::UserInfo(_) => true,

            // Permanent / semantic rejections; retrying the same input
            // produces the same outcome.
            Self::Config(_)
            | Self::TokenExchange(_)
            | Self::IdTokenValidation(_)
            | Self::UnknownProvider(_)
            | Self::CsrfMismatch
            | Self::NoFlow
            | Self::Expired
            | Self::InvalidParameter
            | Self::RefreshTokenExpired
            | Self::NoRefreshToken
            | Self::NoAccessToken
            | Self::AccessTokenExpired
            | Self::InsufficientScope
            | Self::DeviceAuthorization(_)
            | Self::UnknownKid(_)
            | Self::UnsupportedTokenType => false,
        }
    }
}

#[cfg(test)]
mod oauth_error_is_transient_tests {
    use super::OAuthError;

    #[test]
    fn token_endpoint_5xx_is_transient() {
        let e = OAuthError::TokenEndpointTransient {
            status: 503,
            body: "...".into(),
        };
        assert!(e.is_transient());
    }

    #[test]
    fn discovery_and_userinfo_are_transient() {
        assert!(OAuthError::Discovery("network".into()).is_transient());
        assert!(OAuthError::UserInfo("timeout".into()).is_transient());
    }

    #[test]
    fn permanent_classes_are_not_transient() {
        for e in [
            OAuthError::CsrfMismatch,
            OAuthError::NoFlow,
            OAuthError::Expired,
            OAuthError::InvalidParameter,
            OAuthError::RefreshTokenExpired,
            OAuthError::NoRefreshToken,
            OAuthError::NoAccessToken,
            OAuthError::AccessTokenExpired,
            OAuthError::InsufficientScope,
            OAuthError::UnsupportedTokenType,
            OAuthError::UnknownProvider("p".into()),
            OAuthError::Config("c".into()),
            OAuthError::TokenExchange("t".into()),
            OAuthError::IdTokenValidation("v".into()),
            OAuthError::UnknownKid("k".into()),
            OAuthError::DeviceAuthorization("d".into()),
        ] {
            assert!(!e.is_transient(), "expected permanent: {e:?}");
        }
    }
}
