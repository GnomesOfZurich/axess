//! `OAuthProvider` trait + session-key constants + `AuthUrlResult` alias.
//!
//! The trait is the hub of the OAuth/OIDC type surface: every adopter
//! impl (production [`OAuthProviderConfig`](super::super::OAuthProviderConfig)
//! and the mock) implements this surface, and every service-layer
//! ceremony method (`begin_oauth_login`, `finish_oauth_login`,
//! `complete_oauth_login`, `refresh_session`, …) consumes it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::claims::{OAuthClaims, UserInfoClaims};
use super::client_credentials::ClientCredentialsToken;
use super::device_flow::{DeviceAuthResponse, DeviceTokenOutcome};
use super::error::OAuthError;
use super::fapi::{DpopProof, FapiConfig, ParResponse};
use super::login_options::OAuthLoginOptions;

/// Session-bag keys reserved by the OAuth ceremony. The `axess.`
/// prefix is reserved for library-internal use; adopter session-bag
/// writes must avoid this namespace.
pub mod keys {
    /// PKCE verifier stashed at `begin_oauth_login`, consumed at
    /// `finish_oauth_login` to prove the code exchange came from the
    /// same client.
    pub const PKCE_VERIFIER: &str = "axess.oauth.pkce_verifier";
    /// CSRF state token bound to the user agent; `finish_oauth_login`
    /// fails if the IdP returns a different `state` than this one.
    pub const CSRF_STATE: &str = "axess.oauth.csrf_state";
    /// OIDC `nonce` claim binding the ID token to this session.
    pub const NONCE: &str = "axess.oauth.nonce";
    /// Provider name (the key used in
    /// `axess_core::federation::oauth::OAuthProviderRegistry`).
    pub const PROVIDER: &str = "axess.oauth.provider";
    /// Provider's `issuer` URL: pinned at begin time and re-checked
    /// at finish so a switched-out provider can't complete the flow.
    pub const PROVIDER_ISSUER: &str = "axess.oauth.provider_issuer";
    /// Wall-clock time (RFC3339) the ceremony started; used to
    /// detect abandoned flows past the configured TTL.
    pub const STARTED: &str = "axess.oauth.started";
    /// Optional tenant binding stashed by `begin_oauth_login_in_tenant`.
    /// When present, `complete_oauth_login` refuses to set the session
    /// authenticated unless the resolved `User.tenant_id` matches.
    pub const EXPECTED_TENANT: &str = "axess.oauth.expected_tenant";

    /// Claim-binding token stashed by `finish_oauth_login` and
    /// consumed atomically by `complete_oauth_login`. Encodes the
    /// SHA-256 of `(provider || subject || session_id)` as URL-safe
    /// base64. The presence of this entry, and its match against the
    /// claims supplied to `complete_oauth_login`, proves that the
    /// caller actually completed `finish_oauth_login` rather than
    /// fabricating a `User`/`OAuthClaims` pair to skip the OIDC verify.
    /// Stored under the `axess.` namespace which the documentation
    /// reserves to library use.
    pub const CLAIM_LOCK: &str = "axess.oauth.claim_lock";

    /// In-flight PAR `request_uri` + its computed expiry,
    /// stored as a JSON object `{"expires_at": "RFC3339"}`. Set by
    /// `begin_oauth_login` when the FAPI / PAR path is taken, cleared
    /// alongside the rest of the OAuth ceremony state. Used to refuse a
    /// second `begin_oauth_login` against the same session while the
    /// previous PAR `request_uri` is still valid; the AS is supposed
    /// to enforce single-use, but defense-in-depth costs nothing here.
    pub const PAR_INFLIGHT: &str = "axess.oauth.par_inflight";
}

/// Result type for `build_auth_url` and `build_auth_url_par`.
///
/// Contains `(authorization_url, csrf_state, nonce, pkce_verifier)`.
pub type AuthUrlResult = (url::Url, String, String, String);

/// Abstraction over OAuth/OIDC token operations.
///
/// Production: implemented by [`OAuthProviderConfig`](super::super::OAuthProviderConfig) (uses real HTTP).
/// Tests: [`MockOAuthProvider`](super::super::MockOAuthProvider) (configurable responses, no HTTP).
///
/// This trait covers the HTTP-dependent parts of the OAuth flow so that
/// tests can replace them with deterministic behavior.
///
/// # Timeouts
///
/// The built-in [`OAuthProviderConfig`](super::super::OAuthProviderConfig) applies a 30-second HTTP timeout
/// to all network operations (discovery, token exchange, JWKS fetch) and
/// a configurable ceremony timeout (default 10 minutes) for the full
/// authorization code flow. Custom implementations should enforce similar
/// timeouts to prevent a misbehaving IdP from blocking indefinitely.
pub trait OAuthProvider: Send + Sync + 'static {
    /// Provider name (e.g. `"google"`, `"github"`).
    fn name(&self) -> &Arc<str>;

    /// OIDC issuer URL for this provider (e.g. `"https://accounts.google.com"`).
    fn issuer(&self) -> Option<&str> {
        None
    }

    /// OAuth client ID registered with this provider.
    fn client_id(&self) -> Option<&str> {
        None
    }

    /// Scopes to request in the authorization URL.
    fn scopes(&self) -> &[String];

    /// Ceremony timeout for the OAuth redirect flow.
    fn ceremony_timeout(&self) -> std::time::Duration;

    /// Exchange a refresh token for new claims.
    fn refresh_token<'a>(
        &'a self,
        refresh_token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClaims, OAuthError>> + Send + 'a>>;

    /// Exchange an authorization code for claims.
    fn exchange_code<'a>(
        &'a self,
        code: &'a str,
        pkce_verifier: String,
        nonce: String,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClaims, OAuthError>> + Send + 'a>>;

    /// Fetch additional user claims from the OIDC UserInfo endpoint.
    fn fetch_userinfo<'a>(
        &'a self,
        access_token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<UserInfoClaims, OAuthError>> + Send + 'a>>;

    /// Build an authorization URL for the OAuth flow.
    ///
    /// Returns `(authorization_url, csrf_state, nonce, pkce_verifier)`.
    fn build_auth_url(&self, options: &OAuthLoginOptions) -> Result<AuthUrlResult, OAuthError> {
        // Default rejects without inspecting the options; adopters override
        // to actually construct the URL. Include a hint about what was
        // rejected so the error log carries a forensics breadcrumb.
        Err(OAuthError::Config(format!(
            "build_auth_url not supported by this provider \
             (rejected request with {} extra scope hint(s))",
            options.extra_scopes.len()
        )))
    }

    /// Request a device code from the IdP's device authorization endpoint.
    fn request_device_code<'a>(
        &'a self,
        scopes: &'a [&'a str],
    ) -> Pin<Box<dyn Future<Output = Result<DeviceAuthResponse, OAuthError>> + Send + 'a>> {
        let scope_count = scopes.len();
        Box::pin(async move {
            Err(OAuthError::DeviceAuthorization(format!(
                "device code flow not supported by this provider \
                 (rejected {scope_count}-scope request)"
            )))
        })
    }

    /// Poll the token endpoint for a device code authorization result.
    ///
    /// `current_interval` is the polling interval the caller is currently
    /// using (in seconds, from the original [`DeviceAuthResponse::interval`]
    /// or the last [`DeviceTokenOutcome::SlowDown::new_interval`]). The
    /// implementation uses it to compute the new back-off interval to
    /// return on `slow_down` per RFC 8628 §3.5.
    ///
    /// `nonce` is the value the application supplied when
    /// initiating the device authorization (or `None` if no nonce was
    /// generated). When `Some`, the IdP-returned ID token MUST contain
    /// a matching `nonce` claim or verification fails. RFC 8628 / OIDC
    /// allow nonce in device flows; passing `None` preserves the prior
    /// (no-binding) behavior for backends that don't generate one.
    fn poll_device_token<'a>(
        &'a self,
        device_code: &'a str,
        current_interval: u64,
        nonce: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<DeviceTokenOutcome, OAuthError>> + Send + 'a>> {
        let device_code_len = device_code.len();
        let has_nonce = nonce.is_some();
        Box::pin(async move {
            Err(OAuthError::DeviceAuthorization(format!(
                "device code flow not supported by this provider \
                 (rejected {device_code_len}-byte device_code, \
                 interval={current_interval}s, has_nonce={has_nonce})"
            )))
        })
    }

    /// Verify the signature of a back-channel logout JWT using this provider's
    /// JWKS keys.
    ///
    /// Implementations MUST verify the signature against trusted keys before
    /// returning the decoded payload. The default returns an error so that any
    /// provider that forgets to override this fails closed rather than
    /// accepting unsigned logout tokens.
    fn verify_logout_jwt(&self, token: &str) -> Result<serde_json::Value, OAuthError> {
        // Default refuses to verify; adopters override. Surface the token
        // length so the param is observed and the error log carries a hint
        // about what was rejected.
        Err(OAuthError::Config(format!(
            "verify_logout_jwt not implemented for this provider \
             (rejected token of {} bytes); override to verify the logout \
             token signature before use",
            token.len()
        )))
    }

    /// Re-fetch the JWKS from the IdP's `jwks_uri`.
    fn refresh_jwks<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), OAuthError>> + Send + 'a>> {
        Box::pin(async move { Ok(()) })
    }

    /// Build the RP-Initiated Logout URL (OIDC RP-Initiated Logout 1.0).
    ///
    /// Redirects the user to the IdP's `end_session_endpoint` to terminate the
    /// IdP session. The `id_token_hint` allows the IdP to identify the session
    /// without re-authentication. The `post_logout_redirect_uri` is where the
    /// IdP redirects after logout completes.
    ///
    /// Returns `None` if the provider's metadata does not include an
    /// `end_session_endpoint`.
    fn build_end_session_url(
        &self,
        _id_token_hint: Option<&str>,
        _post_logout_redirect_uri: Option<&str>,
        _state: Option<&str>,
    ) -> Option<url::Url> {
        None
    }

    /// Revoke an access or refresh token at the IdP (RFC 7009).
    ///
    /// Sends a POST to the IdP's `revocation_endpoint` with the token and an
    /// optional `token_type_hint` (`"access_token"` or `"refresh_token"`).
    ///
    /// Per RFC 7009, the server MUST respond with 200 even if the token is
    /// already invalid. This method returns `Ok(())` on any 2xx response.
    fn revoke_token<'a>(
        &'a self,
        _token: &'a str,
        _token_type_hint: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            Err(OAuthError::Config(
                "token revocation not supported by this provider".to_string(),
            ))
        })
    }

    /// Build an authorization URL using Pushed Authorization Requests (RFC 9126).
    ///
    /// Like `build_auth_url`, but sends the authorization parameters to the
    /// PAR endpoint server-to-server first, then returns a minimal redirect URL
    /// containing only `client_id` and the opaque `request_uri`.
    ///
    /// Returns `(authorization_url, csrf_state, nonce, pkce_verifier)`.
    fn build_auth_url_par<'a>(
        &'a self,
        _options: &'a OAuthLoginOptions,
    ) -> Pin<Box<dyn Future<Output = Result<AuthUrlResult, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            Err(OAuthError::Config(
                "PAR not supported by this provider".to_string(),
            ))
        })
    }

    /// Push authorization parameters to the IdP's PAR endpoint (RFC 9126).
    ///
    /// Returns a `request_uri` that replaces query params in the authorization
    /// URL. The IdP stores the parameters server-side, preventing tampering
    /// and URL length issues.
    fn push_authorization_request<'a>(
        &'a self,
        _params: &'a [(&'a str, &'a str)],
    ) -> Pin<Box<dyn Future<Output = Result<ParResponse, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            Err(OAuthError::Config(
                "PAR not supported by this provider".to_string(),
            ))
        })
    }

    /// Generate a DPoP proof JWT (RFC 9449) for the given HTTP method and URL.
    ///
    /// The proof binds the request to an ephemeral key pair. Include the
    /// returned JWT in the `DPoP` header of the HTTP request.
    ///
    /// `key_seed` supplies 32 bytes of entropy used to derive the ephemeral
    /// ES256 key. Production callers should fill it from the application's
    /// [`SecureRng`](axess_rng::SecureRng); this preserves the
    /// DST contract (deterministic FAPI tests) and keeps `OsRng` use out
    /// of trait implementations.
    fn generate_dpop_proof(
        &self,
        _http_method: &str,
        _http_url: &str,
        _access_token: Option<&str>,
        _key_seed: [u8; 32],
    ) -> Result<DpopProof, OAuthError> {
        Err(OAuthError::Config(
            "DPoP not supported by this provider".to_string(),
        ))
    }

    /// Return the FAPI configuration, if this provider has FAPI enabled.
    fn fapi_config(&self) -> Option<&FapiConfig> {
        None
    }

    /// Exchange client credentials for an access token (OAuth 2.0 Client
    /// Credentials grant, RFC 6749 section 4.4).
    fn client_credentials<'a>(
        &'a self,
        _scopes: &'a [&'a str],
    ) -> Pin<Box<dyn Future<Output = Result<ClientCredentialsToken, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            Err(OAuthError::Config(
                "client_credentials not supported by this provider".to_string(),
            ))
        })
    }
}

#[cfg(test)]
mod provider_default_methods_tests {
    use super::*;

    /// Minimal stub to exercise the trait's default method bodies.
    /// Only the required methods are real; everything else falls
    /// through to the trait default, which is exactly what
    /// is pinning.
    struct StubProvider {
        name: Arc<str>,
        scopes: Vec<String>,
    }

    impl OAuthProvider for StubProvider {
        fn name(&self) -> &Arc<str> {
            &self.name
        }
        fn scopes(&self) -> &[String] {
            &self.scopes
        }
        fn ceremony_timeout(&self) -> std::time::Duration {
            std::time::Duration::from_secs(600)
        }
        fn refresh_token<'a>(
            &'a self,
            _refresh_token: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<OAuthClaims, OAuthError>> + Send + 'a>> {
            Box::pin(async move { Err(OAuthError::Config("stub".into())) })
        }
        fn exchange_code<'a>(
            &'a self,
            _code: &'a str,
            _pkce_verifier: String,
            _nonce: String,
        ) -> Pin<Box<dyn Future<Output = Result<OAuthClaims, OAuthError>> + Send + 'a>> {
            Box::pin(async move { Err(OAuthError::Config("stub".into())) })
        }
        fn fetch_userinfo<'a>(
            &'a self,
            _access_token: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<UserInfoClaims, OAuthError>> + Send + 'a>> {
            Box::pin(async move { Err(OAuthError::Config("stub".into())) })
        }
    }

    fn stub() -> StubProvider {
        StubProvider {
            name: Arc::from("stub"),
            scopes: vec![],
        }
    }

    /// A provider that does not override `issuer()` must
    /// return `None`. The default exists to guard against silently
    /// returning a fabricated string ("xyzzy" from a mutation) which
    /// would let downstream code accept a token without checking the
    /// real `iss` claim.
    #[test]
    fn default_issuer_returns_none() {
        assert!(stub().issuer().is_none());
    }

    /// A provider that does not override `client_id()` must
    /// return `None`. A bogus default would leak into PAR / token
    /// exchange paths.
    #[test]
    fn default_client_id_returns_none() {
        assert!(stub().client_id().is_none());
    }

    /// The default `verify_logout_jwt` MUST fail closed.
    /// The trait doc explicitly contracts this so a forgotten override
    /// rejects unsigned logout tokens. A mutation to `Ok(Default::default())`
    /// would silently accept any payload.
    #[test]
    fn default_verify_logout_jwt_fails_closed() {
        let result = stub().verify_logout_jwt("any.jwt.payload");
        assert!(result.is_err(), "default must reject unsigned tokens");
        match result.unwrap_err() {
            OAuthError::Config(msg) => assert!(msg.contains("verify_logout_jwt")),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    /// A provider without FAPI configured must return `None`.
    /// A leaked default `FapiConfig` would silently turn on
    /// sender-constraint enforcement for non-FAPI providers.
    #[test]
    fn default_fapi_config_returns_none() {
        assert!(stub().fapi_config().is_none());
    }
}
