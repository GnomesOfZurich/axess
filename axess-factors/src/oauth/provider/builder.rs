//! Builder-style `with_*` methods on [`OAuthProviderConfig`].
//!
//! Each method returns `self` so they can be chained immediately after
//! [`OAuthProviderConfig::discover`]:
//!
//! ```text
//! let provider = OAuthProviderConfig::discover(...).await?
//!     .with_scopes(vec!["openid".into(), "email".into()])
//!     .with_ceremony_timeout(Duration::from_secs(900))
//!     .with_par_endpoint("https://idp.example/par")
//!     .with_allowed_post_logout_redirect_uris(["https://app.example/logout"]);
//! ```

use super::OAuthProviderConfig;
use crate::oauth::types::{FapiConfig, OAuthError};

impl OAuthProviderConfig {
    /// Override the default scopes.
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Require every back-channel logout token to carry the `typ` header
    /// `logout+jwt` (OpenID Connect Back-Channel Logout 1.0, section 2.4).
    ///
    /// By default a token is taken when its `typ` is `logout+jwt`, `JWT` or
    /// `Logout` (any case, with or without `application/`), or when it has
    /// none, because IdPs in the field send all of those. Only the types of
    /// other tokens signed by the same key (`dpop+jwt`, `at+jwt`) are
    /// refused. Turn this on for an IdP known to send the explicit type, and
    /// a token with another `typ` or none is refused too.
    pub fn with_required_logout_typ(mut self) -> Self {
        self.require_logout_typ = true;
        self
    }

    /// Override the ceremony timeout (default: 10 minutes).
    pub fn with_ceremony_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.ceremony_timeout = timeout;
        self
    }

    /// Enable the FAPI 2.0 profile for this provider.
    ///
    /// What the profile then means:
    ///
    /// * **Sender-constrained tokens.** With [`SenderConstraint::DPoP`](crate::oauth::SenderConstraint::DPoP) the
    ///   token request carries a DPoP proof signed by a key the service makes
    ///   for the login (and repeats on `use_dpop_nonce`), the response must
    ///   say `token_type` `DPoP`, and the key comes back in
    ///   `OAuthClaims::dpop_key` to be kept for the token's life. With
    ///   [`SenderConstraint::Mtls`](crate::oauth::SenderConstraint::Mtls) the certificate and key are loaded here
    ///   into the HTTP client, the server's `mtls_endpoint_aliases` replace the
    ///   token, userinfo, revocation and PAR endpoints it lists, and the
    ///   client secret is no longer sent (the certificate authenticates).
    /// * **PAR** is required: the provider must have a PAR endpoint.
    /// * **ID tokens** must carry `nbf`, live no longer than
    ///   `max_id_token_lifetime_secs`, and be signed with one of
    ///   `allowed_id_token_algs` (`PS256`, `ES256`, `EdDSA` by default),
    ///   whatever the IdP advertises.
    /// * **JARM** when `require_jarm` is set: authorization requests ask for
    ///   `response_mode=jwt` and the callback is finished with the response
    ///   JWT; a plain callback is refused.
    ///
    /// Reads the mTLS certificate and key files synchronously; call it at
    /// startup, not on a request path.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when the provider has no PAR endpoint, an
    /// algorithm name is not an asymmetric one this provider verifies (or the
    /// list is empty), the mTLS files cannot be read or parsed, or an
    /// advertised mTLS alias is not a secure URL.
    pub fn with_fapi(self, config: FapiConfig) -> Result<Self, OAuthError> {
        self.enable_fapi(config)
    }

    /// Manually set the PAR endpoint (RFC 9126).
    ///
    /// Only needed if the IdP doesn't advertise it in OIDC discovery metadata.
    pub fn with_par_endpoint(mut self, url: impl Into<String>) -> Self {
        self.par_endpoint = Some(url.into());
        self
    }

    /// Manually set the OAuth 2.0 token revocation endpoint (RFC 7009).
    ///
    /// Only needed when the IdP exposes a revocation endpoint but does
    /// not advertise it in the standard OIDC discovery metadata under
    /// the `revocation_endpoint` field; `discover()` then leaves
    /// `revoke_token` returning `Config("...does not include a
    /// revocation_endpoint")`. Use this setter to override.
    pub fn with_revocation_endpoint(mut self, url: impl Into<String>) -> Self {
        self.revocation_endpoint = Some(url.into());
        self
    }

    /// Manually set the OIDC RP-Initiated Logout endpoint
    /// (`end_session_endpoint`).
    ///
    /// Same rationale as [`with_revocation_endpoint`](Self::with_revocation_endpoint):
    /// many IdPs expose the endpoint without advertising it in
    /// discovery, so [`build_end_session_url`](crate::oauth::OAuthProvider::build_end_session_url)
    /// returns `None` until the URL is supplied.
    pub fn with_end_session_endpoint(mut self, url: impl Into<String>) -> Self {
        self.end_session_endpoint = Some(url.into());
        self
    }

    /// Configure the set of `post_logout_redirect_uri` values accepted by
    /// [`build_end_session_url`](crate::oauth::OAuthProvider::build_end_session_url). Each entry must match exactly (no glob /
    /// substring matching); values not in the list are dropped (with a
    /// warning) before being passed to the IdP, defeating phishing chains
    /// where an attacker tricks a user-controlled redirect parameter through
    /// the logout flow.
    ///
    /// The list is empty by default and an empty list forwards nothing: a
    /// provider that exposes a logout link with a redirect parameter must
    /// list the destinations it accepts here, and each must also be
    /// registered at the IdP.
    pub fn with_allowed_post_logout_redirect_uris(
        mut self,
        uris: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.allowed_post_logout_redirect_uris = uris.into_iter().map(Into::into).collect();
        self
    }

    /// Set the device authorization endpoint URL (RFC 8628).
    ///
    /// Required for the device code flow. Not part of standard OIDC discovery;
    /// check your IdP's documentation for the URL.
    pub fn with_device_authorization_endpoint(mut self, url: impl Into<String>) -> Self {
        self.device_authorization_endpoint = Some(url.into());
        self
    }

    /// Swap the clock behind every time-bound decision the provider makes:
    /// ID-token `exp` and `iat` (inside `openidconnect`), the FAPI `nbf`
    /// check, back-channel logout token lifetimes, and the JWKS refresh
    /// debounce. Defaults to [`SystemClock`](axess_clock::SystemClock).
    /// Pass a `MockClock` under DST so all of them are deterministic.
    pub fn with_clock(mut self, clock: std::sync::Arc<dyn axess_clock::Clock>) -> Self {
        self.jwks_cache = self.jwks_cache.with_clock(clock.clone());
        self.clock = clock;
        self
    }
}
