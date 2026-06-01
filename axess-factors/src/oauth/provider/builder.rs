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

    /// Override the ceremony timeout (default: 10 minutes).
    pub fn with_ceremony_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.ceremony_timeout = timeout;
        self
    }

    /// Enable FAPI 2.0 Baseline Profile for this provider.
    ///
    /// Enforces: mandatory PAR, sender-constrained tokens (DPoP or MTLS),
    /// and stricter ID token lifetime validation. Requires the IdP to
    /// advertise a `pushed_authorization_request_endpoint` in discovery.
    pub fn with_fapi(mut self, config: FapiConfig) -> Result<Self, OAuthError> {
        if self.par_endpoint.is_none() {
            return Err(OAuthError::Config(
                "FAPI 2.0 requires pushed_authorization_request_endpoint in provider metadata"
                    .to_string(),
            ));
        }
        self.fapi = Some(config);
        Ok(self)
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
    /// substring matching); values not in the list are silently dropped
    /// before being passed to the IdP, defeating phishing chains where an
    /// attacker tricks a user-controlled redirect parameter through the
    /// logout flow.
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

    /// Swap the clock used for FAPI `nbf` / clock-skew checks. Defaults
    /// to [`SystemClock`](axess_clock::SystemClock). Pass a
    /// [`MockClock`](axess_clock::testing::MockClock) under DST so the
    /// time-bound validation is deterministic.
    pub fn with_clock(mut self, clock: std::sync::Arc<dyn axess_clock::Clock>) -> Self {
        self.clock = clock;
        self
    }
}
