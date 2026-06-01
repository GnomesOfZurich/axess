//! [`OAuthProviderConfig::discover`]: async constructor that performs
//! OIDC discovery against `{issuer_url}/.well-known/openid-configuration`,
//! fetches the IdP's JWKS for back-channel-logout signature verification,
//! and extracts the optional non-OIDC-core endpoints (PAR,
//! `end_session_endpoint`, `revocation_endpoint`) from the metadata's raw
//! JSON.

use super::OAuthProviderConfig;
use crate::oauth::types::OAuthError;
use crate::oidc::JwksCache;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl, core::CoreProviderMetadata};

/// True when `issuer_url` satisfies the OIDC-discovery transport-security
/// rail: HTTPS, or one of the three IETF-allocated loopback hosts under
/// plain HTTP (RFC 8252 §7.3) for local development.
///
/// Extracted as a pure helper so the discriminator suite can pin every
/// branch of the predicate without spinning up a discovery HTTP roundtrip.
/// Inlined into [`OAuthProviderConfig::discover`] would require live IdP
/// or mock HTTP infra to exercise the rejection paths.
pub(crate) fn is_issuer_url_acceptable(issuer_url: &str) -> bool {
    if issuer_url.starts_with("https://") {
        return true;
    }
    issuer_url.starts_with("http://localhost")
        || issuer_url.starts_with("http://127.0.0.1")
        || issuer_url.starts_with("http://[::1]")
}

impl OAuthProviderConfig {
    /// Create a provider using OIDC discovery.
    ///
    /// Fetches `{issuer_url}/.well-known/openid-configuration` to configure
    /// authorization, token, and userinfo endpoints automatically.
    pub async fn discover(
        name: &str,
        issuer_url: &str,
        client_id: &str,
        client_secret: &str,
        redirect_url: &str,
    ) -> Result<Self, OAuthError> {
        // Reject non-HTTPS issuer URLs to prevent MITM during OIDC discovery.
        // Allow http://localhost / 127.0.0.1 / [::1] for local development.
        if !is_issuer_url_acceptable(issuer_url) {
            return Err(OAuthError::Config(
                "issuer URL must use HTTPS (http is only allowed for localhost/127.0.0.1)"
                    .to_string(),
            ));
        }

        let issuer = IssuerUrl::new(issuer_url.to_string())
            .map_err(|e| OAuthError::Config(format!("invalid issuer URL: {e}")))?;

        // HTTP client MUST NOT follow redirects (SSRF prevention).
        // 30-second timeout for individual HTTP operations (discovery, token
        // exchange, JWKS fetch). This is distinct from `ceremony_timeout` which
        // bounds the entire OAuth redirect flow (default 10 min).
        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| OAuthError::Config(format!("HTTP client build failed: {e}")))?;

        let metadata = CoreProviderMetadata::discover_async(issuer, &http_client)
            .await
            .map_err(|e| OAuthError::Discovery(format!("{e}")))?;

        let redirect = RedirectUrl::new(redirect_url.to_string())
            .map_err(|e| OAuthError::Config(format!("invalid redirect URL: {e}")))?;

        // Fetch JWKS for logout token signature verification via the
        // shared OIDC primitive; single-flight refresh + debounce are
        // built in to JwksCache.
        let jwks_uri = metadata.jwks_uri().url().to_string();
        let jwks_cache = JwksCache::fetch(jwks_uri, &http_client)
            .await
            .map_err(|e| OAuthError::Discovery(format!("{e}")))?;

        // Extract optional endpoints from discovery metadata.
        // These are standard OIDC fields but not exposed by CoreProviderMetadata
        // (which uses EmptyAdditionalProviderMetadata). Parse from the raw JSON
        // serialization of the metadata instead.
        let metadata_json = serde_json::to_value(&metadata).unwrap_or_default();
        let end_session_endpoint = metadata_json
            .get("end_session_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from);
        let revocation_endpoint = metadata_json
            .get("revocation_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from);
        let par_endpoint = metadata_json
            .get("pushed_authorization_request_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(Self {
            name: name.into(),
            metadata,
            client_id: ClientId::new(client_id.to_string()),
            client_secret: Some(ClientSecret::new(client_secret.to_string())),
            redirect_url: redirect,
            http_client,
            jwks_cache,
            device_authorization_endpoint: None,
            end_session_endpoint,
            revocation_endpoint,
            par_endpoint,
            fapi: None,
            clock: std::sync::Arc::new(axess_clock::SystemClock),
            allowed_post_logout_redirect_uris: Vec::new(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            ceremony_timeout: std::time::Duration::from_secs(600),
        })
    }
}

#[cfg(test)]
mod issuer_url_acceptability_tests {
    use super::*;

    /// Pin the URL-scheme rail for OIDC discovery against every
    /// mutation flagged on [`OAuthProviderConfig::discover`]:
    ///
    /// - HTTPS URLs always pass: kills `delete !` on the
    ///   `starts_with("https://")` guard (`if !https → if https` would
    ///   take the loopback branch for HTTPS URLs and then either accept
    ///   or reject them based on subsequent operators).
    /// - Each of the three loopback host strings independently makes
    ///   a plain-http URL acceptable: kills `||→&&` on the loopback
    ///   disjunction (the AND form would require every loopback string
    ///   to match simultaneously, which is impossible, so every plain
    ///   http URL would fail).
    /// - Non-loopback plain-http URLs are rejected: kills `delete !`
    ///   on the inner guard (without the `!` the function would accept
    ///   non-loopback http and reject loopback http).
    #[test]
    fn is_issuer_url_acceptable_pins_https_rail_and_loopback_exceptions() {
        // HTTPS always acceptable.
        assert!(is_issuer_url_acceptable("https://idp.example.com"));
        assert!(is_issuer_url_acceptable("https://example.com/path"));
        // Each loopback scheme independently acceptable.
        assert!(is_issuer_url_acceptable("http://localhost"));
        assert!(is_issuer_url_acceptable("http://localhost:8080/realms/dev"));
        assert!(is_issuer_url_acceptable("http://127.0.0.1:8080"));
        assert!(is_issuer_url_acceptable("http://[::1]:8443"));
        // Non-loopback plain http rejected.
        assert!(!is_issuer_url_acceptable("http://idp.example.com"));
        assert!(!is_issuer_url_acceptable("http://attacker.test/"));
        // Other schemes rejected.
        assert!(!is_issuer_url_acceptable("ftp://example.com"));
        assert!(!is_issuer_url_acceptable("file:///etc/passwd"));
        assert!(!is_issuer_url_acceptable(""));
    }
}
