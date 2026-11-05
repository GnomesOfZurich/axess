//! [`OAuthProviderConfig::discover`]: async constructor that performs
//! OIDC discovery against `{issuer_url}/.well-known/openid-configuration`,
//! fetches the IdP's JWKS for back-channel-logout signature verification,
//! and extracts the optional non-OIDC-core endpoints (PAR,
//! `end_session_endpoint`, `revocation_endpoint`) from the metadata's raw
//! JSON.

use super::{OAuthProviderBuilder, OAuthProviderConfig};
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
    // One rule for both discovery paths: the parsed host decides, see
    // `oidc::discovery::require_https_or_loopback`.
    crate::oidc::discovery::require_https_or_loopback(issuer_url).is_ok()
}

impl OAuthProviderConfig {
    /// Discover a provider by OIDC discovery and return its builder.
    ///
    /// Fetches `{issuer_url}/.well-known/openid-configuration` to configure
    /// authorization, token, and userinfo endpoints automatically. Finish
    /// with [`OAuthProviderBuilder::build`], after any `with_*` settings.
    ///
    /// When the document advertises DPoP (`ES256` among its
    /// `dpop_signing_alg_values_supported`), the provider binds its tokens
    /// to a DPoP key from the start: see
    /// [`with_dpop`](OAuthProviderBuilder::with_dpop) for what that asks of
    /// the caller, and [`without_dpop`](OAuthProviderBuilder::without_dpop)
    /// for deployments whose resource servers take only Bearer tokens.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] for an issuer or redirect URL that is not
    /// acceptable, or an advertised endpoint that is not HTTPS;
    /// [`OAuthError::Discovery`] when the document or the key set cannot be
    /// fetched or read.
    pub async fn discover(
        name: &str,
        issuer_url: &str,
        client_id: &str,
        client_secret: &str,
        redirect_url: &str,
    ) -> Result<OAuthProviderBuilder, OAuthError> {
        Self::discover_with(
            name,
            issuer_url,
            client_id,
            Some(ClientSecret::new(client_secret.to_string())),
            redirect_url,
        )
        .await
    }

    /// Create a provider using OIDC discovery that authenticates to the
    /// token endpoint by `private_key_jwt` (RFC 7523) instead of a client
    /// secret. The client id is the signer's; no request this provider makes
    /// carries a secret.
    ///
    /// The same as [`discover`](Self::discover) in every other respect.
    ///
    /// # Errors
    ///
    /// As [`discover`](Self::discover).
    pub async fn discover_with_private_key_jwt(
        name: &str,
        issuer_url: &str,
        signer: crate::client_assertion::ClientAssertionSigner,
        redirect_url: &str,
    ) -> Result<OAuthProviderBuilder, OAuthError> {
        let client_id = signer.client_id().to_string();
        Ok(
            Self::discover_with(name, issuer_url, &client_id, None, redirect_url)
                .await?
                .with_private_key_jwt(signer),
        )
    }

    async fn discover_with(
        name: &str,
        issuer_url: &str,
        client_id: &str,
        client_secret: Option<ClientSecret>,
        redirect_url: &str,
    ) -> Result<OAuthProviderBuilder, OAuthError> {
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

        // One fetch of the discovery document. The shared OIDC primitive
        // reads it, binds it to the issuer it was fetched from and checks
        // the key set's transport; the typed metadata is parsed from the
        // same bytes, so the endpoints the provider calls and the optional
        // endpoints read below cannot come from two answers that differ.
        let extras = crate::oidc::discovery::DiscoveryDocument::fetch(issuer_url, &http_client)
            .await
            .map_err(|e| OAuthError::Discovery(format!("{e}")))?;
        let metadata: CoreProviderMetadata = serde_json::from_value(extras.raw.clone())
            .map_err(|e| OAuthError::Discovery(format!("discovery document: {e}")))?;
        if metadata.issuer().as_str() != issuer.as_str() {
            return Err(OAuthError::Discovery(format!(
                "discovery document names issuer {} but was fetched from {issuer_url}",
                metadata.issuer().as_str()
            )));
        }

        let redirect = RedirectUrl::new(redirect_url.to_string())
            .map_err(|e| OAuthError::Config(format!("invalid redirect URL: {e}")))?;

        // Fetch JWKS for logout token signature verification via the
        // shared OIDC primitive; single-flight refresh + debounce are
        // built in to JwksCache.
        let jwks_uri = metadata.jwks_uri().url().to_string();
        let jwks_cache = JwksCache::fetch(jwks_uri, &http_client)
            .await
            .map_err(|e| OAuthError::Discovery(format!("{e}")))?;

        // The optional endpoints are not part of the typed metadata:
        // `CoreProviderMetadata` carries an empty "additional metadata" type,
        // so every field outside the standard set is dropped when the
        // document is parsed (and so when it is serialised again). Read them
        // from the raw document the primitive keeps.
        let end_session_endpoint = extras.end_session_endpoint.clone();
        let revocation_endpoint = extras.revocation_endpoint.clone();
        let par_endpoint = extras.pushed_authorization_request_endpoint.clone();
        let iss_parameter_supported = extras
            .raw
            .get("authorization_response_iss_parameter_supported")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mtls_aliases = super::fapi_profile::MtlsAliases::from_document(&extras.raw);
        // DPoP is on by default wherever the IdP advertises it in a form the
        // proofs meet; `without_dpop` is the explicit way out, and `build`
        // decides.
        let dpop_advertised = super::dpop::advertised_in(&extras.raw);

        // Every endpoint that receives a secret, a token or a code travels
        // over HTTPS (loopback http allowed for development).
        super::endpoint::require_secure(
            metadata.token_endpoint().map(|e| e.url().as_str()),
            "token_endpoint",
        )?;
        super::endpoint::require_secure(
            metadata.userinfo_endpoint().map(|e| e.url().as_str()),
            "userinfo_endpoint",
        )?;
        super::endpoint::require_secure(
            Some(metadata.authorization_endpoint().url().as_str()),
            "authorization_endpoint",
        )?;
        super::endpoint::require_secure(end_session_endpoint.as_deref(), "end_session_endpoint")?;
        super::endpoint::require_secure(revocation_endpoint.as_deref(), "revocation_endpoint")?;
        super::endpoint::require_secure(
            par_endpoint.as_deref(),
            "pushed_authorization_request_endpoint",
        )?;

        Ok(OAuthProviderBuilder::discovered(Self {
            name: name.into(),
            metadata,
            client_id: ClientId::new(client_id.to_string()),
            client_secret,
            client_assertion: None,
            rng: std::sync::Arc::new(axess_rng::SystemRng),
            redirect_url: redirect,
            http_client,
            jwks_cache,
            device_authorization_endpoint: None,
            end_session_endpoint,
            revocation_endpoint,
            par_endpoint,
            iss_parameter_supported,
            mtls_aliases,
            fapi: None,
            dpop: false,
            dpop_advertised,
            id_token_algs: None,
            clock: std::sync::Arc::new(axess_clock::SystemClock),
            allowed_post_logout_redirect_uris: Vec::new(),
            require_logout_typ: false,
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            ceremony_timeout: std::time::Duration::from_secs(600),
        }))
    }
}

#[cfg(test)]
mod discovery_fetch_tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The discovery document is fetched once: the typed metadata and the
    /// optional endpoints are read from the same answer, so a second
    /// answer that differs cannot feed the optional endpoints.
    #[tokio::test]
    async fn the_discovery_document_is_fetched_once() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "revocation_endpoint": format!("{issuer}/revoke"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [],
            })))
            .mount(&server)
            .await;

        let provider = OAuthProviderConfig::discover(
            "test",
            &issuer,
            "client-id",
            "client-secret",
            "https://rp.example/callback",
        )
        .await
        .expect("discovery")
        .build()
        .expect("build");
        assert_eq!(
            provider.revocation_endpoint.as_deref(),
            Some(format!("{issuer}/revoke").as_str()),
            "the optional endpoint is read from the one document"
        );
        let discovery_fetches = server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .filter(|r| r.url.path() == "/.well-known/openid-configuration")
            .count();
        assert_eq!(
            discovery_fetches, 1,
            "the discovery document is fetched once"
        );
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
        // Non-loopback plain http rejected, including hosts that merely START
        // like loopback and URLs that hide the host behind userinfo.
        assert!(!is_issuer_url_acceptable("http://idp.example.com"));
        assert!(!is_issuer_url_acceptable("http://localhost.attacker.com"));
        assert!(!is_issuer_url_acceptable("http://127.0.0.1.nip.io"));
        assert!(!is_issuer_url_acceptable("http://localhost@evil.com"));
        assert!(!is_issuer_url_acceptable("http://attacker.test/"));
        // Other schemes rejected.
        assert!(!is_issuer_url_acceptable("ftp://example.com"));
        assert!(!is_issuer_url_acceptable("file:///etc/passwd"));
        assert!(!is_issuer_url_acceptable(""));
    }
}
