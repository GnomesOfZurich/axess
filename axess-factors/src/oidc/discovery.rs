//! OIDC discovery: fetch and parse a provider's
//! `.well-known/openid-configuration` document, then prime a refreshable
//! JWKS cache from `jwks_uri`.
//!
//! The OAuth provider parses metadata via the `openidconnect` crate for
//! the full typed authorisation/token endpoint surface; this primitive
//! parses the raw JSON for adopters that only need issuer identity +
//! JWKS access (workload identity verification, federated IdPs, custom
//! token validators).

use crate::oidc::error::OidcError;
use crate::oidc::jwks_cache::JwksCache;
use jsonwebtoken::jwk::JwkSet;
use std::sync::{Arc, RwLock};

/// Path appended to the issuer URL when fetching the discovery document
/// (OIDC Core 1.0 §4.1).
const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

/// Parsed OIDC discovery document.
///
/// Only OIDC-standard fields are typed; everything else (provider
/// extensions, FAPI metadata, etc.) is preserved in [`raw`](Self::raw).
#[derive(Debug, Clone)]
pub struct DiscoveryDocument {
    /// The `issuer` claim: must match the issuer URL the document was
    /// fetched from (RFC 8414 §3.3).
    pub issuer: String,
    /// JWKS endpoint URL: mandatory in OIDC Core.
    pub jwks_uri: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: Option<String>,
    /// Token endpoint URL.
    pub token_endpoint: Option<String>,
    /// UserInfo endpoint URL.
    pub userinfo_endpoint: Option<String>,
    /// OIDC RP-Initiated Logout endpoint.
    pub end_session_endpoint: Option<String>,
    /// OAuth 2.0 Token Revocation endpoint (RFC 7009).
    pub revocation_endpoint: Option<String>,
    /// Pushed Authorization Request endpoint (RFC 9126).
    pub pushed_authorization_request_endpoint: Option<String>,
    /// Device Authorization endpoint (RFC 8628).
    pub device_authorization_endpoint: Option<String>,
    /// Raw JSON, preserved so callers can read provider-specific
    /// extension fields without re-fetching.
    pub raw: serde_json::Value,
}

impl DiscoveryDocument {
    /// Fetch and parse the discovery document at
    /// `{issuer_url}/.well-known/openid-configuration`.
    ///
    /// Enforces HTTPS (loopback exemption for `localhost`, `127.0.0.1`,
    /// `[::1]`); plain HTTP elsewhere would let an on-path attacker
    /// rewrite the `jwks_uri` and break signature verification.
    pub async fn fetch(
        issuer_url: &str,
        http_client: &openidconnect::reqwest::Client,
    ) -> Result<Self, OidcError> {
        require_https_or_loopback(issuer_url)?;

        let url = format!("{}{WELL_KNOWN_SUFFIX}", issuer_url.trim_end_matches('/'));
        let body = http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| OidcError::DiscoveryFetch(format!("{e}")))?
            .bytes()
            .await
            .map_err(|e| OidcError::DiscoveryFetch(format!("read body: {e}")))?;

        let raw: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| OidcError::DiscoveryParse(format!("{e}")))?;

        let issuer = raw
            .get("issuer")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(OidcError::MissingField("issuer"))?;
        let jwks_uri = raw
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(OidcError::MissingField("jwks_uri"))?;

        let pick = |key: &str| -> Option<String> {
            raw.get(key).and_then(|v| v.as_str()).map(String::from)
        };

        Ok(Self {
            issuer,
            jwks_uri,
            authorization_endpoint: pick("authorization_endpoint"),
            token_endpoint: pick("token_endpoint"),
            userinfo_endpoint: pick("userinfo_endpoint"),
            end_session_endpoint: pick("end_session_endpoint"),
            revocation_endpoint: pick("revocation_endpoint"),
            pushed_authorization_request_endpoint: pick("pushed_authorization_request_endpoint"),
            device_authorization_endpoint: pick("device_authorization_endpoint"),
            raw,
        })
    }
}

/// OIDC discovery + refreshable JWKS cache, bundled.
///
/// Adopters that need both the parsed metadata and a long-lived JWKS
/// handle (e.g. token verifiers running across multiple requests) hold
/// one of these per issuer.
pub struct Discovery {
    document: DiscoveryDocument,
    jwks_cache: JwksCache,
}

impl Discovery {
    /// Fetch the discovery document at `issuer_url`, then fetch the
    /// JWKS at the `jwks_uri` it advertises, returning a primed cache.
    ///
    /// The supplied client is reused for the JWKS fetch and cloned into
    /// the resulting cache for subsequent refreshes.
    pub async fn fetch(
        issuer_url: &str,
        http_client: &openidconnect::reqwest::Client,
    ) -> Result<Self, OidcError> {
        let document = DiscoveryDocument::fetch(issuer_url, http_client).await?;
        let jwks_cache = JwksCache::fetch(document.jwks_uri.clone(), http_client).await?;
        Ok(Self {
            document,
            jwks_cache,
        })
    }

    /// Parsed discovery document.
    pub fn document(&self) -> &DiscoveryDocument {
        &self.document
    }

    /// Shared handle to the cached `JwkSet`.
    pub fn jwks(&self) -> Arc<RwLock<JwkSet>> {
        self.jwks_cache.handle()
    }

    /// Underlying JWKS cache, for callers that need direct access (e.g.
    /// to drive a background rotation loop).
    pub fn jwks_cache(&self) -> &JwksCache {
        &self.jwks_cache
    }

    /// Re-fetch the JWKS, coalescing concurrent callers.
    pub async fn refresh_jwks(&self) -> Result<(), OidcError> {
        self.jwks_cache.refresh().await
    }
}

/// Reject non-HTTPS issuer URLs unless they target the loopback
/// allowlist (`localhost`, `127.0.0.1`, `[::1]`). HTTPS-on-issuer is what
/// transitively secures the JWKS URI: an attacker that can rewrite the
/// discovery doc can swap `jwks_uri` to a key set they control.
fn require_https_or_loopback(issuer_url: &str) -> Result<(), OidcError> {
    if issuer_url.starts_with("https://") {
        return Ok(());
    }
    let is_loopback = issuer_url.starts_with("http://localhost")
        || issuer_url.starts_with("http://127.0.0.1")
        || issuer_url.starts_with("http://[::1]");
    if is_loopback {
        return Ok(());
    }
    Err(OidcError::NonHttpsIssuer(issuer_url.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_jwks_json() -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "k1",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
            }],
        })
    }

    fn discovery_json(issuer: &str, jwks_uri: &str) -> serde_json::Value {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": jwks_uri,
            "end_session_endpoint": format!("{issuer}/logout"),
            "scopes_supported": ["openid", "email", "profile"],
        })
    }

    #[tokio::test]
    async fn document_fetch_parses_well_known() {
        let server = MockServer::start().await;
        let jwks_uri = format!("{}/jwks", server.uri());
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(discovery_json(&server.uri(), &jwks_uri)),
            )
            .mount(&server)
            .await;

        let client = openidconnect::reqwest::Client::new();
        let doc = DiscoveryDocument::fetch(&server.uri(), &client)
            .await
            .expect("fetch ok");

        assert_eq!(doc.issuer, server.uri());
        assert_eq!(doc.jwks_uri, jwks_uri);
        assert!(doc.authorization_endpoint.is_some());
        assert!(doc.end_session_endpoint.is_some());
        assert!(doc.revocation_endpoint.is_none());
        // Raw JSON preserves extension fields.
        assert!(doc.raw.get("scopes_supported").is_some());
    }

    #[tokio::test]
    async fn document_fetch_rejects_missing_jwks_uri() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": server.uri(),
                // jwks_uri intentionally omitted
            })))
            .mount(&server)
            .await;

        let client = openidconnect::reqwest::Client::new();
        let err = DiscoveryDocument::fetch(&server.uri(), &client)
            .await
            .expect_err("missing jwks_uri must reject");
        assert!(
            matches!(err, OidcError::MissingField("jwks_uri")),
            "expected MissingField(jwks_uri), got {err:?}",
        );
    }

    #[tokio::test]
    async fn document_fetch_rejects_non_https_non_loopback() {
        let client = openidconnect::reqwest::Client::new();
        let err = DiscoveryDocument::fetch("http://idp.example.com", &client)
            .await
            .expect_err("plain http must reject");
        assert!(
            matches!(err, OidcError::NonHttpsIssuer(_)),
            "expected NonHttpsIssuer, got {err:?}",
        );
    }

    #[tokio::test]
    async fn discovery_fetch_chains_jwks() {
        let server = MockServer::start().await;
        let jwks_uri = format!("{}/jwks", server.uri());
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(discovery_json(&server.uri(), &jwks_uri)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
            .mount(&server)
            .await;

        let client = openidconnect::reqwest::Client::new();
        let discovery = Discovery::fetch(&server.uri(), &client)
            .await
            .expect("discovery ok");

        assert_eq!(discovery.document().issuer, server.uri());
        let handle = discovery.jwks();
        assert_eq!(handle.read().unwrap().keys.len(), 1);
    }
}
