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

/// Largest discovery document body read (1 MiB). Real documents are a few
/// kilobytes; a larger body is refused while it arrives, not buffered.
pub const MAX_DISCOVERY_BYTES: usize = 1024 * 1024;

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
        let mut response = http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| OidcError::DiscoveryFetch(format!("{e}")))?
            // A 500 with a JSON body is not a discovery document.
            .error_for_status()
            .map_err(|e| OidcError::DiscoveryFetch(format!("{e}")))?;
        let body = crate::oidc::body::read_capped(
            &mut response,
            MAX_DISCOVERY_BYTES,
            || OidcError::DiscoveryFetch("discovery body exceeds limit".to_string()),
            |e| OidcError::DiscoveryFetch(format!("read body: {e}")),
        )
        .await?;

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

        // The document is bound to the issuer it was fetched from (OIDC
        // Discovery §4.3, RFC 8414 §3.3): a document naming another issuer is
        // a mix-up, not a configuration. And the key set it points at travels
        // over the same rail as the document, else an on-path attacker swaps
        // the keys the document names.
        if issuer.trim_end_matches('/') != issuer_url.trim_end_matches('/') {
            return Err(OidcError::InvalidIssuer(format!(
                "discovery document names issuer {issuer} but was fetched from {issuer_url}"
            )));
        }
        require_https_or_loopback(&jwks_uri)?;

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
pub(crate) fn require_https_or_loopback(issuer_url: &str) -> Result<(), OidcError> {
    // Parsed, not prefix-matched: `http://localhost.attacker.com`,
    // `http://127.0.0.1.nip.io` and `http://localhost@evil.com` all start with
    // a loopback spelling and none is loopback. The HOST decides, and a URL
    // carrying userinfo is refused outright, since `user@host` is how a
    // prefix test is defeated.
    let refuse = || OidcError::NonHttpsIssuer(issuer_url.to_string());
    let parsed = url::Url::parse(issuer_url).map_err(|_| refuse())?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(refuse());
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => match parsed.host() {
            Some(url::Host::Domain("localhost")) => Ok(()),
            Some(url::Host::Ipv4(ip)) if ip.is_loopback() => Ok(()),
            Some(url::Host::Ipv6(ip)) if ip.is_loopback() => Ok(()),
            _ => Err(refuse()),
        },
        _ => Err(refuse()),
    }
}

#[cfg(test)]
mod tests;
