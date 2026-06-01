//! Error type for OIDC discovery and JWKS retrieval.

use thiserror::Error;

/// Errors emitted by the OIDC primitive (discovery, JWKS fetch/refresh).
///
/// Provider-agnostic; adopters that wrap higher-level OAuth flows
/// (e.g. `OAuthError`) typically convert these at the boundary.
#[derive(Debug, Error)]
pub enum OidcError {
    /// The supplied issuer URL is syntactically invalid.
    #[error("invalid issuer URL: {0}")]
    InvalidIssuer(String),

    /// The issuer URL uses an insecure scheme and is not on the loopback
    /// allowlist (`localhost`, `127.0.0.1`, `[::1]`). Plain HTTP elsewhere
    /// would let an on-path attacker rewrite the discovery document and,
    /// transitively, the JWKS URI, defeating signature verification.
    #[error("issuer URL must use HTTPS (http is only allowed for loopback): {0}")]
    NonHttpsIssuer(String),

    /// The discovery document could not be fetched (network/transport error).
    #[error("discovery document fetch failed: {0}")]
    DiscoveryFetch(String),

    /// The discovery document was fetched but could not be parsed as JSON.
    #[error("discovery document parse failed: {0}")]
    DiscoveryParse(String),

    /// A field required by OIDC Core (`issuer`, `jwks_uri`) is missing
    /// from the discovery document.
    #[error("missing required discovery field: {0}")]
    MissingField(&'static str),

    /// The JWKS endpoint could not be fetched.
    #[error("JWKS fetch failed: {0}")]
    JwksFetch(String),

    /// The JWKS body was fetched but could not be parsed as RFC 7517 JSON.
    #[error("JWKS parse failed: {0}")]
    JwksParse(String),
}
