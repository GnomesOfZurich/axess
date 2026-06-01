//! FAPI 2.0 Baseline Profile types: sender-constraint mechanisms,
//! Pushed Authorization Requests (RFC 9126), DPoP proofs (RFC 9449).

use serde::Deserialize;

/// Sender-constraint mechanism for FAPI 2.0.
///
/// FAPI 2.0 requires tokens to be bound to the client that requested them.
/// Choose one of these mechanisms based on your IdP and deployment topology.
#[derive(Debug, Clone)]
pub enum SenderConstraint {
    /// DPoP (RFC 9449): ephemeral key pair per session, proof JWT on each request.
    /// Preferred for browser-based and mobile clients.
    DPoP,
    /// MTLS (RFC 8705): client TLS certificate presented during token exchange.
    /// Requires TLS client cert configuration. Preferred for server-to-server.
    Mtls {
        /// Path to the PEM-encoded client certificate.
        client_cert_path: String,
        /// Path to the PEM-encoded client private key.
        client_key_path: String,
    },
}

/// FAPI 2.0 Baseline Profile configuration.
///
/// When applied to a provider via [`OAuthProviderConfig::with_fapi`](crate::oauth::OAuthProviderConfig::with_fapi), enforces:
/// - Mandatory PAR (authorization params sent server-to-server)
/// - Mandatory PKCE with S256 (already the default in axess)
/// - Sender-constrained tokens (DPoP or MTLS)
/// - JARM (JWT-secured authorization responses) when `require_jarm` is set
/// - Stricter token lifetimes (ID token `exp` ≤ 5 minutes)
/// - `nbf` enforcement on ID tokens
#[derive(Debug, Clone)]
pub struct FapiConfig {
    /// How tokens are bound to the client.
    pub sender_constraint: SenderConstraint,
    /// Require JWT-secured authorization responses (JARM).
    pub require_jarm: bool,
    /// Maximum allowed ID token lifetime in seconds. Default: 300 (5 minutes).
    pub max_id_token_lifetime_secs: u64,
}

impl Default for FapiConfig {
    fn default() -> Self {
        Self {
            sender_constraint: SenderConstraint::DPoP,
            require_jarm: false,
            max_id_token_lifetime_secs: 300,
        }
    }
}

/// Response from a Pushed Authorization Request (RFC 9126).
#[derive(Debug, Clone, Deserialize)]
pub struct ParResponse {
    /// Opaque URI referencing the pushed authorization request.
    pub request_uri: String,
    /// Lifetime of the request_uri in seconds.
    pub expires_in: u64,
}

/// A DPoP proof and its associated public key thumbprint.
#[derive(Debug, Clone)]
pub struct DpopProof {
    /// The DPoP proof JWT to include in the `DPoP` header.
    pub proof_jwt: String,
    /// The JWK thumbprint of the ephemeral key (`jkt` for token binding).
    pub thumbprint: String,
}
