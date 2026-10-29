//! FAPI 2.0 Baseline Profile types: sender-constraint mechanisms,
//! Pushed Authorization Requests (RFC 9126), DPoP proofs (RFC 9449).

use super::dpop_key::DpopKey;
use serde::Deserialize;

/// The ID-token signature algorithms FAPI 2.0 permits: `PS256`, `ES256` and
/// `EdDSA`. The default of [`FapiConfig::allowed_id_token_algs`].
pub const FAPI_ID_TOKEN_ALGS: [&str; 3] = ["PS256", "ES256", "EdDSA"];

/// Sender-constraint mechanism for FAPI 2.0.
///
/// FAPI 2.0 requires tokens to be bound to the client that requested them.
/// Choose one of these mechanisms based on your IdP and deployment topology.
#[derive(Debug, Clone)]
pub enum SenderConstraint {
    /// DPoP (RFC 9449): one key per login, a proof JWT on the token request
    /// and on every call made with the token. Preferred for browser-based and
    /// mobile clients.
    DPoP,
    /// MTLS (RFC 8705): the client certificate is presented on the TLS
    /// handshake of every request to the authorization server, and the client
    /// authenticates with it (`tls_client_auth`), so the configured client
    /// secret is not sent. The token, revocation, userinfo and PAR requests
    /// go to the `mtls_endpoint_aliases` the server advertises, when it
    /// advertises them. Preferred for server-to-server.
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
/// - Sender-constrained tokens (DPoP or MTLS): the token request carries the
///   proof or the client certificate, and a response whose `token_type` is
///   not what the constraint promises is refused
/// - JARM (JWT-secured authorization responses) when `require_jarm` is set
/// - Stricter token lifetimes (ID token `exp` ≤ 5 minutes)
/// - `nbf` enforcement on ID tokens
/// - A short allow-list of ID-token signature algorithms
#[derive(Debug, Clone)]
pub struct FapiConfig {
    /// How tokens are bound to the client.
    pub sender_constraint: SenderConstraint,
    /// Require JWT-secured authorization responses (JARM). The authorization
    /// request then asks for `response_mode=jwt`, and the callback is
    /// finished with `finish_oauth_login_jarm`; the plain callback is
    /// refused.
    pub require_jarm: bool,
    /// Maximum allowed ID token lifetime in seconds. Default: 300 (5 minutes).
    pub max_id_token_lifetime_secs: u64,
    /// The JWS algorithms an ID token may be signed with, by their JOSE
    /// names. Default: [`FAPI_ID_TOKEN_ALGS`]. A deployment against an IdP
    /// that cannot sign with those names widens it here, knowingly: the
    /// profile does not accept `RS256`.
    pub allowed_id_token_algs: Vec<String>,
}

impl Default for FapiConfig {
    fn default() -> Self {
        Self {
            sender_constraint: SenderConstraint::DPoP,
            require_jarm: false,
            max_id_token_lifetime_secs: 300,
            allowed_id_token_algs: FAPI_ID_TOKEN_ALGS
                .iter()
                .map(|a| (*a).to_string())
                .collect(),
        }
    }
}

/// What a request needs to carry a DPoP proof: the key the token is bound to
/// and a source for the proof's `jti`.
///
/// The service makes one for each token request or protected-resource call
/// it sends for a DPoP provider and passes it to the `_with` methods of
/// [`OAuthProvider`](crate::oauth::OAuthProvider). The provider reads the
/// time from its own clock.
#[derive(Clone, Copy)]
pub struct DpopSigner<'a> {
    /// The key the access token is (or will be) bound to.
    pub key: &'a DpopKey,
    /// Source of the 16 random bytes behind each proof's `jti`.
    pub rng: &'a dyn axess_rng::SecureRng,
}

impl std::fmt::Debug for DpopSigner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopSigner")
            .field("key", self.key)
            .finish_non_exhaustive()
    }
}

/// The members of a verified JARM authorization response (JWT Secured
/// Authorization Response Mode): the JWT's signature, `iss`, `aud` and `exp`
/// have been checked, and these are its authorization-response parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JarmResponse {
    /// The `iss` claim, which the caller compares with the provider's issuer.
    pub iss: String,
    /// The authorization code, when the response is a success.
    pub code: Option<String>,
    /// The `state` the request carried.
    pub state: Option<String>,
    /// The `error` member, when the response is a refusal.
    pub error: Option<String>,
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
