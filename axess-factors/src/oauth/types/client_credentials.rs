//! OAuth 2.0 Client Credentials grant token response (RFC 6749 §4.4).

use serde::{Deserialize, Serialize};

/// Token response from an OAuth 2.0 Client Credentials grant.
///
/// Used for service-to-service authentication where no user is involved.
/// The client authenticates directly with the authorization server using
/// its own credentials (`client_id` + `client_secret`) and receives an
/// access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCredentialsToken {
    /// The access token issued by the authorization server.
    ///
    /// Wrapped in [`ZeroizedString`](crate::secret::ZeroizedString) so the
    /// bearer string is redacted in `Debug` output and zeroed from the heap
    /// when dropped. The type derives `Debug`, and this is the field a
    /// `tracing` call recording the whole response would print.
    ///
    /// Unlike [`OAuthClaims::access_token`](crate::oauth::types::OAuthClaims),
    /// this field is *not* `#[serde(skip_serializing)]`: a client-credentials
    /// response is a token and nothing else, so an adopter caching one must
    /// be able to serialize it. `ZeroizedString` is transparent to serde in
    /// both directions.
    pub access_token: crate::secret::ZeroizedString,
    /// Token type (typically `"Bearer"`).
    pub token_type: String,
    /// Token lifetime in seconds.
    pub expires_in: Option<u64>,
    /// Granted scopes (may differ from requested).
    pub scope: Option<String>,
}
