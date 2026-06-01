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
    pub access_token: String,
    /// Token type (typically `"Bearer"`).
    pub token_type: String,
    /// Token lifetime in seconds.
    pub expires_in: Option<u64>,
    /// Granted scopes (may differ from requested).
    pub scope: Option<String>,
}
