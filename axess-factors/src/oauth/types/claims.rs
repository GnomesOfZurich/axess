//! ID-token and UserInfo claim shapes returned by the IdP.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// OIDC claims extracted from a validated ID token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClaims {
    /// Provider name (e.g. `"google"`).
    pub provider: Arc<str>,
    /// OIDC subject: unique, stable identifier at this provider.
    pub subject: String,
    /// Email address (if `email` scope was granted).
    pub email: Option<String>,
    /// Whether the email has been verified by the provider.
    pub email_verified: Option<bool>,
    /// Display name (if `profile` scope was granted).
    pub name: Option<String>,
    /// Group memberships from the IdP (e.g. Azure AD `groups` claim).
    pub groups: Vec<String>,
    /// Role assignments from the IdP (e.g. Azure AD `roles` claim).
    pub roles: Vec<String>,
    /// The access token returned by the IdP, if any.
    ///
    /// Wrapped in [`ZeroizedString`](crate::secret::ZeroizedString)
    /// so the bearer string is zeroed from heap when dropped; bounds the
    /// window during which the token is recoverable from a process dump
    /// or core file.
    #[serde(skip_serializing)]
    pub access_token: Option<crate::secret::ZeroizedString>,
    /// The refresh token returned by the IdP, if any. Zeroized on drop.
    #[serde(skip_serializing)]
    pub refresh_token: Option<crate::secret::ZeroizedString>,
    /// OIDC session ID (`sid` claim) from the ID token, if present.
    pub oidc_sid: Option<String>,
    /// Raw ID token JWT string, preserved for RP-Initiated Logout
    /// (`id_token_hint` parameter to the IdP's `end_session_endpoint`).
    /// Zeroized on drop. The JWT carries `sub`, `email`, and other PII.
    #[serde(skip_serializing)]
    pub id_token_hint: Option<crate::secret::ZeroizedString>,
    /// All additional claims from the ID token as a raw JSON map.
    pub additional_claims: serde_json::Value,
}

/// Claims returned by the OIDC UserInfo endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfoClaims {
    /// OIDC subject: unique, stable identifier at this provider.
    pub sub: String,
    /// Email address (if `email` scope was granted).
    pub email: Option<String>,
    /// Whether the email has been verified by the provider.
    pub email_verified: Option<bool>,
    /// Display name.
    pub name: Option<String>,
    /// Given (first) name.
    pub given_name: Option<String>,
    /// Family (last) name.
    pub family_name: Option<String>,
    /// URL of the user's profile picture.
    pub picture: Option<String>,
    /// User's locale (e.g. `"en-US"`).
    pub locale: Option<String>,
    /// Any additional claims from the provider not covered by the fixed fields.
    #[serde(flatten)]
    pub additional: serde_json::Value,
}
