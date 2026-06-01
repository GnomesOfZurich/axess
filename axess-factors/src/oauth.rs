//! OAuth 2.0 / OpenID Connect relying party support.
//!
//! Provides federated authentication via external identity providers (Google,
//! GitHub, Microsoft, enterprise IdPs). The flow is:
//!
//! 1. `AuthnService::begin_oauth_login`: generates an authorization URL with
//!    PKCE, state, and nonce. Redirect the user's browser there.
//! 2. The IdP authenticates the user and redirects back with an authorization code.
//! 3. `AuthnService::finish_oauth_login`: exchanges the code for tokens,
//!    validates the ID token, and returns the OIDC claims. The application maps
//!    these to a local user and completes the session.
//!
//! # Token refresh
//!
//! If the IdP returned a refresh token (e.g. `offline_access` scope was
//! requested), use `AuthnService::refresh_oauth_token` to exchange it for
//! new tokens without re-authenticating the user.
//!
//! # Deterministic simulation testing
//!
//! Use [`MockOAuthProvider`] in tests to simulate OIDC discovery and token
//! exchange without HTTP. Configure it with [`MockOAuthProvider::with_user`]
//! or [`MockOAuthProvider::with_failure`].

pub mod mock;
pub mod provider;
pub mod types;

pub use mock::MockOAuthProvider;
pub use provider::OAuthProviderConfig;
#[cfg(feature = "fapi")]
pub use provider::dpop_verify::{
    DpopJtiCache, DpopVerified, DpopVerifyRequest, MemoryJtiCache, verify_dpop_proof,
};
pub use types::OAuthProvider;
pub use types::*;

/// Re-export of [`crate::pkce`]. PKCE utilities live at the top of
/// `axess-factors` so they are accessible without the `oauth`
/// feature; this alias keeps `axess_factors::oauth::pkce` usable for
/// callers inside the OAuth surface.
pub use crate::pkce;

/// Extract a string array from a JSON value at the given key.
///
/// Public so `axess_core`'s `oauth.rs` shim can re-call it from the
/// same path adopters already use; consumers outside the provider
/// implementations shouldn't reach for it directly.
pub fn extract_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}
