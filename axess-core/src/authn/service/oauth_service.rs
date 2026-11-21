//! OAuth/OIDC ceremony methods on [`AuthnService`](super::AuthnService).
//!
//! The methods sit in sub-modules by concern:
//!
//! - `login`: three-step ceremony (`begin` / `finish` / `complete`)
//!   plus the claim-binding lock, tenant rail, PAR single-flight,
//!   and the OIDC `sid` mapping for back-channel logout.
//! - `refresh`: refresh-token exchange against the IdP's `/token`
//!   endpoint.
//! - `userinfo`: passthrough to the OIDC UserInfo endpoint.
//! - `tokens`: token-side operations (RFC 7009 revocation, RP-Initiated
//!   Logout URL builder, FAPI 2.0 DPoP proof generation).
//! - `jwks_refresh`: background ticker that proactively refreshes
//!   per-provider JWKS so back-channel logout doesn't trip on a missing
//!   `kid` after key rotation.
//!
//! Each submodule contributes its own `impl<I, F> AuthnService<I, F>`
//! block. Public method surface is byte-identical to the pre-split
//! monolith.

mod jwks_refresh;
pub(crate) use jwks_refresh::{JwksRefreshTask, live_providers};
mod login;
mod refresh;
mod scoped;
pub use login::OAuthCallbackRoute;
pub use scoped::ScopedOAuth;
mod tokens;
pub use tokens::OAUTH_REVOCATION_REQUESTED_REASON;
mod userinfo;

/// A provider name a caller passed in, as a span or a log line carries it:
/// the name is often the request's own text (the `{provider}` of a route),
/// so it is escaped and cut as every request text is (see
/// [`logged_request_text`](super::log_text::logged_request_text)).
fn logged_provider_name(name: &str) -> String {
    super::log_text::logged_request_text(name)
}

/// The refusal of a provider name nothing resolves: the name as a span
/// carries it ([`logged_provider_name`]), since the error is logged and
/// shown as the span is, and the name is the caller's text. A registered
/// name with no control character and within the cut reads as it was.
fn unknown_provider(name: &str) -> axess_factors::oauth::OAuthError {
    axess_factors::oauth::OAuthError::UnknownProvider(logged_provider_name(name))
}
