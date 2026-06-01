//! OAuth/OIDC ceremony methods on [`AuthnService`](super::AuthnService).
//!
//! The previous monolithic `oauth_service.rs` (1187 lines) was split
//! into orthogonal sub-modules:
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
mod login;
mod refresh;
mod tokens;
mod userinfo;
