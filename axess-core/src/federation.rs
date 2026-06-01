//! Orchestrator-side external-IdP integration code.
//!
//! Per-protocol algorithms and data shapes (OAuth ceremony, JWT
//! verifier, mTLS resolver, FIDO2 provider, LDAP bind, PKCE predicate,
//! federation adapters) live in [`axess_factors`]. This module owns
//! the pieces that compose those primitives on the **orchestrator**
//! side:
//!
//! - **OAuth provider registry** ([`oauth::OAuthProviderRegistry`](crate::federation::oauth::OAuthProviderRegistry)):
//!   the per-`AuthnService` map of configured OAuth providers.
//! - **LDAP health check** ([`ldap`](crate::federation::ldap)): `HealthCheck` impl for
//!   `LdapProviderConfig` (the trait lives in axess-core).
//! - **Back-channel logout** ([`backchannel_logout`](crate::federation::backchannel_logout)) and
//!   **front-channel logout** ([`frontchannel_logout`](crate::federation::frontchannel_logout)): IdP-initiated
//!   logout flows.
//!
//! Each submodule is feature-gated; pure factor primitives are reached
//! via `axess_factors::*` directly.

#[cfg(feature = "oauth")]
pub mod backchannel_logout;
#[cfg(feature = "oauth")]
pub mod frontchannel_logout;
#[cfg(feature = "ldap")]
pub mod ldap;
#[cfg(feature = "oauth")]
pub mod oauth;
