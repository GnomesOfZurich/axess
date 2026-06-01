//! Shared JWT primitives for signature verification and claim validation.
//!
//! Reusable helpers, not a bearer-token authentication layer. Axess is
//! session-based; these primitives exist so that adopters performing JWT
//! verification (e.g. workload identity, federated OIDC checks, custom
//! logout flows) can share the same hardened parse-and-verify code paths
//! used internally by OAuth and backchannel logout.

pub mod claims;
#[cfg(feature = "jwt-svid")]
pub mod svid;
pub mod validation;
pub mod verifier;
