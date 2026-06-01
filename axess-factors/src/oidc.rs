//! OIDC discovery and JWKS retrieval primitives.
//!
//! The same hardened fetch-and-rotate plumbing used by the OAuth ceremony
//! surface, exposed for adopters that verify JWTs without taking it:
//! workload identity verifiers, federated IdP token checkers, custom
//! validators.

pub mod discovery;
pub mod error;
pub mod jwks_cache;
pub mod logout_token;

pub use discovery::{Discovery, DiscoveryDocument};
pub use error::OidcError;
pub use jwks_cache::{JwksCache, MIN_JWKS_REFRESH_INTERVAL};
