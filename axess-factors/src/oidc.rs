//! OIDC discovery and JWKS retrieval primitives.
//!
//! The same hardened fetch-and-rotate plumbing used by the OAuth ceremony
//! surface, exposed for adopters that verify JWTs without taking it:
//! workload identity verifiers, federated IdP token checkers, custom
//! validators.

mod body;
pub mod discovery;
pub mod error;
pub mod jwks_cache;
pub mod logout_token;

pub use discovery::{Discovery, DiscoveryDocument, MAX_DISCOVERY_BYTES};
pub use error::OidcError;
pub use jwks_cache::{DEFAULT_JWKS_MAX_AGE, JwksCache, MAX_JWKS_BYTES, MIN_JWKS_REFRESH_INTERVAL};
