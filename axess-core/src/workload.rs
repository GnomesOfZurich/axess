//! Outbound workload identity: axess presenting its own identity to a
//! 3rd party (OAuth `client_credentials` / `private_key_jwt`,
//! client-side mTLS, signed JWT assertions, cloud-STS exchanges). Each
//! mechanism lives under [`crate::workload::outbound`].
//!
//! Inbound workload-identity resolvers (axess verifying an incoming
//! claim from an external workload):
//!
//! - SPIFFE JWT-SVID; `axess_factors::jwt::svid` (gated on
//!   `jwt-svid`; SPIFFE *spec* adherence; mandatory `spiffe://` URI
//!   in `sub`).
//! - SPIFFE X509-SVID over mTLS; `axess_factors::mtls`.
//! - Every other JWT-bearer issuer; re-exported below as
//!   `workload`, gated on `jwt`. One generic
//!   `WorkloadResolver` covers GitHub Actions OIDC, Kubernetes
//!   service-account tokens, GitLab CI OIDC, Okta, Azure AD, Auth0,
//!   axess `LocalIdP`, and any other JWT-bearer flow via an
//!   adopter-supplied claim parser + mapping closure. Ready-made
//!   recipes live in the `axess-example-workload-identity` crate.
//!
//! The fetch side of SPIFFE, a workload asking a local SPIRE agent for its
//! own SVIDs and for the bundles to verify its peers with, is
//! `spire` (gated on the feature of that name).
//!
//! See [`crate::delegated`] for the orthogonal "axess acts on a user's
//! behalf at a 3rd party" concern.

pub mod outbound;

// SPIFFE Workload API client: SVIDs and trust bundles fetched from a local
// SPIRE agent and kept current. Gated on `spire`. The module's own
// documentation is the whole of it: a doc comment here would have rustdoc
// resolve that documentation's links from this module instead.
#[cfg(feature = "spire")]
#[cfg_attr(docsrs, doc(cfg(feature = "spire")))]
pub mod spire;

/// Re-export of the generic JWT-bearer workload-identity resolver
/// from `axess-factors`. Adopters program against this directly for
/// any non-SPIFFE workload-identity flow. Types are re-exported at
/// this module's root (`axess_core::workload::WorkloadResolver`) so
/// the import path stays one segment deep on the facade
/// (`axess::workload::WorkloadResolver`).
#[cfg(feature = "jwt")]
pub use axess_factors::federation::workload::{WorkloadMapping, WorkloadResolver};
