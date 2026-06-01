//! Principal abstraction.
//!
//! Type definitions, the [`PrincipalResolver`] trait, [`CliResolver`],
//! and [`MockResolver`](axess_identity::testing::MockResolver) live in the
//! lightweight [`axess_identity`] sub-crate (no axum/tokio/Cedar deps)
//! so adopters needing just the principal *data* (event-envelope
//! stamping, log spans, audit attribution) can depend on
//! `axess-identity` directly and skip the full axess-core surface.
//!
//! This module re-exports the leaf types and adds the two pieces that
//! need axess-core's session and Cedar surfaces:
//!
//! - `SessionResolver`: extracts a [`HumanPrincipal`] from an
//!   authenticated [`AuthSession`](crate::AuthSession). Lives in
//!   axess-core because it depends on the session state machine.
//! - `crate::principal::cedar::ToCedarEntity`: trait emitting
//!   `cedar_policy::Entity` values for adopters using axess Cedar
//!   authorization. Gated on the existing `authz` feature.

#[cfg(feature = "authz")]
pub mod cedar;
pub mod extractor;
pub mod session_resolver;

#[cfg(any(test, feature = "testing"))]
pub use axess_identity::testing::MockResolver;
pub use axess_identity::{
    CliResolver, CliResolverBuilder, HumanPrincipal, IdentityError, Issuer, Principal,
    PrincipalResolver, TrustDomain, WorkloadId, WorkloadPrincipal,
};

pub use extractor::{AuthHumanPrincipal, AuthPrincipal, AuthWorkloadPrincipal, PrincipalRejection};
pub use session_resolver::SessionResolver;

#[cfg(feature = "authz")]
pub use cedar::{
    HUMAN_ENTITY_TYPE, PRINCIPAL_NAMESPACE, ToCedarEntity, WORKLOAD_ENTITY_TYPE,
    json_to_restricted_expression,
};
