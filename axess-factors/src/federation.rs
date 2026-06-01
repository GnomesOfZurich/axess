//! Workload-identity federation.
//!
//! One generic [`WorkloadResolver`](workload::WorkloadResolver) that
//! verifies any JWT-bearer workload token (GitHub Actions OIDC,
//! Kubernetes service-account projected tokens, GitLab CI OIDC,
//! Okta / Azure AD / Auth0, axess `LocalIdP`, etc.) against a
//! configured [`JwtVerifier`](super::jwt::verifier::JwtVerifier) and
//! dispatches the verified claims through a caller-supplied
//! claim-mapping closure to produce a
//! [`Principal::Workload`](axess_identity::Principal::Workload) with a
//! synthesized SPIFFE-shape [`WorkloadId`](axess_identity::WorkloadId).
//!
//! # Design
//!
//! axess deliberately ships *no* per-issuer adapters. The differences
//! between issuers (which JWT claim carries the workload identity,
//! how it maps to `(service, tenant_slug)`, which extra fields are
//! preserved as Cedar attributes) are adopter-owned data. Hardcoding
//! per-company adapters would invite endless additions (`wif-gitlab`,
//! `wif-circleci`, `wif-buildkite`, …) without any reuse benefit
//! beyond what a small claim parser + mapping closure already provides.
//!
//! The typed [`TenantId`](axess_identity::TenantId) is adopter-supplied
//! at resolver construction; the same registry-agnostic pattern as
//! [`MtlsResolver`](super::mtls::MtlsResolver). Adopter middleware
//! peeks at the JWT (or whatever issuer-specific claim drives tenant
//! selection) to look up the tenant id before constructing the resolver.
//!
//! # Recipes
//!
//! Ready-made claim parsers + mappers for GitHub Actions and
//! Kubernetes service-account tokens live in the
//! `axess-example-workload-identity` crate. Adopters copy the recipe
//! that matches their IdP and wire it against
//! [`WorkloadResolver`](workload::WorkloadResolver) here.
//!
//! # SPIFFE-spec adapter
//!
//! [`JwtSvidResolver`](super::jwt::svid::JwtSvidResolver) is the one
//! exception to the generic pattern. It implements the SPIFFE JWT-SVID
//! *spec* (mandatory `spiffe://` URI in `sub`, trust-domain extracted
//! from the URI), not just a claim shape, so it earns its own module
//! gated on the `jwt-svid` feature.
//!
//! # Out of scope here
//!
//! AWS STS, GCP WIF, and Azure FIC are *exchange flows* (the cloud STS
//! exchanges a presented token for cloud credentials) where axess is
//! the relying party feeding into the exchange, not the verifier
//! consuming its output. Different shape, lands when a concrete
//! adopter forces the design.

#[cfg(feature = "jwt")]
pub mod workload;
