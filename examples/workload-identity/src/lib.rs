//! Adopter recipes for axess's generic
//! [`WorkloadResolver`](axess::workload_identity::WorkloadResolver).
//!
//! axess deliberately ships *no* per-issuer adapters: each IdP's JWT
//! claim shape is small enough (~20 lines for the struct, ~30 for the
//! mapper) that hard-coding a `wif-github`, `wif-k8s`, `wif-gitlab`,
//! `wif-buildkite` feature surface per company invites endless
//! additions without reuse benefit. Adopters copy the recipe that
//! matches their IdP and wire it against the generic resolver.
//!
//! Two recipes ship here:
//!
//! - [`github_actions`]; GitHub Actions OIDC tokens
//!   (`https://token.actions.githubusercontent.com`), mapping the
//!   `repository` / `repository_owner` claims to a SPIFFE-shape
//!   workload id and preserving `actor`, `workflow`, `ref`, `sha`,
//!   `event_name` as Cedar attributes.
//! - [`kubernetes`]; projected service-account tokens
//!   (`kubernetes.io.{namespace,serviceaccount.name}` claim
//!   namespace), mapping namespace + service-account-name to the same
//!   shape.
//!
//! Each recipe is `pub` so the example crate can be a dependency for
//! integration tests in adopter projects, but the intended use is
//! copy-paste: read the source, drop the parts you need into your
//! codebase, adjust the SPIFFE-path layout to fit your trust-domain
//! convention.

pub mod github_actions;
pub mod kubernetes;
