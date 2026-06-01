//! GitHub Actions OIDC token recipe.
//!
//! Wires axess's generic
//! [`WorkloadResolver`](axess_factors::federation::workload::WorkloadResolver)
//! against the GitHub Actions JWT shape. Verifies tokens signed by
//! `https://token.actions.githubusercontent.com` and synthesises a
//! SPIFFE-shape workload id from the `repository` /
//! `repository_owner` claims.
//!
//! # Wire-up
//!
//! ```ignore
//! use axess_example_workload_identity::github_actions::{
//!     github_actions_mapper, GitHubActionsClaims,
//! };
//! use axess_factors::federation::workload::WorkloadResolver;
//! use axess_factors::jwt::verifier::JwtVerifier;
//! use axess_identity::{Issuer, TrustDomain};
//! use std::sync::Arc;
//!
//! // Startup wiring (cache the verifier; reuse across requests):
//! let verifier = Arc::new(
//!     JwtVerifier::new(github_jwks_handle)
//!         .with_issuer("https://token.actions.githubusercontent.com")
//!         .with_audience("axess-platform"),
//! );
//! let trust_domain = TrustDomain::new("github.actions").unwrap();
//!
//! // Per-request:
//! let resolver = WorkloadResolver::<GitHubActionsClaims, _, _>::new(
//!     verifier.clone(),
//!     trust_domain.clone(),
//!     tenant_id,                              // adopter looked up from owner
//!     Issuer::custom("github_actions").unwrap(),
//!     bearer_token,
//!     github_actions_mapper(trust_domain),
//! );
//! let principal = resolver.resolve().await?;
//! ```
//!
//! # SPIFFE path shape
//!
//! Recipe synthesises `spiffe://<trust_domain>/<repo>/<owner>` so the
//! repo serves as the SPIFFE `service_name` and the owner as the
//! `tenant_slug`. Adjust `mapper`'s body if your SPIFFE convention
//! places these in a different path order, or if you want to encode
//! `environment` / `workflow_ref` as additional path segments.

use std::collections::BTreeMap;

use axess_factors::federation::workload::WorkloadMapping;
use axess_factors::jwt::verifier::VerifiedClaims;
use axess_identity::{IdentityError, TrustDomain, WorkloadId};
use serde::Deserialize;

/// GitHub Actions OIDC custom-claim shape. Only the fields needed for
/// SPIFFE synthesis + Cedar-attribute preservation are deserialised;
/// other GitHub-specific claims (`workflow_ref`, `job_workflow_ref`,
/// `head_ref`, `base_ref`, `ref_type`, …) can be added by extending
/// this struct. Adopters wanting a different attribute set should
/// fork this struct rather than waiting for axess to add fields.
#[derive(Debug, Deserialize)]
pub struct GitHubActionsClaims {
    /// Full `OWNER/REPO` slug.
    pub repository: String,
    /// Repository owner (org or user login).
    pub repository_owner: String,
    /// Actor who triggered the workflow run.
    #[serde(default)]
    pub actor: Option<String>,
    /// Workflow name (display name from the YAML).
    #[serde(default)]
    pub workflow: Option<String>,
    /// `refs/heads/...` etc.
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
    /// Commit SHA the workflow run is targeting.
    #[serde(default)]
    pub sha: Option<String>,
    /// Triggering event (`push`, `pull_request`, `workflow_dispatch`, …).
    #[serde(default)]
    pub event_name: Option<String>,
}

/// Build the claim-mapping closure for [`WorkloadResolver`](axess_factors::federation::workload::WorkloadResolver).
///
/// Captures the `trust_domain` so the synthesised `WorkloadId` lives
/// under the SPIFFE trust domain the resolver pins.
pub fn github_actions_mapper(
    trust_domain: TrustDomain,
) -> impl Fn(&VerifiedClaims<GitHubActionsClaims>) -> Result<WorkloadMapping, IdentityError> + Send + Sync
{
    move |claims| {
        let custom = &claims.custom;

        // Split `OWNER/REPO` so the owner becomes `tenant_slug` and the
        // bare repo name becomes `service_name`.
        let repo_name = custom
            .repository
            .strip_prefix(&format!("{}/", custom.repository_owner))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                IdentityError::InvalidComponent(format!(
                    "GitHub `repository` ({}) does not start with `repository_owner/` ({})",
                    custom.repository, custom.repository_owner
                ))
            })?;

        let workload_id = WorkloadId::build(&trust_domain, repo_name, &custom.repository_owner)?;

        let mut attributes = BTreeMap::new();
        if let Some(v) = &custom.actor {
            attributes.insert("actor".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(v) = &custom.workflow {
            attributes.insert("workflow".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(v) = &custom.git_ref {
            attributes.insert("ref".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(v) = &custom.sha {
            attributes.insert("sha".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(v) = &custom.event_name {
            attributes.insert(
                "event_name".to_string(),
                serde_json::Value::String(v.clone()),
            );
        }

        Ok(WorkloadMapping {
            workload_id,
            service_name: repo_name.to_string(),
            tenant_slug: custom.repository_owner.clone(),
            attributes,
        })
    }
}
