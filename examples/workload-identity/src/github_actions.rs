//! GitHub Actions OIDC token recipe.
//!
//! Wires axess's generic
//! [`WorkloadResolver`](axess_factors::federation::workload::WorkloadResolver)
//! against the GitHub Actions JWT shape. Verifies tokens signed by
//! `https://token.actions.githubusercontent.com` and synthesises a
//! SPIFFE-shape workload id from the numeric `repository_id` /
//! `repository_owner_id` claims.
//!
//! # Wire-up
//!
//! ```ignore
//! use axess_example_workload_identity::github_actions::{
//!     github_actions_mapper, GitHubActionsClaims, GitHubAllowlist,
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
//!     github_actions_mapper(
//!         trust_domain,
//!         GitHubAllowlist::new().owner_id("123456").repository_id("987654321"),
//!     ),
//! );
//! let principal = resolver.resolve().await?;
//! ```
//!
//! # Trust is decided by what you do with the claims
//!
//! GitHub signs tokens for every repository on the platform with the one
//! issuer above, and any workflow can request one for any audience. A valid
//! signature and audience therefore prove only "some GitHub workflow", not
//! "yours". Before honouring the identity this mapper builds:
//!
//! - key the identity on the numeric `repository_id` and
//!   `repository_owner_id`, never on the `repository` / `repository_owner`
//!   names. Names are mutable and reusable: an organisation or repository
//!   that is renamed, deleted or transferred frees its old name, and whoever
//!   registers it next signs tokens that carry the name you trusted. The ids
//!   do not move. This recipe requires both claims and refuses a token
//!   without them;
//! - give the mapper a [`GitHubAllowlist`] and refuse an owner id you do not
//!   know (the `tenant_id` argument above is that lookup, so it must fail
//!   closed);
//! - authorize on the whole workload id, never on the owner alone;
//! - for anything that deploys or mutates, require the `ref` (or the
//!   `environment`) to be a protected one, not just any branch.
//!
//! # SPIFFE path shape
//!
//! Recipe synthesises `spiffe://<trust_domain>/<repository_id>/<owner_id>`
//! so the repository id serves as the SPIFFE `service_name` and the owner
//! id as the `tenant_slug`; the human-readable names travel as attributes
//! (`repository`, `repository_owner`) for audit only. Adjust `mapper`'s body if your SPIFFE convention
//! places these in a different path order, or if you want to encode
//! `environment` / `workflow_ref` as additional path segments.

use std::collections::{BTreeMap, BTreeSet};

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
    /// Full `OWNER/REPO` slug. Mutable: audit only, never an identity key.
    pub repository: String,
    /// Repository owner (org or user login). Mutable: audit only.
    pub repository_owner: String,
    /// Immutable numeric repository id (a string on the wire). Required.
    pub repository_id: String,
    /// Immutable numeric id of the owning organisation or user. Required.
    pub repository_owner_id: String,
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

/// Which GitHub owners and repositories are trusted, by immutable id.
///
/// An owner id must be listed. When any repository id is listed, the token's
/// repository id must be one of them too; leave the repository list empty to
/// trust every repository of a listed owner.
#[derive(Debug, Clone, Default)]
pub struct GitHubAllowlist {
    owner_ids: BTreeSet<String>,
    repository_ids: BTreeSet<String>,
}

impl GitHubAllowlist {
    /// An empty allowlist, which refuses every token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust the owner (organisation or user) with this numeric id.
    pub fn owner_id(mut self, id: impl Into<String>) -> Self {
        self.owner_ids.insert(id.into());
        self
    }

    /// Trust only the repositories with these numeric ids (within trusted owners).
    pub fn repository_id(mut self, id: impl Into<String>) -> Self {
        self.repository_ids.insert(id.into());
        self
    }

    fn admits(&self, owner_id: &str, repository_id: &str) -> bool {
        self.owner_ids.contains(owner_id)
            && (self.repository_ids.is_empty() || self.repository_ids.contains(repository_id))
    }
}

/// Build the claim-mapping closure for [`WorkloadResolver`](axess_factors::federation::workload::WorkloadResolver).
///
/// Captures the `trust_domain` so the synthesised `WorkloadId` lives
/// under the SPIFFE trust domain the resolver pins.
pub fn github_actions_mapper(
    trust_domain: TrustDomain,
    allowlist: GitHubAllowlist,
) -> impl Fn(&VerifiedClaims<GitHubActionsClaims>) -> Result<WorkloadMapping, IdentityError> + Send + Sync
{
    move |claims| {
        let custom = &claims.custom;

        // The names must still agree with each other: a token whose
        // `repository` does not begin with its own `repository_owner` is
        // malformed whatever its ids say.
        let names_agree = custom
            .repository
            .strip_prefix(&format!("{}/", custom.repository_owner))
            .is_some_and(|name| !name.is_empty());
        if !names_agree {
            return Err(IdentityError::InvalidComponent(format!(
                "GitHub `repository` ({}) does not start with `repository_owner/` ({})",
                custom.repository, custom.repository_owner
            )));
        }

        if !allowlist.admits(&custom.repository_owner_id, &custom.repository_id) {
            return Err(IdentityError::NotAuthenticated);
        }

        let workload_id = WorkloadId::build(
            &trust_domain,
            &custom.repository_id,
            &custom.repository_owner_id,
        )?;

        let mut attributes = BTreeMap::new();
        attributes.insert(
            "repository".to_string(),
            serde_json::Value::String(custom.repository.clone()),
        );
        attributes.insert(
            "repository_owner".to_string(),
            serde_json::Value::String(custom.repository_owner.clone()),
        );
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
            service_name: custom.repository_id.clone(),
            tenant_slug: custom.repository_owner_id.clone(),
            attributes,
        })
    }
}
