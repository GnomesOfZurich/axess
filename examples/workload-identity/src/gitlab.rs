//! GitLab CI ID-token recipe.
//!
//! Wires axess's generic
//! [`WorkloadResolver`](axess_factors::federation::workload::WorkloadResolver)
//! against the claim set GitLab puts in a CI/CD job's ID token (the
//! `id_tokens:` keyword). The token is signed by the GitLab instance
//! (`https://gitlab.com`, or your self-managed or Azure-hosted instance's
//! URL; the keys are at `<instance>/oauth/discovery/keys`) and names the
//! audience the job asked for.
//!
//! # The job side
//!
//! ```yaml
//! deploy:
//!   stage: deploy
//!   environment: production
//!   id_tokens:
//!     AXESS_TOKEN:
//!       aud: https://axess.example.com   # must equal the verifier's audience
//!   script:
//!     - >
//!       curl --fail -H "Authorization: Bearer ${AXESS_TOKEN}"
//!       https://axess.example.com/deploy-hook
//! ```
//!
//! # The service side
//!
//! ```ignore
//! use axess_example_workload_identity::gitlab::{
//!     gitlab_mapper, GitLabAllowlist, GitLabClaims,
//! };
//! use axess_factors::federation::workload::WorkloadResolver;
//! use axess_factors::jwt::verifier::JwtVerifier;
//! use axess_identity::{Issuer, TrustDomain};
//! use std::sync::Arc;
//!
//! let verifier = Arc::new(
//!     JwtVerifier::new(gitlab_jwks_handle)
//!         .with_issuer("https://gitlab.example.com")
//!         .with_audience("https://axess.example.com"),
//! );
//! let trust_domain = TrustDomain::new("gitlab.ci").unwrap();
//!
//! let resolver = WorkloadResolver::<GitLabClaims, _, _>::new(
//!     verifier.clone(),
//!     trust_domain.clone(),
//!     |namespace_id| tenants.get(namespace_id).copied(), // None refuses the token
//!     Issuer::custom("gitlab_ci").unwrap(),
//!     bearer_token,
//!     gitlab_mapper(
//!         GitLabAllowlist::new()
//!             .namespace_id("1204")
//!             .project_id("4711")
//!             .environment("production"),
//!     ),
//! );
//! let principal = resolver.resolve().await?;
//! ```
//!
//! # Trust is decided by what you do with the claims
//!
//! One GitLab instance signs tokens for every project on it, and any job can
//! ask for any audience, so a valid signature and audience prove only "some
//! job on this instance". This mapper therefore:
//!
//! - keys the identity on the numeric `project_id` and `namespace_id`, never
//!   on `project_path` or `namespace_path`. Paths are mutable and reusable: a
//!   renamed, transferred or deleted project or group frees its old path, and
//!   whoever registers it next signs tokens that carry the path you trusted.
//!   The ids do not move. Both claims are required;
//! - requires the namespace id to be on the [`GitLabAllowlist`] (and, when
//!   project ids are listed, the project id too);
//! - requires `ref_protected` to be `true` unless the allowlist opts out with
//!   [`GitLabAllowlist::allow_unprotected_refs`]. A job on an unprotected
//!   branch is one any developer of the project can start, so it is not the
//!   project's deploy identity;
//! - when environments are listed, requires the `environment` claim to be one
//!   of them (a job with no environment is refused).
//!
//! Every refusal is an [`IdentityError::InvalidComponent`] that names the claim.
//!
//! # SPIFFE path shape
//!
//! `spiffe://<trust_domain>/<project_id>/<namespace_id>`: the project id is
//! the `service_name` and the namespace id the `tenant_slug`. The paths and
//! the rest travel as attributes for audit and policy.

use std::collections::{BTreeMap, BTreeSet};

use axess_factors::federation::workload::WorkloadMapping;
use axess_factors::jwt::verifier::VerifiedClaims;
use axess_identity::IdentityError;
use serde::Deserialize;

/// GitLab writes booleans in ID tokens as the strings `"true"` and `"false"`;
/// accept a real boolean too so a proxy that rewrites the token still parses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum GitLabBool {
    /// The documented form, `"true"` or `"false"`.
    Text(String),
    /// A JSON boolean.
    Flag(bool),
}

impl GitLabBool {
    /// True only for `"true"` or `true`.
    pub fn is_true(&self) -> bool {
        match self {
            Self::Text(s) => s == "true",
            Self::Flag(b) => *b,
        }
    }
}

/// The GitLab ID-token claims this recipe reads. GitLab sends more
/// (`ci_config_ref_uri`, `runner_id`, `deployment_tier`, ...); the verifier
/// ignores what is not listed, and a fork of this struct can add them.
#[derive(Debug, Deserialize)]
pub struct GitLabClaims {
    /// Immutable numeric project id (a string on the wire). Required.
    pub project_id: String,
    /// Immutable numeric id of the owning group or user namespace. Required.
    pub namespace_id: String,
    /// `group/subgroup/project`. Mutable: audit only, never an identity key.
    #[serde(default)]
    pub project_path: Option<String>,
    /// `group/subgroup`. Mutable: audit only.
    #[serde(default)]
    pub namespace_path: Option<String>,
    /// Branch or tag name the pipeline runs for.
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
    /// `branch` or `tag`.
    #[serde(default)]
    pub ref_type: Option<String>,
    /// Whether the ref is protected in the project.
    #[serde(default)]
    pub ref_protected: Option<GitLabBool>,
    /// The job's `environment:` name, when it has one.
    #[serde(default)]
    pub environment: Option<String>,
    /// `push`, `merge_request_event`, `schedule`, `web`, ...
    #[serde(default)]
    pub pipeline_source: Option<String>,
    /// Commit SHA of the pipeline.
    #[serde(default)]
    pub sha: Option<String>,
    /// Login of the user who started the pipeline.
    #[serde(default)]
    pub user_login: Option<String>,
    /// Numeric job id.
    #[serde(default)]
    pub job_id: Option<String>,
    /// Numeric pipeline id.
    #[serde(default)]
    pub pipeline_id: Option<String>,
}

/// Which GitLab namespaces, projects and environments are trusted, by
/// immutable id and by environment name.
///
/// A namespace id must be listed. When any project id is listed the token's
/// project id must be one of them too. When any environment is listed the
/// token's `environment` must be one of them. Protected refs only, unless
/// [`allow_unprotected_refs`](Self::allow_unprotected_refs) is called.
#[derive(Debug, Clone, Default)]
pub struct GitLabAllowlist {
    namespace_ids: BTreeSet<String>,
    project_ids: BTreeSet<String>,
    environments: BTreeSet<String>,
    unprotected_refs: bool,
}

impl GitLabAllowlist {
    /// An empty allowlist, which refuses every token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust the group or user namespace with this numeric id.
    pub fn namespace_id(mut self, id: impl Into<String>) -> Self {
        self.namespace_ids.insert(id.into());
        self
    }

    /// Trust only the projects with these numeric ids (within trusted namespaces).
    pub fn project_id(mut self, id: impl Into<String>) -> Self {
        self.project_ids.insert(id.into());
        self
    }

    /// Trust only jobs that run in one of the listed environments.
    pub fn environment(mut self, name: impl Into<String>) -> Self {
        self.environments.insert(name.into());
        self
    }

    /// Also admit jobs whose ref is not protected. Off by default: only for
    /// identities that may be used from any branch of the project.
    pub fn allow_unprotected_refs(mut self) -> Self {
        self.unprotected_refs = true;
        self
    }

    /// `Ok` when the claims are admitted; the error names the refusing claim.
    fn check(&self, c: &GitLabClaims) -> Result<(), IdentityError> {
        let refuse = |claim: &str, why: String| {
            Err(IdentityError::InvalidComponent(format!(
                "GitLab claim `{claim}` {why}"
            )))
        };
        if !self.namespace_ids.contains(&c.namespace_id) {
            return refuse(
                "namespace_id",
                format!("({}) is not on the allowlist", c.namespace_id),
            );
        }
        if !self.project_ids.is_empty() && !self.project_ids.contains(&c.project_id) {
            return refuse(
                "project_id",
                format!("({}) is not on the allowlist", c.project_id),
            );
        }
        if !self.unprotected_refs && !c.ref_protected.as_ref().is_some_and(GitLabBool::is_true) {
            return refuse("ref_protected", "is not true".to_string());
        }
        if !self.environments.is_empty() {
            match c.environment.as_deref() {
                Some(e) if self.environments.contains(e) => {}
                Some(e) => {
                    return refuse("environment", format!("({e}) is not on the allowlist"));
                }
                None => return refuse("environment", "is absent".to_string()),
            }
        }
        Ok(())
    }
}

/// Build the claim-mapping closure for [`WorkloadResolver`](axess_factors::federation::workload::WorkloadResolver).
///
/// The resolver builds the `WorkloadId` itself, under the trust domain it
/// pins, from the service name and tenant slug this mapper returns.
pub fn gitlab_mapper(
    allowlist: GitLabAllowlist,
) -> impl Fn(&VerifiedClaims<GitLabClaims>) -> Result<WorkloadMapping, IdentityError> + Send + Sync
{
    move |claims| {
        let c = &claims.custom;
        allowlist.check(c)?;

        let mut attributes = BTreeMap::new();
        let mut put = |key: &str, value: Option<&String>| {
            if let Some(v) = value {
                attributes.insert(key.to_string(), serde_json::Value::String(v.clone()));
            }
        };
        put("project_path", c.project_path.as_ref());
        put("namespace_path", c.namespace_path.as_ref());
        put("ref", c.git_ref.as_ref());
        put("ref_type", c.ref_type.as_ref());
        put("environment", c.environment.as_ref());
        put("pipeline_source", c.pipeline_source.as_ref());
        put("sha", c.sha.as_ref());
        put("user_login", c.user_login.as_ref());
        put("job_id", c.job_id.as_ref());
        put("pipeline_id", c.pipeline_id.as_ref());

        Ok(WorkloadMapping {
            service_name: c.project_id.clone(),
            tenant_slug: c.namespace_id.clone(),
            attributes,
        })
    }
}
