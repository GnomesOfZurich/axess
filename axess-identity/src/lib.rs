//! Identity primitives for the axess workspace.
//!
//! Two layers in one crate:
//!
//! 1. **Typed identifiers** ([`id`] module, re-exported at the crate
//!    root): [`TenantId`], [`UserId`], [`DeviceId`], [`SessionId`],
//!    [`EventId`]: all `FooId(Uuid)` newtypes (16 bytes, `Copy`)
//!    minted via the [`define_id!`] macro. Adopters can declare their
//!    own domain ids (`AccountId`, `OrderId`, …) with the same shape.
//! 2. **Principal abstraction**: [`Principal`] unifies human and
//!    workload identity under one type so authorization policies, audit
//!    trails, and downstream consumers treat both kinds symmetrically.
//!    [`HumanPrincipal`] (a user behind an authenticated session) and
//!    [`WorkloadPrincipal`] (a service, batch job, agent, CI runner,
//!    anything that authenticates without an interactive session) both
//!    carry [`TenantId`] so the multi-tenant rail cuts through every
//!    consumer uniformly.
//!
//! # Workload identity model
//!
//! Workload identifiers follow the [SPIFFE-ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
//! URI shape from day one (`spiffe://<trust-domain>/<path>`), even when
//! resolved from a non-SPIFFE source ([`Issuer::Cli`] today; JWT-SVID,
//! mTLS, and SPIRE land later). Using the SPIFFE format up front means
//! the on-wire identity string does not change when those resolution
//! modes light up; only the [`Issuer`] variant flips.
//!
//! # Layering
//!
//! Foundation crate, deliberately small: depends only on `axess-rng`
//! (for the DST-injectable `SecureRng` trait), `uuid`, and `thiserror`.
//! No tokio, no axum, no Cedar. axess-core layers two more pieces on
//! top:
//! - `SessionResolver`: extracts a [`HumanPrincipal`] from an
//!   authenticated `AuthSession` (depends on axess-core's session
//!   state machine).
//! - `ToCedarEntity` trait: emits `cedar_policy::Entity` values for
//!   adopters using axess Cedar authorization (depends on cedar-policy).
//!
//! Downstream consumers that only need the principal *data* (event
//! envelope stamping, log spans, audit attribution) pull in
//! `axess-identity` directly and skip the heavier axess-core dep.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::collections::BTreeMap;

pub mod human;
pub mod id;
pub mod resolver;
#[cfg(any(test, feature = "testing"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;
pub mod workload;

pub use human::HumanPrincipal;
pub use id::*;
pub use resolver::{CliResolver, CliResolverBuilder, PrincipalResolver};
pub use workload::{TrustDomain, WorkloadId, WorkloadPrincipal};

/// An authenticated principal: either a human user or a workload.
///
/// Constructed by a [`PrincipalResolver`] impl once authentication has
/// succeeded; consumers downstream (authorization, audit, event
/// stamping) treat both kinds symmetrically via the shared accessors.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
    /// A human user behind an authenticated session.
    Human(HumanPrincipal),
    /// A workload: service, batch job, agent, CI runner, etc.
    Workload(WorkloadPrincipal),
}

impl Principal {
    /// The tenant this principal belongs to. Both human and workload
    /// principals are tenant-scoped; cross-tenant operations require
    /// a separate principal per tenant.
    pub fn tenant_id(&self) -> &TenantId {
        match self {
            Self::Human(h) => &h.tenant_id,
            Self::Workload(w) => &w.tenant_id,
        }
    }

    /// Arbitrary key-value attributes attached to the principal.
    /// Empty for baseline principals; populated from JWT claims or
    /// other resolver-specific metadata once federated resolvers
    /// land.
    pub fn attributes(&self) -> &BTreeMap<String, serde_json::Value> {
        match self {
            Self::Human(h) => &h.attributes,
            Self::Workload(w) => &w.attributes,
        }
    }
}

/// How a principal's identity was vouched for at resolution time.
///
/// The SPIRE variant lands when a concrete adopter use case arrives;
/// it is deliberately not yet present so the enum doesn't carry a
/// constructor that no resolver impl ever produces.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issuer {
    /// Identity supplied via CLI args or environment variables.
    /// Trust comes from the operator who started the process.
    Cli,
    /// Identity verified from a SPIFFE JWT-SVID. Trust comes from the
    /// SPIFFE-aware IdP whose JWKS signed the token; the resolver
    /// pinned the trust domain at construction.
    JwtSvid,
    /// Identity verified from a SPIFFE X509-SVID presented over mTLS.
    /// Trust comes from the rustls peer-cert chain validation already
    /// performed by the TLS terminator; the resolver pinned the trust
    /// domain at construction and extracts the SPIFFE-ID from the leaf
    /// certificate's `SAN URI` field.
    Mtls,
    /// Identity verified from a bearer JWT via the generic
    /// [`WorkloadResolver`](https://docs.rs/axess-factors/latest/axess_factors/federation/struct.WorkloadResolver.html).
    /// The adopter-supplied claim-mapping closure decides how the
    /// verified JWT claims map onto the SPIFFE-shape `WorkloadId` +
    /// tenant slug. Covers Kubernetes service accounts, GitHub Actions
    /// OIDC, GitLab CI OIDC, Okta, Azure AD, Auth0, axess's
    /// `LocalIdP`, and any other JWT-issuing IdP; adopters write a
    /// small claim parser + mapper per issuer they care about.
    OAuth,
    /// Adopter-labelled issuer for cases where the generic [`OAuth`]
    /// variant's wire-string (`"oauth"`) is not specific enough for
    /// audit logs or Cedar policies. Construct via [`Issuer::custom`]
    /// which validates the label format (`[a-z0-9_]{1,32}`).
    ///
    /// [`OAuth`]: Self::OAuth
    Custom(String),
}

impl Issuer {
    /// Build an [`Issuer::Custom`] with a validated label.
    ///
    /// Labels must match `[a-z0-9_]{1,32}` so that wire-strings
    /// (audit events, Cedar attribute values, SIEM grep patterns)
    /// stay short, stable, and grep-safe across issuers.
    /// Pre-defined examples: `"github_actions"`, `"kubernetes"`,
    /// `"gitlab_ci"`, `"circleci"`, `"buildkite"`, `"local_idp"`.
    pub fn custom(label: impl AsRef<str>) -> Result<Self, IdentityError> {
        let s = label.as_ref();
        if s.is_empty() || s.len() > 32 {
            return Err(IdentityError::InvalidComponent(format!(
                "Issuer::custom label length must be 1..=32, got {}",
                s.len()
            )));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(IdentityError::InvalidComponent(format!(
                "Issuer::custom label must match [a-z0-9_], got {s:?}"
            )));
        }
        Ok(Self::Custom(s.to_string()))
    }

    /// Stable lowercase wire-string for this variant. Use as the
    /// Cedar attribute value and any other on-wire serialization.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Cli => "cli",
            Self::JwtSvid => "jwt_svid",
            Self::Mtls => "mtls",
            Self::OAuth => "oauth",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// Errors from principal construction and identity parsing.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// A SPIFFE-ID URI failed validation.
    #[error("invalid SPIFFE identifier: {0}")]
    InvalidSpiffeId(String),

    /// A trust domain string failed validation per the SPIFFE spec.
    #[error("invalid trust domain: {0}")]
    InvalidTrustDomain(String),

    /// An empty or malformed input where one of the WorkloadId
    /// components (service name, tenant slug) was required.
    #[error("invalid workload identifier component: {0}")]
    InvalidComponent(String),

    /// A resolver was asked to produce a principal from a context
    /// where no authenticated identity is available (e.g. a Guest
    /// session, or a worker before identity bootstrap).
    #[error("no authenticated identity available")]
    NotAuthenticated,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tenant() -> TenantId {
        TenantId::from_bytes([1u8; 16])
    }

    fn sample_user() -> UserId {
        UserId::from_bytes([2u8; 16])
    }

    #[test]
    fn human_principal_tenant_id_accessor() {
        let tenant = sample_tenant();
        let human = HumanPrincipal {
            user_id: sample_user(),
            tenant_id: tenant,
            session_id: None,
            attributes: BTreeMap::new(),
        };
        let p = Principal::Human(human);
        assert_eq!(p.tenant_id(), &tenant);
    }

    #[test]
    fn workload_principal_tenant_id_accessor() {
        let tenant = sample_tenant();
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let wid = WorkloadId::build(&trust, "compute-worker", "ekekrantz").unwrap();
        let workload = WorkloadPrincipal {
            workload_id: wid,
            trust_domain: trust,
            issuer: Issuer::Cli,
            tenant_id: tenant,
            tenant_slug: "ekekrantz".to_string(),
            service_name: "compute-worker".to_string(),
            attributes: BTreeMap::new(),
        };
        let p = Principal::Workload(workload);
        assert_eq!(p.tenant_id(), &tenant);
    }

    #[test]
    fn attributes_accessor_returns_empty_by_default() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let wid = WorkloadId::build(&trust, "feed-worker", "ekekrantz").unwrap();
        let workload = WorkloadPrincipal {
            workload_id: wid,
            trust_domain: trust,
            issuer: Issuer::Cli,
            tenant_id: sample_tenant(),
            tenant_slug: "ekekrantz".to_string(),
            service_name: "feed-worker".to_string(),
            attributes: BTreeMap::new(),
        };
        let p = Principal::Workload(workload);
        assert!(p.attributes().is_empty());
    }

    /// `attributes()` returns the LIVE attribute map, not a fresh
    /// empty one. The mutation `-> Box::leak(Box::new(BTreeMap::new()))`
    /// would hide any populated attributes.
    #[test]
    fn attributes_accessor_returns_populated_human_map() {
        let mut attrs = BTreeMap::new();
        attrs.insert("amr".to_string(), serde_json::json!(["pwd", "mfa"]));
        let human = HumanPrincipal {
            user_id: sample_user(),
            tenant_id: sample_tenant(),
            session_id: None,
            attributes: attrs,
        };
        let p = Principal::Human(human);
        let seen = p.attributes();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen.get("amr"), Some(&serde_json::json!(["pwd", "mfa"])));
    }

    #[test]
    fn attributes_accessor_returns_populated_workload_map() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let wid = WorkloadId::build(&trust, "feed-worker", "ekekrantz").unwrap();
        let mut attrs = BTreeMap::new();
        attrs.insert("region".to_string(), serde_json::json!("eu-west-1"));
        let workload = WorkloadPrincipal {
            workload_id: wid,
            trust_domain: trust,
            issuer: Issuer::Cli,
            tenant_id: sample_tenant(),
            tenant_slug: "ekekrantz".to_string(),
            service_name: "feed-worker".to_string(),
            attributes: attrs,
        };
        let p = Principal::Workload(workload);
        assert_eq!(
            p.attributes().get("region"),
            Some(&serde_json::json!("eu-west-1"))
        );
    }

    #[test]
    fn issuer_as_str_is_stable_lowercase() {
        assert_eq!(Issuer::Cli.as_str(), "cli");
        assert_eq!(Issuer::JwtSvid.as_str(), "jwt_svid");
        assert_eq!(Issuer::Mtls.as_str(), "mtls");
        assert_eq!(Issuer::OAuth.as_str(), "oauth");
        assert_eq!(
            Issuer::custom("github_actions").unwrap().as_str(),
            "github_actions"
        );
    }

    #[test]
    fn issuer_custom_validation_rejects_bad_labels() {
        // Empty: rejected.
        assert!(Issuer::custom("").is_err());
        // Too long (>32): rejected.
        assert!(Issuer::custom("a".repeat(33)).is_err());
        // Uppercase: rejected.
        assert!(Issuer::custom("GitHubActions").is_err());
        // Dashes / dots / spaces: rejected.
        assert!(Issuer::custom("github-actions").is_err());
        assert!(Issuer::custom("github.actions").is_err());
        assert!(Issuer::custom("github actions").is_err());
        // Accepted shapes.
        assert!(Issuer::custom("k8s").is_ok());
        assert!(Issuer::custom("github_actions").is_ok());
        assert!(Issuer::custom("circleci_2_1").is_ok());
    }

    #[test]
    fn issuer_custom_accepts_exactly_32_chars() {
        let label = "a".repeat(32);
        assert!(
            Issuer::custom(&label).is_ok(),
            "32-char label must be accepted (kills `> -> >=` boundary mutation)"
        );
        let too_long = "a".repeat(33);
        assert!(
            Issuer::custom(&too_long).is_err(),
            "33-char label must be rejected"
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn principal_serde_round_trip_human() {
        let human = HumanPrincipal {
            user_id: sample_user(),
            tenant_id: sample_tenant(),
            session_id: None,
            attributes: BTreeMap::new(),
        };
        let p = Principal::Human(human);
        let json = serde_json::to_string(&p).unwrap();
        let back: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn principal_serde_round_trip_workload() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let wid = WorkloadId::build(&trust, "market-worker", "world_cup").unwrap();
        let workload = WorkloadPrincipal {
            workload_id: wid,
            trust_domain: trust,
            issuer: Issuer::Cli,
            tenant_id: sample_tenant(),
            tenant_slug: "world_cup".to_string(),
            service_name: "market-worker".to_string(),
            attributes: BTreeMap::new(),
        };
        let p = Principal::Workload(workload);
        let json = serde_json::to_string(&p).unwrap();
        let back: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
