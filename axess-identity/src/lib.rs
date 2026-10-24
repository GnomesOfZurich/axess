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
#[cfg_attr(feature = "serde", serde(into = "IssuerRepr", try_from = "IssuerRepr"))]
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
        if matches!(s, "cli" | "jwt_svid" | "mtls" | "oauth") {
            return Err(IdentityError::InvalidComponent(format!(
                "Issuer::custom label {s:?} is reserved for a built-in issuer"
            )));
        }
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

/// Serde wire shape of [`Issuer`]: internally tagged by `kind`, with the
/// custom label carried in a `label` field. (A tagged newtype over a bare
/// string cannot be serialized, so the public enum maps through this.)
/// Deserializing a custom issuer re-runs [`Issuer::custom`], so a stored
/// or wire value cannot carry a label the constructor would refuse.
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum IssuerRepr {
    Cli,
    JwtSvid,
    Mtls,
    #[serde(rename = "oauth")]
    OAuth,
    Custom {
        label: String,
    },
}

#[cfg(feature = "serde")]
impl From<Issuer> for IssuerRepr {
    fn from(issuer: Issuer) -> Self {
        match issuer {
            Issuer::Cli => Self::Cli,
            Issuer::JwtSvid => Self::JwtSvid,
            Issuer::Mtls => Self::Mtls,
            Issuer::OAuth => Self::OAuth,
            Issuer::Custom(label) => Self::Custom { label },
        }
    }
}

#[cfg(feature = "serde")]
impl TryFrom<IssuerRepr> for Issuer {
    type Error = IdentityError;

    fn try_from(repr: IssuerRepr) -> Result<Self, Self::Error> {
        Ok(match repr {
            IssuerRepr::Cli => Self::Cli,
            IssuerRepr::JwtSvid => Self::JwtSvid,
            IssuerRepr::Mtls => Self::Mtls,
            IssuerRepr::OAuth => Self::OAuth,
            IssuerRepr::Custom { label } => Self::custom(label)?,
        })
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
mod tests;
