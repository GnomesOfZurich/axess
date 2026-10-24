//! Workload principals: services, batch jobs, agents, CI runners.
//!
//! Identified by a SPIFFE-ID URI from day one (`spiffe://<trust-domain>/<path>`),
//! even when resolved from a non-SPIFFE source. The format choice is
//! forward-compatible: when [`Issuer::JwtSvid`](crate::Issuer) and
//! friends land, the on-wire identity string does not change; only
//! the [`crate::Issuer`] variant flips.

use std::collections::BTreeMap;

use crate::{IdentityError, Issuer};

/// SPIFFE-ID-shaped workload identifier.
///
/// Wire format: `spiffe://<trust-domain>/<path>` where the trust domain is
/// the URI authority and the path is a slash-separated sequence of non-empty
/// segments. Validation follows the [SPIFFE-ID spec](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md):
///
/// - scheme must be exactly `spiffe`
/// - no userinfo, no port, no query, no fragment
/// - trust domain matches `[a-z0-9][a-z0-9.-]*`, lowercase, max 255 chars
/// - each path segment is non-empty and matches `[A-Za-z0-9._~-]+`
/// - full URI length ≤ 2048 characters
///
/// Constructors:
/// - [`WorkloadId::build`] builds from the three platform components
///   used by `CliResolver` (trust domain, service name, tenant slug).
/// - [`WorkloadId::parse`] validates an arbitrary string. Used when
///   loading from external sources (JWT-SVID `sub` claim, mTLS SAN, etc.).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorkloadId(String);

impl WorkloadId {
    /// Maximum URI length per the SPIFFE-ID spec.
    pub const MAX_LEN: usize = 2048;

    /// Build a SPIFFE-ID URI from the platform identity components.
    ///
    /// Format: `spiffe://<trust_domain>/<service>/<tenant_slug>`.
    /// Validates `service` and `tenant_slug` as SPIFFE path segments;
    /// the trust domain is already validated by [`TrustDomain::new`].
    pub fn build(
        trust_domain: &TrustDomain,
        service: &str,
        tenant_slug: &str,
    ) -> Result<Self, IdentityError> {
        validate_path_segment(service, "service")?;
        validate_path_segment(tenant_slug, "tenant_slug")?;
        let raw = format!(
            "spiffe://{}/{}/{}",
            trust_domain.as_str(),
            service,
            tenant_slug
        );
        if raw.len() > Self::MAX_LEN {
            return Err(IdentityError::InvalidSpiffeId(format!(
                "URI exceeds {} chars",
                Self::MAX_LEN
            )));
        }
        Ok(Self(raw))
    }

    /// Validate and adopt an arbitrary SPIFFE-ID string. Rejects any
    /// URI that does not conform to the SPIFFE-ID spec.
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        if raw.len() > Self::MAX_LEN {
            return Err(IdentityError::InvalidSpiffeId(format!(
                "URI exceeds {} chars",
                Self::MAX_LEN
            )));
        }
        let after_scheme = raw.strip_prefix("spiffe://").ok_or_else(|| {
            IdentityError::InvalidSpiffeId(format!("missing 'spiffe://' scheme prefix: {raw}"))
        })?;
        if after_scheme.contains('?') || after_scheme.contains('#') {
            return Err(IdentityError::InvalidSpiffeId(
                "query and fragment components not permitted".to_string(),
            ));
        }
        let path_start = after_scheme.find('/').unwrap_or(after_scheme.len());
        let authority = &after_scheme[..path_start];
        if authority.contains('@') {
            return Err(IdentityError::InvalidSpiffeId(
                "userinfo component not permitted".to_string(),
            ));
        }
        if authority.contains(':') {
            return Err(IdentityError::InvalidSpiffeId(
                "port component not permitted".to_string(),
            ));
        }
        TrustDomain::new(authority).map_err(|e| match e {
            IdentityError::InvalidTrustDomain(msg) => {
                IdentityError::InvalidSpiffeId(format!("invalid trust domain: {msg}"))
            }
            other => other,
        })?;
        if path_start < after_scheme.len() {
            let path = &after_scheme[path_start..];
            if !path.starts_with('/') {
                return Err(IdentityError::InvalidSpiffeId(
                    "path must start with '/'".to_string(),
                ));
            }
            for segment in path[1..].split('/') {
                validate_path_segment(segment, "path segment")?;
            }
        }
        Ok(Self(raw.to_string()))
    }

    /// Borrow the underlying URI as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for WorkloadId {
    type Error = IdentityError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

impl From<WorkloadId> for String {
    fn from(id: WorkloadId) -> Self {
        id.0
    }
}

impl std::fmt::Display for WorkloadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// SPIFFE trust domain: the authority component of a SPIFFE-ID URI.
///
/// Per the spec: non-empty, lowercase ASCII, alphanumeric / hyphen / dot,
/// must start with an alphanumeric, max 255 characters.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TrustDomain(String);

impl TrustDomain {
    /// Maximum trust-domain length per the SPIFFE-ID spec.
    pub const MAX_LEN: usize = 255;

    /// Construct after validating that `raw` is a syntactically valid
    /// SPIFFE trust domain.
    pub fn new(raw: &str) -> Result<Self, IdentityError> {
        if raw.is_empty() {
            return Err(IdentityError::InvalidTrustDomain(
                "trust domain must not be empty".to_string(),
            ));
        }
        if raw.len() > Self::MAX_LEN {
            return Err(IdentityError::InvalidTrustDomain(format!(
                "trust domain exceeds {} chars",
                Self::MAX_LEN
            )));
        }
        let mut chars = raw.chars();
        let first = chars.next().expect("non-empty checked above");
        if !first.is_ascii_alphanumeric() {
            return Err(IdentityError::InvalidTrustDomain(format!(
                "must start with an alphanumeric: {raw}"
            )));
        }
        for c in std::iter::once(first).chain(chars) {
            let valid = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.';
            if !valid {
                return Err(IdentityError::InvalidTrustDomain(format!(
                    "invalid character '{c}' in trust domain '{raw}' (expected [a-z0-9.-])"
                )));
            }
        }
        Ok(Self(raw.to_string()))
    }

    /// Borrow the trust domain as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TrustDomain {
    type Error = IdentityError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::new(&raw)
    }
}

impl From<TrustDomain> for String {
    fn from(domain: TrustDomain) -> Self {
        domain.0
    }
}

impl std::fmt::Display for TrustDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A workload principal: a service, batch job, agent, or other
/// non-human compute identity. Carries the SPIFFE-shaped workload id,
/// its trust domain, the issuer that vouched for it, the tenant
/// scope, and arbitrary attributes (empty today; populated from JWT
/// claims when JWT-SVID resolution lands).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadPrincipal {
    /// SPIFFE-shaped workload identifier.
    pub workload_id: WorkloadId,
    /// Trust domain the workload belongs to. Redundant with the
    /// authority component of [`workload_id`](Self::workload_id) but
    /// surfaced explicitly for ergonomic policy access.
    pub trust_domain: TrustDomain,
    /// How the workload's identity was vouched for at resolution time.
    pub issuer: Issuer,
    /// Tenant the workload is scoped to.
    pub tenant_id: crate::TenantId,
    /// Human-readable tenant slug (matches `tenants.name` in the
    /// adopter's storage). Carried alongside the typed
    /// [`tenant_id`](Self::tenant_id) for log lines and admin UIs that
    /// need the readable form without a registry lookup.
    pub tenant_slug: String,
    /// Service identifier: `"compute-worker"`, `"feed-worker"`, etc.
    pub service_name: String,
    /// Arbitrary key-value attributes from the resolver. Empty for
    /// `CliResolver`; populated from JWT claims by future federation
    /// resolvers.
    pub attributes: BTreeMap<String, serde_json::Value>,
}

fn validate_path_segment(segment: &str, role: &str) -> Result<(), IdentityError> {
    if segment.is_empty() {
        return Err(IdentityError::InvalidComponent(format!(
            "{role} must not be empty"
        )));
    }
    // SPIFFE-ID spec: "." and ".." segments are not permitted, so a
    // path can never be read as a traversal by a consumer that
    // normalizes it.
    if segment == "." || segment == ".." {
        return Err(IdentityError::InvalidComponent(format!(
            "{role} must not be '.' or '..'"
        )));
    }
    for c in segment.chars() {
        let valid = c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '~' || c == '-';
        if !valid {
            return Err(IdentityError::InvalidComponent(format!(
                "invalid character '{c}' in {role} '{segment}' (expected [A-Za-z0-9._~-])"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
