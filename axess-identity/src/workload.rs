//! Workload principals: services, batch jobs, agents, CI runners.
//!
//! Identified by a SPIFFE-ID URI from day one (`spiffe://<trust-domain>/<path>`),
//! even when resolved from a non-SPIFFE source. The format choice is
//! forward-compatible: when [`Issuer::JwtSvid`](crate::Issuer) and
//! friends land, the on-wire identity string does not change; only
//! the [`crate::Issuer`] variant flips.

use std::collections::BTreeMap;

use crate::{IdentityError, Issuer};

/// The scheme of a SPIFFE ID, with the separator that follows it.
const SCHEME: &str = "spiffe://";

/// SPIFFE-ID-shaped workload identifier.
///
/// Wire format: `spiffe://<trust-domain>/<path>` where the trust domain is
/// the URI authority and the path is a slash-separated sequence of non-empty
/// segments. Validation follows the [SPIFFE-ID spec](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md):
///
/// - scheme must be exactly `spiffe`
/// - no userinfo, no port, no query, no fragment
/// - trust domain matches `[a-z0-9._-]+`, lowercase, max 255 chars (section 2.1)
/// - each path segment is non-empty, is not `.` or `..`, and matches
///   `[A-Za-z0-9._-]+` (section 2.2)
/// - full URI length ≤ 2048 characters
///
/// Constructors:
/// - [`WorkloadId::build`] builds from the three platform components
///   used by `CliResolver` (trust domain, service name, tenant slug).
/// - [`WorkloadId::parse`] validates an arbitrary string. Used when
///   loading from external sources (JWT-SVID `sub` claim, mTLS SAN, etc.).
///
/// Taken apart again by [`WorkloadId::trust_domain`], which every SPIFFE ID
/// has, and [`WorkloadId::components`], for an ID of the platform's shape.
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
    /// URI that does not conform to the SPIFFE-ID spec with
    /// [`IdentityError::InvalidSpiffeId`], whichever part is at fault.
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        if raw.len() > Self::MAX_LEN {
            return Err(IdentityError::InvalidSpiffeId(format!(
                "URI exceeds {} chars",
                Self::MAX_LEN
            )));
        }
        // SPIFFE-ID section 2.4: the scheme is case-insensitive. The ID is
        // kept with it in lower case, so two spellings of one ID are one
        // value. The trust domain is another matter: section 2.1 has it in
        // lower case, and an upper-case letter in it is refused below.
        let after_scheme = raw
            .get(..SCHEME.len())
            .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
            .and_then(|_| raw.get(SCHEME.len()..))
            .ok_or_else(|| {
                IdentityError::InvalidSpiffeId(format!(
                    "missing 'spiffe://' scheme prefix: {}",
                    quoted(raw)
                ))
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
                validate_path_segment(segment, "path segment").map_err(|e| match e {
                    IdentityError::InvalidComponent(msg) => IdentityError::InvalidSpiffeId(msg),
                    other => other,
                })?;
            }
        }
        Ok(Self(format!("{SCHEME}{after_scheme}")))
    }

    /// Borrow the underlying URI as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The URI's authority, and the path after it without the slash
    /// between them. Both constructors validated the URI, so the scheme is
    /// there and the authority is a trust domain.
    fn authority_and_path(&self) -> (&str, &str) {
        let after_scheme = self.0.strip_prefix(SCHEME).unwrap_or(&self.0);
        after_scheme.split_once('/').unwrap_or((after_scheme, ""))
    }

    /// The trust domain the ID belongs to: the authority of its URI.
    pub fn trust_domain(&self) -> TrustDomain {
        TrustDomain(self.authority_and_path().0.to_owned())
    }

    /// The ID taken apart into the three platform components
    /// [`build`](Self::build) puts together: the trust domain, the service
    /// name and the tenant slug.
    ///
    /// The platform's shape is `spiffe://<trust_domain>/<service>/<tenant_slug>`.
    /// An ID of any other shape (no path, one segment, more than two) is a
    /// valid SPIFFE ID and not one of the platform's, and is refused with
    /// [`IdentityError::InvalidSpiffeId`]. Every resolver that reads a
    /// service and a tenant out of a SPIFFE ID reads them here.
    ///
    /// ```
    /// use axess_identity::{TrustDomain, WorkloadId};
    ///
    /// let trust_domain = TrustDomain::new("prod.example.com")?;
    /// let id = WorkloadId::build(&trust_domain, "billing-api", "acme")?;
    /// let parts = id.components()?;
    /// assert_eq!(parts.trust_domain, trust_domain);
    /// assert_eq!((parts.service, parts.tenant_slug), ("billing-api", "acme"));
    ///
    /// let other = WorkloadId::parse("spiffe://prod.example.com/ns/payments/sa/api")?;
    /// assert!(other.components().is_err());
    /// # Ok::<(), axess_identity::IdentityError>(())
    /// ```
    pub fn components(&self) -> Result<WorkloadIdComponents<'_>, IdentityError> {
        let (_, path) = self.authority_and_path();
        let mut segments = path.split('/');
        match (segments.next(), segments.next(), segments.next()) {
            (Some(service), Some(tenant_slug), None)
                if !service.is_empty() && !tenant_slug.is_empty() =>
            {
                Ok(WorkloadIdComponents {
                    trust_domain: self.trust_domain(),
                    service,
                    tenant_slug,
                })
            }
            // The identifier is the presenter's text, up to `MAX_LEN` bytes
            // of it: the refusal quotes it cut.
            _ => Err(IdentityError::InvalidSpiffeId(format!(
                "SPIFFE path is not <service>/<tenant_slug>: {}",
                quoted(self.as_str())
            ))),
        }
    }
}

/// A SPIFFE ID of the platform's shape, taken apart: what
/// [`WorkloadId::components`] returns, and what [`WorkloadId::build`] takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadIdComponents<'a> {
    /// The trust domain: the URI's authority.
    pub trust_domain: TrustDomain,
    /// The service name: the first segment of the path.
    pub service: &'a str,
    /// The tenant slug: the second segment of the path.
    pub tenant_slug: &'a str,
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
/// Per section 2.1 of the SPIFFE-ID standard: not empty, at most 255
/// characters, and only lowercase letters, digits, dots, dashes and
/// underscores. A trust domain name is not a DNS name: one that starts with
/// a dash or holds an underscore is as valid as one that could be a host
/// name, and the standard forbids treating the two differently.
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
        for c in raw.chars() {
            let valid =
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_');
            if !valid {
                return Err(IdentityError::InvalidTrustDomain(format!(
                    "invalid character '{}' in trust domain '{}' (expected [a-z0-9._-])",
                    quoted(c.encode_utf8(&mut [0; 4])),
                    quoted(raw)
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
/// scope, and arbitrary attributes (empty from `CliResolver` and the
/// SPIFFE resolvers, JWT-SVID, mTLS and the SPIRE agent's; filled from the
/// token's claims by the federation `WorkloadResolver`'s claim mapper).
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
    /// `CliResolver` and the SPIFFE resolvers; the federation
    /// `WorkloadResolver` fills them from the claim mapper's
    /// `WorkloadMapping`.
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
    // SPIFFE-ID section 2.2: letters, numbers, dots, dashes and underscores.
    for c in segment.chars() {
        let valid = c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_');
        if !valid {
            return Err(IdentityError::InvalidComponent(format!(
                "invalid character '{}' in {role} '{}' (expected [A-Za-z0-9._-])",
                quoted(c.encode_utf8(&mut [0; 4])),
                quoted(segment)
            )));
        }
    }
    Ok(())
}

/// The most bytes of a refused value an error quotes.
const QUOTED_BYTES: usize = 64;

/// A refused value as an error quotes it. The value is whatever the caller
/// was handed (a token's `sub`, a certificate's URI name), and the error is
/// logged: it is made safe by the one predicate of the workspace
/// ([`log_safe`](crate::log_text::log_safe)), so every character
/// [`escapes`](crate::log_text::escapes) names is written as an escape and
/// the text is cut to [`QUOTED_BYTES`] bytes with `...` marking the cut. A
/// refused value can neither forge a log line, make one read otherwise
/// than it is, nor fill one.
fn quoted(text: &str) -> String {
    crate::log_text::log_safe(text, QUOTED_BYTES)
}

#[cfg(test)]
mod tests;
