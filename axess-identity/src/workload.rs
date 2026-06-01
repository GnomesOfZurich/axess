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
#[cfg_attr(feature = "serde", serde(transparent))]
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
#[cfg_attr(feature = "serde", serde(transparent))]
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
mod tests {
    use super::*;

    #[test]
    fn trust_domain_accepts_valid_forms() {
        assert!(TrustDomain::new("gnomes.local").is_ok());
        assert!(TrustDomain::new("gnomes.internal").is_ok());
        assert!(TrustDomain::new("example.com").is_ok());
        assert!(TrustDomain::new("a").is_ok());
        assert!(TrustDomain::new("prod-1.example.com").is_ok());
    }

    #[test]
    fn trust_domain_rejects_invalid_forms() {
        assert!(TrustDomain::new("").is_err());
        assert!(TrustDomain::new("UPPER.case").is_err());
        assert!(TrustDomain::new("-leading-hyphen").is_err());
        assert!(TrustDomain::new("has spaces").is_err());
        assert!(TrustDomain::new("has/slash").is_err());
        assert!(TrustDomain::new("has:port").is_err());
        let too_long = "a".repeat(TrustDomain::MAX_LEN + 1);
        assert!(TrustDomain::new(&too_long).is_err());
    }

    #[test]
    fn workload_id_build_round_trips_through_parse() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let wid = WorkloadId::build(&trust, "compute-worker", "ekekrantz").unwrap();
        assert_eq!(
            wid.as_str(),
            "spiffe://gnomes.local/compute-worker/ekekrantz"
        );
        let reparsed = WorkloadId::parse(wid.as_str()).unwrap();
        assert_eq!(wid, reparsed);
    }

    #[test]
    fn workload_id_build_rejects_empty_service() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        assert!(WorkloadId::build(&trust, "", "ekekrantz").is_err());
    }

    #[test]
    fn workload_id_build_rejects_empty_tenant_slug() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        assert!(WorkloadId::build(&trust, "compute-worker", "").is_err());
    }

    #[test]
    fn workload_id_build_rejects_invalid_chars_in_segment() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        assert!(WorkloadId::build(&trust, "compute worker", "ekekrantz").is_err());
        assert!(WorkloadId::build(&trust, "compute-worker", "eke/krantz").is_err());
        assert!(WorkloadId::build(&trust, "compute-worker", "eke?krantz").is_err());
    }

    #[test]
    fn workload_id_parse_accepts_canonical_spiffe_uri() {
        let raw = "spiffe://gnomes.local/compute-worker/ekekrantz";
        let parsed = WorkloadId::parse(raw).unwrap();
        assert_eq!(parsed.as_str(), raw);
    }

    #[test]
    fn workload_id_parse_accepts_trust_domain_only() {
        let parsed = WorkloadId::parse("spiffe://gnomes.local").unwrap();
        assert_eq!(parsed.as_str(), "spiffe://gnomes.local");
    }

    #[test]
    fn workload_id_parse_rejects_non_spiffe_scheme() {
        assert!(WorkloadId::parse("https://gnomes.local/x/y").is_err());
        assert!(WorkloadId::parse("http://gnomes.local/x/y").is_err());
        assert!(WorkloadId::parse("/gnomes.local/x/y").is_err());
    }

    #[test]
    fn workload_id_parse_rejects_userinfo() {
        assert!(WorkloadId::parse("spiffe://user@gnomes.local/x").is_err());
    }

    #[test]
    fn workload_id_parse_rejects_port() {
        assert!(WorkloadId::parse("spiffe://gnomes.local:8443/x").is_err());
    }

    #[test]
    fn workload_id_parse_rejects_query_and_fragment() {
        assert!(WorkloadId::parse("spiffe://gnomes.local/x?y=1").is_err());
        assert!(WorkloadId::parse("spiffe://gnomes.local/x#frag").is_err());
    }

    #[test]
    fn workload_id_parse_rejects_empty_segment() {
        assert!(WorkloadId::parse("spiffe://gnomes.local//x").is_err());
        assert!(WorkloadId::parse("spiffe://gnomes.local/x//y").is_err());
    }

    #[test]
    fn workload_id_parse_rejects_over_length_uri() {
        let trust = "gnomes.local";
        let path: String = std::iter::repeat_n('a', WorkloadId::MAX_LEN).collect();
        let raw = format!("spiffe://{trust}/{path}");
        assert!(WorkloadId::parse(&raw).is_err());
    }

    #[test]
    fn workload_id_parse_rejects_uppercase_trust_domain() {
        assert!(WorkloadId::parse("spiffe://Gnomes.Local/x").is_err());
    }

    #[test]
    fn workload_id_display_matches_as_str() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let wid = WorkloadId::build(&trust, "feed-worker", "ekekrantz").unwrap();
        assert_eq!(format!("{wid}"), wid.as_str());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn workload_id_serializes_as_transparent_string() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let wid = WorkloadId::build(&trust, "compute-worker", "ekekrantz").unwrap();
        let json = serde_json::to_string(&wid).unwrap();
        assert_eq!(json, "\"spiffe://gnomes.local/compute-worker/ekekrantz\"");
        let back: WorkloadId = serde_json::from_str(&json).unwrap();
        assert_eq!(wid, back);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn trust_domain_serializes_as_transparent_string() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let json = serde_json::to_string(&trust).unwrap();
        assert_eq!(json, "\"gnomes.local\"");
        let back: TrustDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(trust, back);
    }

    /// `parse` rejects only when `?` OR `#` is present. Test the
    /// `?`-only path explicitly so the `|| → &&` mutation can be
    /// observed: with `&&`, a URI containing only `?` would slip past
    /// the early reject and (potentially) succeed via downstream
    /// segment validation.
    #[test]
    fn workload_id_parse_rejects_question_mark_without_hash() {
        let result = WorkloadId::parse("spiffe://gnomes.local/x?y");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        // The early-reject branch yields a specific message; if the
        // mutation fell through to segment validation, the rejection
        // message would mention the segment instead.
        assert!(
            msg.contains("query and fragment"),
            "must reject at the early `?/#` guard, got: {msg}"
        );
    }

    /// `TrustDomain::Display` writes the trust-domain string. Mutation
    /// `-> Ok(())` would yield an empty format output.
    #[test]
    fn trust_domain_display_matches_as_str() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        assert_eq!(format!("{trust}"), "gnomes.local");
    }

    /// `WorkloadId::build` rejects URIs ABOVE `MAX_LEN` with strict
    /// `>`. At exactly `MAX_LEN` bytes the result must succeed.
    /// Mutations `==` and `>=` would reject at the boundary.
    #[test]
    fn workload_id_build_accepts_uri_at_exact_max_len() {
        let trust = TrustDomain::new("a").unwrap();
        // Build a URI exactly at MAX_LEN: "spiffe://a/svc/" = 15 chars,
        // then pad tenant_slug to (MAX_LEN - 15) chars.
        let prefix_len = "spiffe://a/svc/".len();
        let pad = WorkloadId::MAX_LEN - prefix_len;
        let tenant = "a".repeat(pad);
        let result = WorkloadId::build(&trust, "svc", &tenant);
        assert!(
            result.is_ok(),
            "URI of EXACTLY MAX_LEN must build successfully"
        );
        assert_eq!(result.unwrap().as_str().len(), WorkloadId::MAX_LEN);
    }

    /// `WorkloadId::parse` rejects URIs ABOVE `MAX_LEN`. At exactly
    /// `MAX_LEN` bytes the parse must succeed. Mutation `>=` would
    /// reject at the boundary.
    #[test]
    fn workload_id_parse_accepts_uri_at_exact_max_len() {
        let prefix_len = "spiffe://a/svc/".len();
        let pad = WorkloadId::MAX_LEN - prefix_len;
        let raw = format!("spiffe://a/svc/{}", "a".repeat(pad));
        assert_eq!(raw.len(), WorkloadId::MAX_LEN);
        let result = WorkloadId::parse(&raw);
        assert!(
            result.is_ok(),
            "URI of EXACTLY MAX_LEN must parse successfully"
        );
    }
}
