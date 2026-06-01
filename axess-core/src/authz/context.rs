//! Request context for Cedar ABAC policies.
//!
//! Cedar's `Context` field carries request-level facts that policies can
//! inspect: IP address, MFA verification status, session age, time of day.
//! Without this, Cedar can only reason about principals and resources, so ABAC
//! conditions are impossible.
//!
//! # Usage
//!
//! Use [`StandardRequestContext`] for most applications:
//!
//! ```rust,ignore
//! use axess_core::authz::context::StandardRequestContext;
//!
//! // Default: emits `mfa_verified` (+ `ip_address` if Some) only.
//! let ctx = StandardRequestContext::new(
//!     session.is_mfa_complete(),
//!     Some("192.168.1.1".parse().unwrap()),
//! );
//!
//! // Opt-in timestamp from an injectable Clock (DST-friendly). Only
//! // emitted when explicitly provided; Cedar schema must then declare
//! // `timestamp` as well.
//! let ctx = StandardRequestContext::at(
//!     session.is_mfa_complete(),
//!     ip_from_headers(request.headers()),
//!     clock.now(),
//! );
//!
//! let authz = state.authz.for_user_id_with_context(&user_id, ctx)?;
//! authz.require("PostJournalEntry", &ledger_id).await?;
//! ```
//!
//! For applications that do not need ABAC context, use [`NoContext`]; it
//! produces an empty Cedar `Context` with zero overhead.
//!
//! # Cedar schema requirements
//!
//! Whatever attributes `StandardRequestContext` actually emits for a
//! given request must appear in the matching Cedar action's context
//! declaration; Cedar's schema validation rejects requests carrying
//! attributes the schema does not list. Minimum (always-emitted):
//!
//! ```json
//! "context": {
//!     "type": "Record",
//!     "attributes": {
//!         "mfa_verified": { "type": "Boolean" }
//!     }
//! }
//! ```
//!
//! Add `"ip_address": { "type": "String", "required": false }` if you
//! ever pass `Some(ip)` to `new` / `at`; add `"timestamp": { "type":
//! "String", "required": false }` if you call `at(..)` with an explicit
//! timestamp.

use cedar_policy::{Context, RestrictedExpression};
use chrono::{DateTime, Utc};

use super::error::AuthzError;

// ── BuildRequestContext ───────────────────────────────────────────────────────

/// Converts request-level data into a Cedar [`Context`] for ABAC evaluation.
///
/// Implement this trait to provide custom context attributes beyond what
/// [`StandardRequestContext`] offers (e.g. geographic region, subscription
/// tier, feature flags).
pub trait BuildRequestContext: Send + Sync {
    /// Produce the Cedar [`Context`] for this request.
    ///
    /// Any error causes the authorization check to fail closed.
    fn to_cedar_context(&self) -> Result<Context, AuthzError>;
}

// ── NoContext ─────────────────────────────────────────────────────────────────

/// Zero-overhead context for applications that do not use ABAC in Cedar policies.
///
/// Produces an empty [`Context`]. Use this when all Cedar policy decisions are
/// based purely on principal attributes (RBAC) or resource relationships (ReBAC).
pub struct NoContext;

impl BuildRequestContext for NoContext {
    fn to_cedar_context(&self) -> Result<Context, AuthzError> {
        Ok(Context::empty())
    }
}

// ── StandardRequestContext ────────────────────────────────────────────────────

/// Request context covering the most common ABAC attributes for web applications.
///
/// Attributes exposed to Cedar policies (only emitted ones must appear
/// in the schema; see module docs):
///
/// | Cedar attribute    | Type    | Always present |
/// |--------------------|---------|----------------|
/// | `mfa_verified`     | Boolean | yes            |
/// | `ip_address`       | String  | only if `Some` |
/// | `timestamp`        | String (ISO 8601) | only if built via [`StandardRequestContext::at`] |
///
/// Cedar policy example: require recent MFA for financial operations:
///
/// ```cedar
/// permit (
///     principal in App::Role::"finance-member",
///     action == App::Action::"PostJournalEntry",
///     resource is App::Ledger
/// ) when {
///     context.mfa_verified == true
/// };
/// ```
pub struct StandardRequestContext {
    /// Whether the current session has completed all required MFA factors.
    pub mfa_verified: bool,

    /// Source IP address, if available. Passed as a string; use Cedar's
    /// `ip()` extension function in policies if you need range checks.
    pub ip_address: Option<std::net::IpAddr>,

    /// Optional request timestamp. `None` (the default from [`new`])
    /// means *no* `timestamp` attribute is emitted into the Cedar
    /// context, so the schema doesn't need to declare one. Set via
    /// [`at`] with a `clock.now()` value if your policies inspect time.
    ///
    /// [`new`]: Self::new
    /// [`at`]: Self::at
    pub timestamp: Option<DateTime<Utc>>,
}

impl StandardRequestContext {
    /// Create a context without a timestamp.
    ///
    /// The Cedar request will carry `mfa_verified` (and `ip_address` if
    /// `Some`). No wall-clock call is made; DST-safe by construction.
    /// Use [`at`](Self::at) when a policy needs the time-of-request.
    pub fn new(mfa_verified: bool, ip_address: Option<std::net::IpAddr>) -> Self {
        Self {
            mfa_verified,
            ip_address,
            timestamp: None,
        }
    }

    /// Create a context with an explicit timestamp from an injectable
    /// clock. Pass `clock.now()` so DST tests can pin time.
    ///
    /// Emits `timestamp: String` (RFC 3339) into the Cedar context, so
    /// the corresponding action's schema must declare `timestamp`.
    pub fn at(
        mfa_verified: bool,
        ip_address: Option<std::net::IpAddr>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            mfa_verified,
            ip_address,
            timestamp: Some(timestamp),
        }
    }
}

impl BuildRequestContext for StandardRequestContext {
    fn to_cedar_context(&self) -> Result<Context, AuthzError> {
        let mut pairs: Vec<(String, RestrictedExpression)> = vec![(
            "mfa_verified".to_string(),
            RestrictedExpression::new_bool(self.mfa_verified),
        )];

        if let Some(ip) = &self.ip_address {
            pairs.push((
                "ip_address".to_string(),
                RestrictedExpression::new_string(ip.to_string()),
            ));
        }

        if let Some(ts) = &self.timestamp {
            pairs.push((
                "timestamp".to_string(),
                RestrictedExpression::new_string(ts.to_rfc3339()),
            ));
        }

        Context::from_pairs(pairs).map_err(|e| AuthzError::Context(format!("{e:?}")))
    }
}

// ── Convenience: build from a header map ─────────────────────────────────────

/// Extract a best-effort IP address from Axum request headers.
///
/// **Use only behind a trusted reverse proxy.** Reads `X-Real-IP` then
/// `X-Forwarded-For` (first entry) without any authenticity check: any
/// client can set these headers, so an internet-facing service that calls
/// this directly will accept attacker-supplied values for `ip_address` in
/// Cedar policies and rate-limit keys.
///
/// For internet-facing deployments, prefer
/// [`ip_from_headers_trusted`], which requires the actual peer address to
/// be in a configured trusted-proxy set before consulting forwarded
/// headers. Returns `None` if neither header is present or parseable.
pub fn ip_from_headers(headers: &axum::http::HeaderMap) -> Option<std::net::IpAddr> {
    let raw = headers
        .get("X-Real-IP")
        .or_else(|| headers.get("X-Forwarded-For"))
        .and_then(|v| v.to_str().ok())?;

    // X-Forwarded-For may be a comma-separated list; take the first entry.
    raw.split(',').next().and_then(|s| s.trim().parse().ok())
}

/// Set of trusted reverse-proxy peer addresses. When the request peer is in
/// this set the forwarded headers are honored; otherwise the peer address
/// itself is used. Construct from an explicit list of proxy IPs (typically
/// loopback for sidecars, or your load balancer's egress addresses).
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    proxies: std::sync::Arc<[std::net::IpAddr]>,
}

impl TrustedProxies {
    /// Build from any iterable of `IpAddr`. An empty set means "trust no
    /// forwarded headers": `ip_from_headers_trusted` will only ever return
    /// the peer address.
    pub fn new(addrs: impl IntoIterator<Item = std::net::IpAddr>) -> Self {
        Self {
            proxies: addrs.into_iter().collect(),
        }
    }

    /// Convenience: trust loopback only (typical for a sidecar / same-host
    /// reverse proxy like Envoy or NGINX on the same pod).
    pub fn loopback_only() -> Self {
        Self::new([
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ])
    }

    /// Whether `peer` is one of the configured trusted proxies.
    pub fn trusts(&self, peer: std::net::IpAddr) -> bool {
        self.proxies.contains(&peer)
    }
}

/// Extract the client IP, only honoring forwarded headers when the request's
/// actual peer address is in `trusted`. Returns the peer address otherwise.
///
/// Cedar policies and rate-limiters that branch on IP must use this (not
/// `ip_from_headers`) on any deployment exposed to clients that can set
/// arbitrary headers; otherwise an attacker can spoof
/// `X-Forwarded-For: 10.0.0.1` to forge a "trusted" origin and bypass
/// IP-conditioned rules.
pub fn ip_from_headers_trusted(
    headers: &axum::http::HeaderMap,
    peer: std::net::IpAddr,
    trusted: &TrustedProxies,
) -> std::net::IpAddr {
    if trusted.trusts(peer)
        && let Some(forwarded) = ip_from_headers(headers)
    {
        return forwarded;
    }
    peer
}

// ── Blanket impl for Arc<T> ───────────────────────────────────────────────────

impl<T: BuildRequestContext> BuildRequestContext for std::sync::Arc<T> {
    fn to_cedar_context(&self) -> Result<Context, AuthzError> {
        self.as_ref().to_cedar_context()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn ip_from_headers_reads_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "203.0.113.5".parse().unwrap());
        assert_eq!(
            ip_from_headers(&headers),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)))
        );
    }

    #[test]
    fn ip_from_headers_falls_back_to_x_forwarded_for_first_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            "198.51.100.10, 10.0.0.1".parse().unwrap(),
        );
        assert_eq!(
            ip_from_headers(&headers),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))
        );
    }

    #[test]
    fn ip_from_headers_returns_none_when_neither_header_present() {
        let headers = HeaderMap::new();
        assert!(ip_from_headers(&headers).is_none());
    }

    #[test]
    fn trusted_proxies_loopback_only_contains_v4_and_v6_loopback() {
        let trusted = TrustedProxies::loopback_only();
        assert!(trusted.trusts(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(trusted.trusts(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn trusted_proxies_rejects_unrelated_peer() {
        let trusted = TrustedProxies::loopback_only();
        assert!(!trusted.trusts(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn trusted_proxies_empty_set_trusts_nothing() {
        let trusted = TrustedProxies::new([]);
        assert!(!trusted.trusts(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
