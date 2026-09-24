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
//!     ip_from_headers_untrusted(request.headers()),
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
pub fn ip_from_headers_untrusted(headers: &axum::http::HeaderMap) -> Option<std::net::IpAddr> {
    let raw = headers
        .get("X-Real-IP")
        .or_else(|| headers.get("X-Forwarded-For"))
        .and_then(|v| v.to_str().ok())?;

    // X-Forwarded-For may be a comma-separated list; take the first entry.
    raw.split(',').next().and_then(|s| s.trim().parse().ok())
}

/// A trusted reverse proxy: either one address or a CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustedEntry {
    Exact(std::net::IpAddr),
    /// Network address plus prefix length, already masked at construction.
    Net(std::net::IpAddr, u8),
}

/// A CIDR string that could not be parsed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CidrParseError {
    /// No `/` separator, so no prefix length.
    #[error("missing '/' in CIDR: {0}")]
    MissingPrefix(String),
    /// The address before the `/` is not an IP address.
    #[error("invalid address in CIDR: {0}")]
    Address(String),
    /// The prefix length is not a number, or is wider than the family
    /// allows (over 32 for IPv4, over 128 for IPv6).
    #[error("invalid prefix length in CIDR: {0}")]
    Prefix(String),
    /// Bits are set below the prefix, so the spec names a host rather
    /// than a network: `10.0.0.5/8` is not `10.0.0.5`, it is the whole
    /// of `10.0.0.0/8`.
    ///
    /// Rejected rather than normalised because this list decides whose
    /// forwarded headers are believed, and silently promoting one host
    /// to sixteen million is not a correction anyone asked for. Write
    /// the network (`10.0.0.0/8`) or the host (`10.0.0.5/32`).
    #[error("CIDR names a host, not a network (host bits set below the prefix): {0}")]
    HostBitsSet(String),
}

fn parse_cidr(spec: &str) -> Result<(std::net::IpAddr, u8), CidrParseError> {
    let (addr, prefix) = spec
        .split_once('/')
        .ok_or_else(|| CidrParseError::MissingPrefix(spec.to_string()))?;
    let addr: std::net::IpAddr = addr
        .trim()
        .parse()
        .map_err(|_| CidrParseError::Address(spec.to_string()))?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .map_err(|_| CidrParseError::Prefix(spec.to_string()))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(CidrParseError::Prefix(spec.to_string()));
    }
    // An operator who writes `10.0.0.5/8` meaning one host would
    // otherwise trust the entire /8 with no error and no warning.
    if !host_bits_clear(addr, prefix) {
        return Err(CidrParseError::HostBitsSet(spec.to_string()));
    }
    Ok((addr, prefix))
}

/// Whether `addr` falls inside `net/prefix`. Mixed families never match:
/// an IPv4-mapped IPv6 peer is a different address, and silently treating
/// it as its IPv4 form would let a v6 client claim a v4 allowance.
/// Whether `addr` has no bits set below `prefix`, i.e. it names a
/// network rather than a host inside one.
fn host_bits_clear(addr: std::net::IpAddr, prefix: u8) -> bool {
    match addr {
        // Shifting by the full width is undefined, so a prefix that
        // covers every bit (and so has no host bits) is handled first.
        std::net::IpAddr::V4(a) => prefix == 32 || u32::from(a) & (u32::MAX >> prefix) == 0,
        std::net::IpAddr::V6(a) => prefix == 128 || u128::from(a) & (u128::MAX >> prefix) == 0,
    }
}

fn in_network(addr: std::net::IpAddr, net: std::net::IpAddr, prefix: u8) -> bool {
    match (addr, net) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
            // Shifting a u32 by 32 is undefined, so prefix 0 (match
            // everything) is handled before the shift.
            prefix == 0 || {
                let shift = 32 - u32::from(prefix);
                u32::from(a) >> shift == u32::from(n) >> shift
            }
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
            prefix == 0 || {
                let shift = 128 - u32::from(prefix);
                u128::from(a) >> shift == u128::from(n) >> shift
            }
        }
        _ => false,
    }
}

/// Set of trusted reverse proxies, as individual addresses or CIDR blocks.
///
/// When the request peer is in this set the forwarded headers are consulted;
/// otherwise the peer address itself is used. Populate it with your load
/// balancer's egress addresses or ranges, or use [`loopback_only`](Self::loopback_only)
/// for a same-host sidecar such as Envoy or NGINX in the same pod.
///
/// An empty set trusts nothing, which is the right configuration for a
/// service with no proxy in front of it: [`ip_from_headers_trusted`] then
/// only ever returns the peer address.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    entries: std::sync::Arc<[TrustedEntry]>,
}

impl TrustedProxies {
    /// Build from individual addresses.
    pub fn new(addrs: impl IntoIterator<Item = std::net::IpAddr>) -> Self {
        Self {
            entries: addrs.into_iter().map(TrustedEntry::Exact).collect(),
        }
    }

    /// Build from CIDR strings such as `"10.0.0.0/8"` or `"2001:db8::/32"`.
    ///
    /// Ranges matter in practice: a cloud load balancer's egress addresses
    /// change, and an operator who cannot express the range tends to skip
    /// the trusted-proxy check altogether and read the headers unguarded,
    /// which is the outcome this type exists to prevent.
    pub fn from_cidrs<I, S>(specs: I) -> Result<Self, CidrParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let entries = specs
            .into_iter()
            .map(|spec| parse_cidr(spec.as_ref()).map(|(net, p)| TrustedEntry::Net(net, p)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            entries: entries.into(),
        })
    }

    /// Add CIDR blocks to an existing set, so addresses and ranges compose.
    pub fn with_cidrs<I, S>(self, specs: I) -> Result<Self, CidrParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut entries: Vec<TrustedEntry> = self.entries.iter().copied().collect();
        for spec in specs {
            let (net, prefix) = parse_cidr(spec.as_ref())?;
            entries.push(TrustedEntry::Net(net, prefix));
        }
        Ok(Self {
            entries: entries.into(),
        })
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
        self.entries.iter().any(|entry| match *entry {
            TrustedEntry::Exact(addr) => addr == peer,
            TrustedEntry::Net(net, prefix) => in_network(peer, net, prefix),
        })
    }
}

/// Extract the client IP, honouring forwarded headers only when the peer the
/// server actually accepted is in `trusted`.
///
/// Cedar policies, rate-limiter keys and audit rows that carry an IP must use
/// this rather than [`ip_from_headers_untrusted`] on any deployment a client
/// can reach directly.
///
/// # Why the rightmost entry
///
/// `X-Forwarded-For` is append-only: each hop adds the address it saw. A
/// client can therefore send its own value, and a correctly configured proxy
/// will faithfully append the real address after it:
///
/// ```text
/// client sends:  X-Forwarded-For: 10.0.0.1
/// proxy appends:                  10.0.0.1, 203.0.113.9
///                                 ^^^^^^^^  ^^^^^^^^^^^
///                                 attacker  real client
/// ```
///
/// Taking the leftmost entry returns whatever the attacker chose, even
/// through a proxy that is doing its job. So this walks the list from the
/// right, skipping hops that are themselves trusted proxies, and returns the
/// first address that is not. Everything to the left of that is client-supplied
/// and is discarded.
///
/// A malformed entry stops the walk and yields the peer: once one hop's
/// contribution cannot be read, which hop wrote what is no longer knowable.
/// If every entry is a trusted proxy, the request originated inside the
/// trusted perimeter and the peer is returned.
///
/// `X-Real-IP` is consulted only when there is no `X-Forwarded-For`, because
/// it is a single value with no chain to audit: a proxy that forwards a
/// client-supplied one is indistinguishable from a proxy that set it.
pub fn ip_from_headers_trusted(
    headers: &axum::http::HeaderMap,
    peer: std::net::IpAddr,
    trusted: &TrustedProxies,
) -> std::net::IpAddr {
    if !trusted.trusts(peer) {
        return peer;
    }

    // Every `X-Forwarded-For` field line, in order, not just the first.
    //
    // RFC 9110 §5.3 makes repeated field lines equivalent to one
    // comma-joined list, but `HeaderMap::get` returns only the first.
    // A client that sends its own `X-Forwarded-For` to a proxy that adds
    // a *separate* line rather than appending to the existing one would
    // otherwise have the whole walk run over attacker-chosen entries,
    // with the real address sitting in a line never read: defeating
    // this function entirely.
    let mut lines = headers.get_all("X-Forwarded-For").iter().peekable();
    if lines.peek().is_some() {
        let mut entries: Vec<&str> = Vec::new();
        for value in lines {
            // A line that is not valid UTF-8 cannot be reasoned about, and
            // skipping it would silently shorten the chain.
            let Ok(text) = value.to_str() else {
                return peer;
            };
            entries.extend(text.split(','));
        }
        for entry in entries.iter().rev() {
            match entry.trim().parse::<std::net::IpAddr>() {
                Ok(addr) if trusted.trusts(addr) => continue,
                Ok(addr) => return addr,
                Err(_) => return peer,
            }
        }
        return peer;
    }

    // `X-Real-IP` carries no chain, so nothing in it can be audited: it is
    // trustworthy only where the proxy *overwrites* any client-supplied
    // value (nginx's `proxy_set_header X-Real-IP $remote_addr`). More than
    // one field line means something appended rather than overwrote, so
    // the first is whatever the client sent: fall back to the peer rather
    // than believe it.
    let mut real_ip = headers.get_all("X-Real-IP").iter();
    match (real_ip.next(), real_ip.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(peer),
        _ => peer,
    }
}

// ── Blanket impl for Arc<T> ───────────────────────────────────────────────────

impl<T: BuildRequestContext> BuildRequestContext for std::sync::Arc<T> {
    fn to_cedar_context(&self) -> Result<Context, AuthzError> {
        self.as_ref().to_cedar_context()
    }
}

#[cfg(test)]
mod tests;
