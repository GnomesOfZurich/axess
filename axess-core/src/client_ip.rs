//! The client's address, resolved once, where it can be resolved correctly.
//!
//! Five things in axess want to know who a request came from: the audit
//! trail, the Cedar request context, the rate limiter, the device
//! freshness gate, and account lockout. Before 0.7.0 each of them took an
//! `Option<IpAddr>` the adopter had to produce, axess shipped the correct
//! walk but never the wiring, and the rate limiter read the headers
//! itself because reaching [`TrustedProxies::client_ip`] meant enabling
//! `authz` and compiling Cedar.
//!
//! So the walk lives here, outside any feature gate, and [`layer()`](crate::client_ip::layer)
//! runs it once per request. Everything downstream reads [`ClientIp`].
//!
//! # Why the header alone is never enough
//!
//! `X-Forwarded-For` is append-only by convention: a caller sends its own
//! value and a proxy that appends leaves it in front of the real address,
//! so the leftmost entry is the caller's choice even through a proxy doing
//! its job. `X-Real-IP` carries no chain at all and no proxy sets it
//! unless configured to, so it usually arrives exactly as the caller wrote
//! it.
//!
//! The only part a caller cannot choose is the peer address the server
//! accepted the connection from. [`TrustedProxies::client_ip`] starts there:
//! if the peer is not a proxy you named, that is the answer and the
//! headers are ignored. If it is, the chain is walked from the right and
//! the first address no trusted hop vouches for is the client.
//!
//! # Two questions, not one
//!
//! That walk asks *may I read the headers at all*, which is about the
//! peer, and *how far left do I go*, which is about entries in the chain.
//! An address set answers both while you can enumerate your proxies.
//!
//! Enumerate them. Most managed front ends publish their ranges and mean
//! it: Cloudflare's list is definitive and machine-readable, cloud load
//! balancers document theirs, and a sidecar is loopback. An address set is
//! the stronger answer and is almost always available.
//!
//! [`TrustedProxies::private_transport`] is for the case where keeping
//! that list current is the weak link rather than the check itself. A
//! published range that rotates has to be re-synced, and a stale set fails
//! quietly: the walk stops trusting the peer, every request resolves to
//! the load balancer, and one bucket serves the world while the audit rows
//! all name the proxy. Where the operator can instead assert that the
//! listener is not reachable except through their own infrastructure, that
//! assertion is checkable and does not go stale.
//!
//! It answers yes to the first question and no to every instance of the
//! second, so the walk returns the rightmost entry. It is the weaker of
//! the two, its precondition is false the moment the port is reachable,
//! and when it is false a direct caller's headers are believed in full.
//! Reach for it because a list you cannot keep fresh is worse, not to
//! avoid writing a CIDR.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;

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
/// service with no proxy in front of it: [`TrustedProxies::client_ip`] then
/// only ever returns the peer address.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    entries: std::sync::Arc<[TrustedEntry]>,
    peer: PeerTrust,
    real_ip: bool,
}

/// Whether the connection's own peer counts as infrastructure.
///
/// The walk asks two questions and they are not the same one. First,
/// *may I read the forwarded headers at all*, which is about the peer.
/// Second, *how far left do I walk before I reach the client*, which is
/// about entries in the chain. A single address set answers both only
/// while you can enumerate your proxies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum PeerTrust {
    /// The peer must appear in the address set. The default, and the
    /// right answer whenever you can name your proxies.
    #[default]
    Enumerated,
    /// Every connection reaching this process came through infrastructure
    /// the operator controls, whatever its address. See
    /// [`TrustedProxies::private_transport`].
    AnyPeer,
}

impl TrustedProxies {
    /// Build from individual addresses.
    pub fn new(addrs: impl IntoIterator<Item = std::net::IpAddr>) -> Self {
        Self {
            entries: addrs.into_iter().map(TrustedEntry::Exact).collect(),
            peer: PeerTrust::Enumerated,
            real_ip: false,
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
            peer: PeerTrust::Enumerated,
            real_ip: false,
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
            // Preserved, so `private_transport().with_cidrs(..)` reads as
            // "trust whatever connects, and also skip these known hops".
            peer: self.peer,
            real_ip: self.real_ip,
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

    /// Trust whatever peer connects, because nothing can reach this
    /// process except through infrastructure you control.
    ///
    /// Prefer [`from_cidrs`](Self::from_cidrs). Managed front ends
    /// generally publish their ranges, and an address set checks something
    /// this cannot.
    ///
    /// This is for when the list is the weak link: a published range that
    /// rotates has to be re-synced, and a stale one fails quietly, with
    /// every request resolving to the proxy and one bucket serving
    /// everybody. Where the operator can assert instead that nothing
    /// reaches this process except through infrastructure they control,
    /// that assertion does not go stale, and it is the topology rather
    /// than the address that authenticates the hop in front.
    ///
    /// The chain set stays empty unless you add to it, so the walk trusts
    /// the peer, reads the headers, finds no entry it vouches for, and
    /// returns the rightmost: the address the platform's ingress appended,
    /// which is the client. Where you can name a further hop, compose:
    ///
    /// ```ignore
    /// // Unpinnable platform ingress, in front of it a CDN you can name.
    /// TrustedProxies::private_transport().with_cidrs(["203.0.113.0/24"])?
    /// ```
    ///
    /// # The precondition, which is yours to hold
    ///
    /// **Your listener must not be reachable from the internet.** If it is,
    /// this trusts a direct caller's forwarded headers completely, which is
    /// the forgery the rest of this module exists to prevent. Bind to a
    /// unix socket, a private interface, or a port only the platform's
    /// ingress can route to, and check it rather than assuming it.
    ///
    /// It is a weaker statement than an address set, and it is weaker in a
    /// way you can verify: "can anything else reach this port" has an
    /// answer you can go and look up. Prefer [`from_cidrs`](Self::from_cidrs)
    /// wherever the addresses are knowable.
    pub fn private_transport() -> Self {
        Self {
            entries: Vec::new().into(),
            peer: PeerTrust::AnyPeer,
            real_ip: false,
        }
    }

    /// Assert that the proxy in front **overwrites** `X-Real-IP`, and read
    /// it where there is no `X-Forwarded-For`.
    ///
    /// Off by default, and the default is the safe one. `X-Real-IP` is an
    /// ordinary request header: a proxy that overwrites it with the peer
    /// and a proxy that forwards whatever the caller sent produce
    /// byte-identical requests, so the value alone cannot be told apart
    /// from a forgery. Unlike `X-Forwarded-For` there is no chain to walk
    /// and nothing to check the value against.
    ///
    /// Most proxies do not set it at all unless told to. nginx needs
    /// `proxy_set_header X-Real-IP $remote_addr`; Caddy never sets it, so
    /// behind Caddy this header is whatever the caller wrote. Turning this
    /// on where the premise does not hold hands an attacker the audit
    /// address, the rate-limit bucket and the tenant IP policy in one
    /// header they can rotate per request.
    ///
    /// Check your proxy's configuration rather than assuming, and prefer
    /// configuring it to set `X-Forwarded-For` instead, which the walk can
    /// audit.
    pub fn proxy_overwrites_real_ip(mut self) -> Self {
        self.real_ip = true;
        self
    }

    /// Whether the connection's peer may have its forwarded headers read.
    ///
    /// Distinct from [`trusts_hop`](Self::trusts_hop): this gates whether
    /// the chain is consulted at all, that one decides how far along it to
    /// walk.
    pub fn trusts_peer(&self, peer: std::net::IpAddr) -> bool {
        match self.peer {
            PeerTrust::AnyPeer => true,
            PeerTrust::Enumerated => self.trusts_hop(peer),
        }
    }

    /// Whether `addr` is a proxy of yours appearing in the forwarded
    /// chain, so the walk should step past it and keep going left.
    pub fn trusts_hop(&self, addr: std::net::IpAddr) -> bool {
        self.entries.iter().any(|entry| match *entry {
            TrustedEntry::Exact(address) => address == addr,
            TrustedEntry::Net(net, prefix) => in_network(addr, net, prefix),
        })
    }

    /// The client's address for this request, as far as this set is
    /// willing to believe it.
    ///
    /// `peer` is the address the server accepted the connection from, or
    /// `None` where the transport has none: a unix-domain socket has no IP
    /// peer, and nothing for an address set to match.
    ///
    /// An untrusted peer is the answer and nothing forwarded is read. A
    /// trusted peer means the chain is walked from the right, and the
    /// first address no hop of yours vouches for is the client. No peer
    /// under [`private_transport`](Self::private_transport) walks the
    /// chain anyway, because that premise never needed the peer's
    /// address, only the guarantee that the request arrived through the
    /// right place. No peer with an address set is `None`: there is
    /// nothing to check against, and a header believed on its own is the
    /// forgery this module exists to prevent.
    ///
    /// # Why the rightmost entry
    ///
    /// `X-Forwarded-For` is append-only: each hop adds the address it saw.
    /// A client can therefore send its own value, and a proxy that appends
    /// will faithfully put the real address after it:
    ///
    /// ```text
    /// client sends:  X-Forwarded-For: 10.0.0.1
    /// proxy appends:                  10.0.0.1, 203.0.113.9
    ///                                 ^^^^^^^^  ^^^^^^^^^^^
    ///                                 attacker  real client
    /// ```
    ///
    /// Taking the leftmost entry returns whatever the attacker chose, even
    /// through a proxy doing its job. So the walk runs from the right,
    /// skipping hops that are themselves trusted, and returns the first
    /// address that is not. Everything to its left is client-supplied and
    /// is discarded.
    ///
    /// A malformed entry stops the walk: once one hop's contribution
    /// cannot be read, which hop wrote what is no longer knowable. If
    /// every entry is trusted, the request originated inside the
    /// perimeter.
    ///
    /// `X-Real-IP` is not read unless
    /// [`proxy_overwrites_real_ip`](Self::proxy_overwrites_real_ip) says
    /// so, and then only where there is no `X-Forwarded-For`. It is a
    /// single value with no chain to audit, so a proxy that forwards a
    /// client-supplied one is indistinguishable from a proxy that set it,
    /// and believing it by default would be the forgery this module exists
    /// to prevent. Without that assertion the peer is the answer.
    pub fn client_ip(
        &self,
        headers: &axum::http::HeaderMap,
        peer: Option<std::net::IpAddr>,
    ) -> ClientIp {
        let found = |addr, source| ClientIp {
            addr: Some(addr),
            source,
        };
        match peer {
            Some(peer) if !self.trusts_peer(peer) => found(peer, Source::Peer),
            Some(peer) => match client_from_chain(headers, self) {
                ChainOutcome::Client(addr) => found(addr, Source::Forwarded),
                // The peer is a proxy of ours, but the chain named nobody
                // behind it, so the request began at the proxy itself.
                ChainOutcome::NoAnswer => found(peer, Source::Peer),
            },
            None if self.peer != PeerTrust::AnyPeer => ClientIp::default(),
            None => match client_from_chain(headers, self) {
                ChainOutcome::Client(addr) => found(addr, Source::Forwarded),
                ChainOutcome::NoAnswer => ClientIp::default(),
            },
        }
    }
}

/// What the forwarded chain yielded, with "use the peer instead" kept
/// separate from an address, because a caller with no peer has no such
/// fallback to fall back to.
enum ChainOutcome {
    Client(std::net::IpAddr),
    NoAnswer,
}

/// The client according to the forwarded headers: the rightmost entry
/// that no trusted hop vouches for.
///
/// The caller has already decided the peer may be believed.
fn client_from_chain(headers: &axum::http::HeaderMap, trusted: &TrustedProxies) -> ChainOutcome {
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
                return ChainOutcome::NoAnswer;
            };
            entries.extend(text.split(','));
        }
        for entry in entries.iter().rev() {
            match entry.trim().parse::<std::net::IpAddr>() {
                Ok(addr) if trusted.trusts_hop(addr) => continue,
                Ok(addr) => return ChainOutcome::Client(addr),
                Err(_) => return ChainOutcome::NoAnswer,
            }
        }
        return ChainOutcome::NoAnswer;
    }

    // `X-Real-IP` carries no chain, so nothing in it can be audited: it is
    // trustworthy only where the proxy *overwrites* any client-supplied
    // value (nginx's `proxy_set_header X-Real-IP $remote_addr`), which is
    // an assertion only the operator can make, so it is theirs to make
    // explicitly. Without it the header is not read at all, because a
    // trusted peer that sets neither header leaves this one entirely in
    // the caller's hands. More than one field line means something
    // appended rather than overwrote, so the first is whatever the client
    // sent: fall back to the peer rather than believe it.
    if !trusted.real_ip {
        return ChainOutcome::NoAnswer;
    }
    let mut real_ip = headers.get_all("X-Real-IP").iter();
    match (real_ip.next(), real_ip.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .map(ChainOutcome::Client)
            .unwrap_or(ChainOutcome::NoAnswer),
        _ => ChainOutcome::NoAnswer,
    }
}
// ── The resolved address ─────────────────────────────────────────────────────

/// The address a request came from, as far as this deployment is willing to
/// believe it.
///
/// The field is private and [`layer()`](crate::client_ip::layer) is the only thing that fills
/// it, so there is no way to build one of these out of a header. That is
/// the point: a type whose wrong value is unconstructible beats a
/// documented warning, which is what the previous two attempts at this
/// were and what an adopter's migration walked straight past.
///
/// `None` means nobody knows. No peer was recorded, so nothing could be
/// checked, and there is deliberately no fallback to the header. A null
/// address in an audit row is honest; a forged one is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientIp {
    addr: Option<IpAddr>,
    source: Source,
}

/// How the address was arrived at.
///
/// The address alone does not say what it is worth. "203.0.113.5, the peer
/// we accepted" and "203.0.113.5, the rightmost entry no trusted hop
/// vouched for" are different claims, and an auditor asking how you know
/// is asking this.
///
/// It also names the two failures that are otherwise silent. Every request
/// sharing one rate-limit bucket, or every audit row carrying a null
/// address, looks the same from the outside; [`Unknown`](Self::Unknown)
/// says the layer is not installed, and [`Peer`](Self::Peer) on a
/// deployment that has a proxy says the trusted set does not name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Nothing resolved an address. No peer was recorded, or the layer is
    /// not installed on this route.
    #[default]
    Unknown,
    /// The peer the server accepted. It was not a proxy this deployment
    /// trusts, so nothing forwarded was read.
    Peer,
    /// The forwarded chain, walked against a peer that is trusted.
    Forwarded,
    /// Handed over by the application through
    /// [`ClientIp::resolved`](ClientIp::resolved), authenticated by
    /// something axess cannot see.
    Supplied,
}

impl Source {
    /// The wire string, for a database column or a log field.
    ///
    /// Pinned like the event enums: these values end up in audit rows that
    /// outlive the code, so a rename here rewrites history.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Peer => "peer",
            Self::Forwarded => "forwarded",
            Self::Supplied => "supplied",
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ClientIp {
    /// The address, if one was resolved.
    pub fn get(self) -> Option<IpAddr> {
        self.addr
    }

    /// How it was arrived at. See [`Source`].
    pub fn source(self) -> Source {
        self.source
    }

    /// Build one from an address you resolved yourself.
    ///
    /// [`layer`] handles the case axess can
    /// reason about: a forwarded chain, checked against the peer and the
    /// proxies you named. Some front ends do not present that. Cloudflare
    /// sends `CF-Connecting-IP`, Fly sends `Fly-Client-IP`, a service mesh
    /// may forward an identity of its own, and each is authenticated by
    /// something axess cannot see, such as an authenticated origin pull or
    /// a network the caller cannot reach.
    ///
    /// Insert the result in your own middleware and everything downstream
    /// reads it: the audit context, the rate-limit key, the device gate.
    ///
    /// ```ignore
    /// let ip = cf_connecting_ip(req.headers());   // yours to validate
    /// req.extensions_mut().insert(ClientIp::resolved(ip));
    /// ```
    ///
    /// # What you are asserting
    ///
    /// That the value is authenticated by something. This constructor
    /// reads no header and checks no peer; it takes your word. Calling it
    /// with a header a caller can write puts the caller's choice into the
    /// audit trail, the lockout counter and the rate-limit bucket, which
    /// is the whole failure this module was built to end.
    ///
    /// Prefer the layer. Reach for this only where the layer cannot see
    /// what authenticates the address.
    pub fn resolved(addr: Option<IpAddr>) -> Self {
        Self {
            addr,
            source: Source::Supplied,
        }
    }

    /// Construct one directly, for tests that need a request to look as
    /// though it arrived from a particular address.
    ///
    /// Identical to [`resolved`](Self::resolved) and kept separate so a
    /// test reads as a test.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_test(addr: Option<IpAddr>) -> Self {
        Self {
            addr,
            source: Source::Supplied,
        }
    }
}

/// Resolve the client address once and put it in the request extensions.
///
/// Wrap the whole router in this, outside everything that reads an
/// address, because only the layer nearest the socket reliably has the
/// peer from `ConnectInfo`. Serve the router with
/// `into_make_service_with_connect_info::<SocketAddr>()` or every request
/// resolves to `None`.
async fn run(trusted: TrustedProxies, mut request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let resolved = trusted.client_ip(request.headers(), peer);
    request.extensions_mut().insert(resolved);
    next.run(request).await
}

/// Apply the resolution to `router` with the proxies this deployment trusts.
///
/// ```ignore
/// let app = client_ip::layer(app, TrustedProxies::loopback_only());
/// ```
pub fn layer(router: axum::Router, trusted: TrustedProxies) -> axum::Router {
    router.layer(axum::middleware::from_fn(move |request, next| {
        let trusted = trusted.clone();
        async move { run(trusted, request, next).await }
    }))
}

impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        // A route mounted outside the layer and a peer that could not be
        // read answer the same way on purpose. Neither can usefully be
        // distinguished by a handler, and both mean the same thing to an
        // audit row and to a rate-limit key.
        Ok(parts
            .extensions
            .get::<ClientIp>()
            .copied()
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests;
