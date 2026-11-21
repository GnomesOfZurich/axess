//! Where the server may connect to on behalf of a URL it was handed.
//!
//! A deployment that lets a tenant name its own identity provider hands the
//! server a URL to fetch, and the document behind it names more URLs to fetch
//! (keys, token and user-info endpoints). Without a screen the server is a
//! request proxy into the loopback interface and the private network. An
//! [`EgressPolicy`](crate::egress::EgressPolicy) is that screen: the scheme and the host of every URL are
//! checked when the URL arrives, and the addresses a name resolves to are
//! checked again when the connection is made, so a name that points at a
//! reserved address is refused, and so is a name that changes its answer
//! between the check and the connection.
//!
//! Three policies, each named:
//!
//! - [`EgressPolicy::screened`](crate::egress::EgressPolicy::screened) (the default): HTTPS only, and no connection
//!   to a loopback, private, link-local, unique-local, shared-address,
//!   metadata, unspecified or multicast address.
//! - [`EgressPolicy::screened_allowing_loopback_http`](crate::egress::EgressPolicy::screened_allowing_loopback_http): the same, except that
//!   loopback hosts may be reached over plain HTTP. For tests and local
//!   development against a mock identity provider.
//! - [`EgressPolicy::unscreened`](crate::egress::EgressPolicy::unscreened): only the transport rule of HTTPS, or
//!   loopback HTTP; any address is reachable. For a deployment that federates
//!   with an identity provider on its own network and trusts everyone who can
//!   write a provider record.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// The address ranges a screened policy refuses to connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedRange {
    /// `127.0.0.0/8`, `::1`: this machine.
    Loopback,
    /// `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`: the private network;
    /// also the IPv4 special-purpose ranges that are not globally reachable
    /// (`192.0.0.0/24`, the documentation ranges, `198.18.0.0/15`,
    /// `240.0.0.0/4`) and the locally used NAT64 prefix.
    Private,
    /// `169.254.0.0/16`, `fe80::/10`: the local link.
    LinkLocal,
    /// `fc00::/7`: IPv6 unique-local addresses.
    UniqueLocal,
    /// The cloud metadata addresses `169.254.169.254` and `fd00:ec2::254`.
    Metadata,
    /// `100.64.0.0/10`: carrier-grade NAT shared space.
    Shared,
    /// `0.0.0.0/8`, `::`: the unspecified address.
    Unspecified,
    /// Multicast and the IPv4 broadcast address.
    Multicast,
}

impl ReservedRange {
    /// The name the refusal carries.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link-local",
            Self::UniqueLocal => "unique-local",
            Self::Metadata => "metadata",
            Self::Shared => "shared-address",
            Self::Unspecified => "unspecified",
            Self::Multicast => "multicast",
        }
    }

    /// The reserved range `ip` is in, or `None` for a public address.
    ///
    /// An IPv6 address that carries an IPv4 address is judged as the IPv4
    /// address it carries, in every form that does: IPv4-mapped
    /// (`::ffff:a.b.c.d`), IPv4-translated (`::ffff:0:a.b.c.d`),
    /// IPv4-compatible (`::a.b.c.d`), NAT64 (`64:ff9b::/96`) and 6to4
    /// (`2002:a.b.c.d::/48`). Two prefixes are never a public server: the
    /// locally used NAT64 prefix `64:ff9b:1::/48`, and Teredo (`2001::/32`),
    /// a tunnel to a client behind a NAT whose address is carried inverted
    /// in the last 32 bits. Each is judged as the IPv4 address it carries
    /// when that one is reserved, and as private otherwise.
    #[must_use]
    pub fn of(ip: IpAddr) -> Option<Self> {
        match ip {
            IpAddr::V4(v4) => of_v4(v4),
            IpAddr::V6(v6) => of_v6_embedding(v6),
        }
    }
}

/// The range of an IPv6 address, looking through the forms that carry IPv4.
fn of_v6_embedding(ip: Ipv6Addr) -> Option<ReservedRange> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return of_v4(v4);
    }
    let seg = ip.segments();
    let o = ip.octets();
    let last = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    if seg[..6] == [0; 6] && !ip.is_loopback() && !ip.is_unspecified() {
        // `::a.b.c.d` is judged by the address in it; `::` and `::1` below.
        return of_v4(last).or_else(|| of_v6(ip));
    }
    if seg[0] == 0x0064 && seg[1] == 0xff9b {
        if seg[2..6] == [0; 4] {
            return of_v4(last);
        }
        if seg[2] == 1 {
            return of_v4(last).or(Some(ReservedRange::Private));
        }
    }
    if seg[0] == 0x2002 {
        return of_v4(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    if seg[..4] == [0; 4] && seg[4] == 0xffff && seg[5] == 0 {
        // `::ffff:0:a.b.c.d`, the IPv4-translated form of a stateless
        // translator: the address in its last 32 bits.
        return of_v4(last);
    }
    if seg[0] == 0x2001 && seg[1] == 0 {
        // Teredo: the client's address, inverted, in the last 32 bits. The
        // tunnel ends at a host behind a NAT, never at a public server.
        let client = Ipv4Addr::new(!o[12], !o[13], !o[14], !o[15]);
        return of_v4(client).or(Some(ReservedRange::Private));
    }
    of_v6(ip)
}

fn of_v4(ip: Ipv4Addr) -> Option<ReservedRange> {
    let o = ip.octets();
    if ip.is_loopback() {
        Some(ReservedRange::Loopback)
    } else if ip == Ipv4Addr::new(169, 254, 169, 254) {
        Some(ReservedRange::Metadata)
    } else if ip.is_link_local() {
        Some(ReservedRange::LinkLocal)
    } else if ip.is_private() {
        Some(ReservedRange::Private)
    } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
        Some(ReservedRange::Shared)
    } else if o[0] == 0 {
        Some(ReservedRange::Unspecified)
    } else if ip.is_multicast() || ip.is_broadcast() {
        Some(ReservedRange::Multicast)
    } else if is_special_purpose_v4(o) {
        Some(ReservedRange::Private)
    } else {
        None
    }
}

/// The IANA special-purpose IPv4 ranges that are not globally reachable and
/// that no other range names: `192.0.0.0/24` (protocol assignments),
/// `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` (documentation),
/// `198.18.0.0/15` (benchmarking) and `240.0.0.0/4` (reserved).
fn is_special_purpose_v4(o: [u8; 4]) -> bool {
    matches!(o, [192, 0, 0 | 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || o[0] >= 240
}

fn of_v6(ip: Ipv6Addr) -> Option<ReservedRange> {
    let seg = ip.segments();
    if ip.is_loopback() {
        Some(ReservedRange::Loopback)
    } else if ip.is_unspecified() {
        Some(ReservedRange::Unspecified)
    } else if seg[0] == 0xfd00 && seg[1] == 0x0ec2 {
        Some(ReservedRange::Metadata)
    } else if (seg[0] & 0xffc0) == 0xfe80 {
        Some(ReservedRange::LinkLocal)
    } else if (seg[0] & 0xfe00) == 0xfc00 {
        Some(ReservedRange::UniqueLocal)
    } else if ip.is_multicast() {
        Some(ReservedRange::Multicast)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Screened,
    ScreenedLoopbackHttp,
    Unscreened,
}

/// What URLs the server may fetch, and which addresses it may connect to.
/// See the [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressPolicy {
    mode: Mode,
}

impl Default for EgressPolicy {
    /// [`screened`](Self::screened).
    fn default() -> Self {
        Self::screened()
    }
}

impl EgressPolicy {
    /// HTTPS only, and no connection to a reserved address. The default.
    #[must_use]
    pub const fn screened() -> Self {
        Self {
            mode: Mode::Screened,
        }
    }

    /// As [`screened`](Self::screened), except that a loopback host may be
    /// reached over plain HTTP. For tests and local development against a
    /// mock identity provider; never for a deployment that takes provider
    /// URLs from tenants.
    #[must_use]
    pub const fn screened_allowing_loopback_http() -> Self {
        Self {
            mode: Mode::ScreenedLoopbackHttp,
        }
    }

    /// No address screen: any host the URL names is reachable, subject only
    /// to the transport rule (HTTPS, or HTTP to a loopback host). The named
    /// opt-out for a deployment that federates with an identity provider on
    /// its own network and trusts everyone who can write a provider record.
    #[must_use]
    pub const fn unscreened() -> Self {
        Self {
            mode: Mode::Unscreened,
        }
    }

    /// Whether addresses are screened.
    #[must_use]
    pub const fn is_screened(self) -> bool {
        !matches!(self.mode, Mode::Unscreened)
    }

    const fn loopback_http(self) -> bool {
        matches!(self.mode, Mode::ScreenedLoopbackHttp)
    }

    /// Check one URL the server was handed. `what` names the setting in the
    /// refusal; the URL itself is not echoed.
    ///
    /// A URL that does not parse, that carries userinfo, or whose scheme is
    /// not HTTPS (or HTTP to loopback where the policy allows it) is refused;
    /// so is a host that is an address in a reserved range, and `localhost`
    /// by name. A host name is checked again, on the addresses it resolves
    /// to, when the connection is made: see
    /// [`build_client`](Self::build_client).
    ///
    /// # Errors
    ///
    /// The refusal, naming `what` and the reason.
    pub fn check_url(self, url: &str, what: &str) -> Result<(), EgressRefusal> {
        if !self.is_screened() {
            return if crate::endpoint::is_https_or_loopback(url) {
                Ok(())
            } else {
                Err(EgressRefusal::new(what, "HTTPS required"))
            };
        }
        let parsed =
            url::Url::parse(url).map_err(|_| EgressRefusal::new(what, "not a valid URL"))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(EgressRefusal::new(what, "credentials in the URL"));
        }
        let host = parsed
            .host()
            .ok_or_else(|| EgressRefusal::new(what, "no host"))?;
        let loopback_host = match &host {
            url::Host::Domain(d) => {
                let d = d.trim_end_matches('.').to_ascii_lowercase();
                d == "localhost" || d.ends_with(".localhost")
            }
            url::Host::Ipv4(ip) => {
                ReservedRange::of(IpAddr::V4(*ip)) == Some(ReservedRange::Loopback)
            }
            url::Host::Ipv6(ip) => {
                ReservedRange::of(IpAddr::V6(*ip)) == Some(ReservedRange::Loopback)
            }
        };
        match parsed.scheme() {
            "https" => {}
            "http" if self.loopback_http() && loopback_host => {}
            _ => return Err(EgressRefusal::new(what, "HTTPS required")),
        }
        let range = match host {
            url::Host::Domain(_) if loopback_host => Some(ReservedRange::Loopback),
            url::Host::Domain(_) => None,
            url::Host::Ipv4(ip) => ReservedRange::of(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => ReservedRange::of(IpAddr::V6(ip)),
        };
        match range {
            Some(ReservedRange::Loopback) if self.loopback_http() => Ok(()),
            Some(range) => Err(EgressRefusal::new(what, range.name())),
            None => Ok(()),
        }
    }

    /// An HTTP client that carries this policy, as a [`ScreenedClient`]:
    /// the only way to make one, so a function that takes a
    /// `ScreenedClient` knows the client follows no redirect and, under a
    /// screened policy, connects to no reserved address and follows no
    /// proxy from the environment. No builder is handed out: a builder
    /// would take a redirect policy, a proxy or a pinned address after the
    /// policy's settings and so undo them.
    ///
    /// ```compile_fail,E0599
    /// use axess_factors::egress::EgressPolicy;
    /// let _ = EgressPolicy::screened().client_builder();
    /// ```
    ///
    /// The screen runs on the addresses a host name resolves to, at the moment
    /// of connecting, so a name that points at a reserved address is refused
    /// and a name that changes its answer after [`check_url`](Self::check_url)
    /// is caught. A URL whose host is an address needs no lookup and is
    /// caught by `check_url`; check every URL before the client uses it.
    ///
    /// A screened policy never follows a proxy from the environment
    /// (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`): a proxy resolves the
    /// target's name itself and connects on its own, so the resolver above
    /// would never see the address it connects to. A deployment that must go
    /// through a proxy either filters at the proxy and uses
    /// [`unscreened`](Self::unscreened), which follows the environment as a
    /// plain client does, or reaches the identity provider directly.
    ///
    /// `configure` adds the caller's settings to the client as
    /// [`ClientSettings`]: timeouts, a `User-Agent`, a trusted root
    /// certificate and a client certificate, the settings that cannot undo
    /// the policy, and no others. The policy's own settings are applied
    /// after them.
    ///
    /// # Errors
    ///
    /// The builder's error: the TLS backend cannot be initialised, or a
    /// setting does not build (a `User-Agent` that is not a header value).
    pub fn build_client(
        self,
        configure: impl FnOnce(ClientSettings) -> ClientSettings,
    ) -> Result<ScreenedClient, reqwest::Error> {
        let settings = configure(ClientSettings {
            builder: reqwest::ClientBuilder::new(),
        });
        let inner = self.screen(settings.builder).build()?;
        Ok(ScreenedClient {
            inner,
            policy: self,
        })
    }

    /// The policy's settings on a builder, applied last so they win: no
    /// redirect, and under a screened policy no environment proxy and the
    /// address screen in the resolver.
    fn screen(self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        let builder = builder.redirect(reqwest::redirect::Policy::none());
        if self.is_screened() {
            builder.no_proxy().dns_resolver(Arc::new(ScreenedResolver {
                allow_loopback: self.loopback_http(),
            }))
        } else {
            builder
        }
    }
}

/// The settings a caller may add to a client the policy builds, through
/// [`EgressPolicy::build_client`]: the ones that cannot undo the policy.
///
/// A `reqwest` builder offers more, and one of them, a fixed answer for a
/// host name (`resolve`), would route that name past the address screen:
/// the resolver the policy installs is asked only about names the caller
/// did not pin. So the caller does not get the builder. It gets this value,
/// which offers timeouts, a `User-Agent`, a trusted root certificate and a
/// client certificate, and nothing else:
///
/// ```compile_fail,E0599
/// use axess_factors::egress::EgressPolicy;
/// let pinned = "10.0.0.5:443".parse().unwrap();
/// let _ = EgressPolicy::screened()
///     .build_client(|settings| settings.resolve("idp.example", pinned));
/// ```
///
/// None of them touches the redirect rule, the proxy rule or the resolver
/// screen. A proxy is not on offer: a screened policy follows none, and an
/// unscreened one follows the environment's (`HTTPS_PROXY`), as a plain
/// client does. A client that needs more than these is not a screened
/// client, and the policy builds none: it is a `reqwest` client of the
/// application's own, which no fetch of this library takes.
#[derive(Debug)]
#[must_use = "the settings reach the client only when returned to build_client"]
pub struct ClientSettings {
    builder: reqwest::ClientBuilder,
}

impl ClientSettings {
    /// A timeout for each request as a whole, from the start of the
    /// connection to the last byte of the body.
    pub fn timeout(self, timeout: std::time::Duration) -> Self {
        Self {
            builder: self.builder.timeout(timeout),
        }
    }

    /// A timeout for the connection alone: name lookup, TCP and the TLS
    /// handshake.
    pub fn connect_timeout(self, timeout: std::time::Duration) -> Self {
        Self {
            builder: self.builder.connect_timeout(timeout),
        }
    }

    /// The `User-Agent` sent with every request. Some token endpoints
    /// refuse a request without one. A value that is not a header value
    /// (a line break in it, say) is refused when the client is built.
    pub fn user_agent(self, user_agent: &str) -> Self {
        Self {
            builder: self.builder.user_agent(user_agent.to_owned()),
        }
    }

    /// Trust `certificate` as a root, beside the bundled web roots: for an
    /// identity provider on the deployment's own network whose certificate
    /// chains to a private certificate authority. It widens whom the client
    /// believes, never where it connects: the address screen and the
    /// redirect rule are the policy's and stay.
    pub fn root_certificate(self, certificate: reqwest::Certificate) -> Self {
        Self {
            builder: self.builder.add_root_certificate(certificate),
        }
    }

    /// The client certificate and key presented on every TLS handshake
    /// (mutual TLS, RFC 8705), through the rustls backend.
    pub fn client_certificate(self, identity: reqwest::Identity) -> Self {
        Self {
            builder: self.builder.use_rustls_tls().identity(identity),
        }
    }
}

/// An HTTP client built by [`EgressPolicy::build_client`], carrying the
/// policy it was built under.
///
/// A fetch that takes one, such as
/// [`DiscoveryDocument::fetch`](crate::oidc::DiscoveryDocument::fetch)
/// or [`JwksCache::fetch`](crate::oidc::JwksCache::fetch),
/// screens its URLs under [`policy`](Self::policy) and connects through a
/// client whose redirect, proxy and resolver settings that policy chose, so
/// the two cannot disagree and a caller cannot hand it a client that
/// follows a redirect or a DNS answer into a reserved range.
#[derive(Debug, Clone)]
pub struct ScreenedClient {
    inner: reqwest::Client,
    policy: EgressPolicy,
}

impl ScreenedClient {
    /// The policy the client was built under.
    #[must_use]
    pub const fn policy(&self) -> EgressPolicy {
        self.policy
    }

    /// The client itself, for a request whose URL
    /// [`check_url`](EgressPolicy::check_url) has passed.
    #[must_use]
    pub const fn inner(&self) -> &reqwest::Client {
        &self.inner
    }

    /// The client itself, for a holder that keeps the policy beside it.
    #[must_use]
    pub fn into_inner(self) -> reqwest::Client {
        self.inner
    }
}

/// A URL the policy refused. It names the setting and the reason, never the
/// URL or an address, so a refusal in a log or an error message gives a
/// probing tenant nothing to map the network with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{setting} refused: {range}")]
pub struct EgressRefusal {
    /// The setting that carried the URL (`issuer URL`, `token_endpoint`).
    pub setting: String,
    /// Why: the name of a reserved range (`loopback`, `private`, `metadata`,
    /// and so on), or `HTTPS required`, `not a valid URL`, `no host`,
    /// `credentials in the URL`.
    pub range: String,
}

impl EgressRefusal {
    fn new(setting: &str, range: &str) -> Self {
        Self {
            setting: setting.to_owned(),
            range: range.to_owned(),
        }
    }
}

struct ScreenedResolver {
    allow_loopback: bool,
}

impl reqwest::dns::Resolve for ScreenedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_loopback = self.allow_loopback;
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let found: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let mut refused = None;
            let allowed: Vec<SocketAddr> = found
                .into_iter()
                .filter(|addr| match ReservedRange::of(addr.ip()) {
                    None => true,
                    Some(ReservedRange::Loopback) if allow_loopback => true,
                    Some(range) => {
                        refused.get_or_insert(range);
                        false
                    }
                })
                .collect();
            if allowed.is_empty() {
                let why = match refused {
                    Some(range) => format!(
                        "host resolves to a {} address, which tenant-supplied URLs may not reach",
                        range.name()
                    ),
                    None => "host did not resolve".to_owned(),
                };
                return Err(why.into());
            }
            let addrs: reqwest::dns::Addrs = Box::new(allowed.into_iter());
            Ok(addrs)
        })
    }
}
