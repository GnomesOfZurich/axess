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
    /// `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`: the private network.
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

    /// The reserved range `ip` is in, or `None` for a public address. An
    /// IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is judged as the IPv4
    /// address it carries.
    #[must_use]
    pub fn of(ip: IpAddr) -> Option<Self> {
        match ip {
            IpAddr::V4(v4) => of_v4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => of_v4(v4),
                None => of_v6(v6),
            },
        }
    }
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
    } else {
        None
    }
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
    /// [`client_builder`](Self::client_builder).
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
            "http" => {
                return Err(EgressRefusal::new(what, "HTTPS required"));
            }
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

    /// An HTTP client builder that follows no redirect and, under a screened
    /// policy, connects only to addresses outside the reserved ranges.
    ///
    /// The screen runs on the addresses a host name resolves to, at the moment
    /// of connecting, so a name that points at a reserved address is refused
    /// and a name that changes its answer after [`check_url`](Self::check_url)
    /// is caught. A URL whose host is an address needs no lookup and is
    /// caught by `check_url`; check every URL before the client uses it.
    pub fn client_builder(self) -> openidconnect::reqwest::ClientBuilder {
        let builder = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none());
        if self.is_screened() {
            builder.dns_resolver(Arc::new(ScreenedResolver {
                allow_loopback: self.loopback_http(),
            }))
        } else {
            builder
        }
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

impl openidconnect::reqwest::dns::Resolve for ScreenedResolver {
    fn resolve(
        &self,
        name: openidconnect::reqwest::dns::Name,
    ) -> openidconnect::reqwest::dns::Resolving {
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
            let addrs: openidconnect::reqwest::dns::Addrs = Box::new(allowed.into_iter());
            Ok(addrs)
        })
    }
}
