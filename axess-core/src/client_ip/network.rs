//! The network a client address stands for, as every per-client key reads
//! it: the login throttle, the request rate limiter and the default device
//! fingerprint read the same answer, so they can never disagree about who
//! one client is.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The network a client address is keyed as.
///
/// One IPv6 subscriber is routinely handed a whole /64, so keying on the
/// full address would give one client 2^64 keys. The forms that carry an
/// IPv4 client are the other way round: every client of one NAT64 gateway
/// (`64:ff9b::/96`), one IPv4-translating or IPv4-compatible relay, one 6to4
/// site prefix (`2002::/16`) or one Teredo server (`2001::/32`) shares the
/// /64, so keyed on it one client would spend the budget of all of them.
/// Each is keyed on the client it carries, as that client reaching the
/// service over IPv4 is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientNetwork {
    /// An IPv4 client: an IPv4 address, or an IPv6 address that carries one
    /// at a fixed place (IPv4-mapped, IPv4-translated, IPv4-compatible,
    /// NAT64, 6to4, Teredo).
    V4(Ipv4Addr),
    /// An address under the locally used NAT64 prefix (`64:ff9b:1::/48`):
    /// the IPv4 client is in it at a place the operator's prefix length
    /// decides, so the whole address is the client.
    Whole(Ipv6Addr),
    /// Any other IPv6 address: its /64 prefix, the address with the
    /// interface identifier cleared.
    Prefix64(Ipv6Addr),
}

impl ClientNetwork {
    /// The network `address` is keyed as.
    pub(crate) fn of(address: IpAddr) -> Self {
        match address.to_canonical() {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => match carried_v4_client(v6) {
                Some(Carried::V4(v4)) => Self::V4(v4),
                Some(Carried::Whole) => Self::Whole(v6),
                None => Self::Prefix64(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
            },
        }
    }

    /// The network as one address: the IPv4 client, the whole address, or
    /// the /64 prefix with its interface identifier cleared.
    pub(crate) fn address(self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4),
            Self::Whole(v6) | Self::Prefix64(v6) => IpAddr::V6(v6),
        }
    }
}

/// What an IPv6 address that stands for a translated or tunnelled IPv4
/// client is keyed on.
enum Carried {
    /// The IPv4 client the address carries at a fixed place.
    V4(Ipv4Addr),
    /// The whole address: the client is in it, at a place the operator's
    /// prefix length decides.
    Whole,
}

/// The IPv4 client `v6` carries, when it is one of the translated or
/// tunnelled forms (the IPv4-mapped form is read by `to_canonical`).
fn carried_v4_client(v6: Ipv6Addr) -> Option<Carried> {
    let bits = u128::from(v6);
    let last32 = Ipv4Addr::from((bits & 0xffff_ffff) as u32);
    let seg = v6.segments();
    // NAT64 well-known prefix (RFC 6052): the client in the last 32 bits.
    if bits >> 32 == 0x0064_ff9b_0000_0000_0000_0000 {
        return Some(Carried::V4(last32));
    }
    // The locally used NAT64 prefix (RFC 8215): the place of the client
    // follows the operator's prefix length, so the whole address is the key.
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001 {
        return Some(Carried::Whole);
    }
    // IPv4-translated (`::ffff:0:a.b.c.d`, RFC 2765).
    if bits >> 32 == 0xffff_0000 {
        return Some(Carried::V4(last32));
    }
    // IPv4-compatible (`::a.b.c.d`), but not the unspecified or loopback
    // address, which share its prefix and carry no client.
    if bits >> 32 == 0 && bits > 1 {
        return Some(Carried::V4(last32));
    }
    // 6to4 (`2002:a.b.c.d::/48`, RFC 3056): the site's IPv4 address.
    if seg[0] == 0x2002 {
        let [a, b] = seg[1].to_be_bytes();
        let [c, d] = seg[2].to_be_bytes();
        return Some(Carried::V4(Ipv4Addr::new(a, b, c, d)));
    }
    // Teredo (`2001::/32`, RFC 4380): the client's address, inverted, in the
    // last 32 bits.
    if seg[0] == 0x2001 && seg[1] == 0 {
        return Some(Carried::V4(Ipv4Addr::from(!u32::from(last32))));
    }
    None
}
