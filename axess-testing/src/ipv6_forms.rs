//! The IPv6 forms that carry, or share a prefix with, another address, as one
//! table for every test that has to treat them alike.
//!
//! An IPv6 address can be a disguise for an IPv4 one (a screen that judges
//! only the IPv6 text lets a metadata address through), and two IPv6 addresses
//! a host can rotate between are one client when they share a `/64` (a
//! throttle keyed on the whole address lets a client dodge it). The table
//! lives here once, so the egress screen and the throttle are tested against
//! the same forms.

use std::net::{Ipv4Addr, Ipv6Addr};

/// One IPv6 address and the form it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Form {
    /// The form, for an assertion message.
    pub name: &'static str,
    /// The address.
    pub addr: Ipv6Addr,
}

/// Every IPv6 form that carries `v4`: IPv4-mapped (`::ffff:a.b.c.d`),
/// IPv4-compatible (`::a.b.c.d`), NAT64 (`64:ff9b::/96`), the locally used
/// NAT64 prefix (`64:ff9b:1::/48`) and 6to4 (`2002:a.b.c.d::/48`).
#[must_use]
pub fn embedding_v4(v4: Ipv4Addr) -> Vec<Ipv6Form> {
    let [a, b, c, d] = v4.octets();
    let hi = u16::from_be_bytes([a, b]);
    let lo = u16::from_be_bytes([c, d]);
    vec![
        Ipv6Form {
            name: "ipv4-mapped",
            addr: v4.to_ipv6_mapped(),
        },
        Ipv6Form {
            name: "ipv4-compatible",
            addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, hi, lo),
        },
        Ipv6Form {
            name: "nat64",
            addr: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, hi, lo),
        },
        Ipv6Form {
            name: "local-use nat64",
            addr: Ipv6Addr::new(0x64, 0xff9b, 1, 0x1234, 0, 0, hi, lo),
        },
        Ipv6Form {
            name: "6to4",
            addr: Ipv6Addr::new(0x2002, hi, lo, 0x1234, 0, 0, 0, 1),
        },
    ]
}

/// Pairs of distinct IPv6 addresses in the same `/64`: one client that rotates
/// its interface identifier.
#[must_use]
pub fn same_64_pairs() -> Vec<(Ipv6Addr, Ipv6Addr)> {
    vec![
        (
            Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0xffff, 0xffff, 0xffff, 0xffff),
        ),
        (
            Ipv6Addr::new(0x2606, 0x4700, 0, 0x10, 1, 2, 3, 4),
            Ipv6Addr::new(0x2606, 0x4700, 0, 0x10, 0x8a2e, 0x370, 0x7334, 5),
        ),
    ]
}

/// Pairs of IPv6 addresses in different `/64`s, one bit of the network part
/// apart at the boundary and far apart: two clients.
#[must_use]
pub fn different_64_pairs() -> Vec<(Ipv6Addr, Ipv6Addr)> {
    vec![
        (
            Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1),
        ),
        (
            Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1),
            Ipv6Addr::new(0x2606, 0x4700, 0, 0x10, 0, 0, 0, 1),
        ),
    ]
}

// The table of forms with their expected classification, used by the throttle
// and screen tests that iterate every form.
/// One spelling of an IPv6 address and what it stands for.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Case {
    /// The form's name, for a failure message.
    pub name: &'static str,
    /// The address in text form.
    pub address: &'static str,
    /// The IPv4 address the form carries, in dotted text, when it embeds one
    /// the way a client keyed on its IPv4 address should treat it.
    pub embedded_v4: Option<&'static str>,
}

/// Forms of IPv6 address that matter to a key or a screen: an IPv4-mapped
/// address, an IPv4-compatible one, a NAT64 address, a 6to4 address, and two
/// addresses in one /64 beside one in the next /64.
pub const IPV6_FORMS: &[Ipv6Case] = &[
    Ipv6Case {
        name: "ipv4-mapped",
        address: "::ffff:203.0.113.7",
        embedded_v4: Some("203.0.113.7"),
    },
    Ipv6Case {
        name: "ipv4-compatible",
        address: "::203.0.113.7",
        embedded_v4: None,
    },
    Ipv6Case {
        name: "nat64",
        address: "64:ff9b::203.0.113.7",
        embedded_v4: None,
    },
    Ipv6Case {
        name: "6to4",
        address: "2002:cb00:7107::1",
        embedded_v4: None,
    },
    Ipv6Case {
        name: "same /64, first",
        address: "2001:db8:1:2::1",
        embedded_v4: None,
    },
    Ipv6Case {
        name: "same /64, second",
        address: "2001:db8:1:2:ffff:ffff:ffff:fffe",
        embedded_v4: None,
    },
    Ipv6Case {
        name: "next /64",
        address: "2001:db8:1:3::1",
        embedded_v4: None,
    },
];
