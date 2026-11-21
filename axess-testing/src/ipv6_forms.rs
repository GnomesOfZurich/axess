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
/// IPv4-translated (`::ffff:0:a.b.c.d`), IPv4-compatible (`::a.b.c.d`),
/// NAT64 (`64:ff9b::/96`), the locally used NAT64 prefix (`64:ff9b:1::/48`),
/// 6to4 (`2002:a.b.c.d::/48`) and Teredo (`2001::/32`, the client address
/// inverted in the last 32 bits).
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
            name: "ipv4-translated",
            addr: Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, hi, lo),
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
        Ipv6Form {
            name: "teredo",
            // Server 192.0.2.1, flags, the obscured port, the inverted client.
            addr: Ipv6Addr::new(0x2001, 0, 0xc000, 0x0201, 0x8000, 0x63bf, !hi, !lo),
        },
    ]
}

/// `v4` under the locally used NAT64 prefix (`64:ff9b:1::/48`, RFC 8215) at
/// each prefix length RFC 6052 allows inside it (/48, /56, /64 and /96), the
/// operator's subnet byte set to `0x5a` where the length leaves room for one.
/// The IPv4 address sits where the length puts it, the `u` octet (bits 64 to
/// 71) skipped, and the suffix is zero, so its place cannot be read from the
/// address alone.
#[must_use]
pub fn local_use_nat64(v4: Ipv4Addr) -> Vec<Ipv6Form> {
    let place = |name: &'static str, prefix: &[u8], v4_at: [usize; 4]| {
        let mut octets = [0u8; 16];
        octets[..prefix.len()].copy_from_slice(prefix);
        for (at, byte) in v4_at.into_iter().zip(v4.octets()) {
            octets[at] = byte;
        }
        Ipv6Form {
            name,
            addr: Ipv6Addr::from(octets),
        }
    };
    let base = [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01];
    let sub = |extra: &[u8]| [&base[..], extra].concat();
    vec![
        place("local-use nat64 /48", &base, [6, 7, 9, 10]),
        place("local-use nat64 /56", &sub(&[0x5a]), [7, 9, 10, 11]),
        place("local-use nat64 /64", &sub(&[0x5a, 0x5a]), [9, 10, 11, 12]),
        place(
            "local-use nat64 /96",
            &sub(&[0x5a, 0x5a, 0, 0, 0, 0]),
            [12, 13, 14, 15],
        ),
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
    /// The IPv4 address a throttle keyed on the client address treats the
    /// form as, in dotted text: every form that carries an IPv4 client at a
    /// fixed place, since keyed on its /64 every client of one translator,
    /// relay or tunnel server would share one key. `None` for a plain IPv6
    /// address.
    pub embedded_v4: Option<&'static str>,
    /// The IPv4 address the form carries, in dotted text, as the egress
    /// screen judges it: every form that embeds one, whatever a throttle
    /// does with it. `None` for a plain IPv6 address.
    pub carries_v4: Option<&'static str>,
}

/// Forms of IPv6 address that matter to a key or a screen: an IPv4-mapped
/// address, an IPv4-translated one, an IPv4-compatible one, a NAT64 address,
/// a 6to4 address, a Teredo address, and two addresses in one /64 beside one
/// in the next /64. The IPv4 address carried is `203.0.113.7`, a
/// documentation address the screen refuses as `private`.
pub const IPV6_FORMS: &[Ipv6Case] = &[
    Ipv6Case {
        name: "ipv4-mapped",
        address: "::ffff:203.0.113.7",
        embedded_v4: Some("203.0.113.7"),
        carries_v4: Some("203.0.113.7"),
    },
    Ipv6Case {
        name: "ipv4-translated",
        address: "::ffff:0:203.0.113.7",
        embedded_v4: Some("203.0.113.7"),
        carries_v4: Some("203.0.113.7"),
    },
    Ipv6Case {
        name: "ipv4-compatible",
        address: "::203.0.113.7",
        embedded_v4: Some("203.0.113.7"),
        carries_v4: Some("203.0.113.7"),
    },
    Ipv6Case {
        name: "nat64",
        address: "64:ff9b::203.0.113.7",
        embedded_v4: Some("203.0.113.7"),
        carries_v4: Some("203.0.113.7"),
    },
    Ipv6Case {
        name: "6to4",
        address: "2002:cb00:7107::1",
        embedded_v4: Some("203.0.113.7"),
        carries_v4: Some("203.0.113.7"),
    },
    Ipv6Case {
        name: "teredo",
        address: "2001:0:c000:201:8000:63bf:34ff:8ef8",
        embedded_v4: Some("203.0.113.7"),
        carries_v4: Some("203.0.113.7"),
    },
    Ipv6Case {
        name: "same /64, first",
        address: "2001:db8:1:2::1",
        embedded_v4: None,
        carries_v4: None,
    },
    Ipv6Case {
        name: "same /64, second",
        address: "2001:db8:1:2:ffff:ffff:ffff:fffe",
        embedded_v4: None,
        carries_v4: None,
    },
    Ipv6Case {
        name: "next /64",
        address: "2001:db8:1:3::1",
        embedded_v4: None,
        carries_v4: None,
    },
];
