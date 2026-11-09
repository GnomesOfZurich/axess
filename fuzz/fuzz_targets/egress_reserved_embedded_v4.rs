// Invariant: if an IPv4 address is reserved, every IPv6 form that
// embeds it is reserved too, and EgressPolicy::check_url refuses it.
// Drives the real public API: axess_factors::egress::{ReservedRange, EgressPolicy}
// (module is behind axess-factors' `oidc` feature).
// While the gap is open it finds NAT64 / 6to4 / IPv4-compatible forms.
#![no_main]

use axess_factors::egress::{EgressPolicy, ReservedRange};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn embeddings(v4: Ipv4Addr, salt: u16) -> Vec<(&'static str, Ipv6Addr)> {
    let [a, b, c, d] = v4.octets();
    let hi = u16::from_be_bytes([a, b]);
    let lo = u16::from_be_bytes([c, d]);
    vec![
        ("ipv4-mapped ::ffff:a.b.c.d", v4.to_ipv6_mapped()),
        (
            "ipv4-compatible ::a.b.c.d",
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, hi, lo),
        ),
        (
            "nat64 64:ff9b::/96",
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, hi, lo),
        ),
        (
            "local nat64 64:ff9b:1::/48",
            Ipv6Addr::new(0x64, 0xff9b, 1, salt, 0, 0, hi, lo),
        ),
        (
            "6to4 2002:aabb:ccdd::/48",
            Ipv6Addr::new(0x2002, hi, lo, salt, 0, 0, 0, 1),
        ),
    ]
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }
    let v4 = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
    let salt = u16::from_be_bytes([data[4], data[5]]);
    let policy = EgressPolicy::screened();

    // Arbitrary IPv6 from the remaining bytes: check_url must never accept
    // something `of` calls reserved.
    if data.len() >= 22 {
        let mut b = [0u8; 16];
        b.copy_from_slice(&data[6..22]);
        let v6 = Ipv6Addr::from(b);
        if ReservedRange::of(IpAddr::V6(v6)).is_some() {
            assert!(
                policy
                    .check_url(&format!("https://[{v6}]/x"), "fuzz")
                    .is_err(),
                "check_url accepted reserved {v6}"
            );
        }
    }

    let Some(want) = ReservedRange::of(IpAddr::V4(v4)) else {
        return;
    };
    for (form, v6) in embeddings(v4, salt) {
        let got = ReservedRange::of(IpAddr::V6(v6));
        assert!(
            got.is_some(),
            "{form} {v6} embeds reserved {v4} ({}) but is public",
            want.name()
        );
        assert!(
            policy
                .check_url(
                    &format!("https://[{v6}]/.well-known/openid-configuration"),
                    "fuzz"
                )
                .is_err(),
            "check_url accepted {form} {v6} embedding reserved {v4}"
        );
    }
});
