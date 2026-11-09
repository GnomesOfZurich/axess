#![cfg(feature = "oidc")]
//! Addresses that are not public even though they do not look reserved: the
//! IPv6 forms that carry an IPv4 address, and the IPv4 special-purpose ranges.

use axess_factors::egress::{EgressPolicy, ReservedRange};
use std::net::IpAddr;

fn range(ip: &str) -> Option<ReservedRange> {
    ReservedRange::of(ip.parse::<IpAddr>().unwrap())
}

#[test]
fn ipv6_forms_embedding_reserved_ipv4_are_screened() {
    for (ip, want) in [
        ("64:ff9b::7f00:1", ReservedRange::Loopback),
        ("64:ff9b::a9fe:a9fe", ReservedRange::Metadata),
        ("64:ff9b::a00:1", ReservedRange::Private),
        ("64:ff9b:1::a00:1", ReservedRange::Private),
        ("2002:7f00:1::", ReservedRange::Loopback),
        ("2002:a9fe:a9fe::1", ReservedRange::Metadata),
        ("2002:c0a8:1::", ReservedRange::Private),
        ("::127.0.0.1", ReservedRange::Loopback),
        ("::10.0.0.1", ReservedRange::Private),
        ("::169.254.169.254", ReservedRange::Metadata),
    ] {
        assert_eq!(range(ip), Some(want), "{ip}");
    }
}

#[test]
fn ipv6_forms_embedding_a_public_ipv4_stay_reachable() {
    for ip in ["64:ff9b::808:808", "2002:808:808::", "2606:4700::1111"] {
        assert_eq!(range(ip), None, "{ip} is public");
    }
}

#[test]
fn a_screened_policy_refuses_urls_naming_embedded_ipv4_hosts() {
    let policy = EgressPolicy::screened();
    for bad in [
        "https://[64:ff9b::a9fe:a9fe]/",
        "https://[2002:7f00:1::]/",
        "https://[::7f00:1]/",
        "https://[::10.0.0.1]/",
    ] {
        assert!(policy.check_url(bad, "issuer URL").is_err(), "{bad}");
    }
}

#[test]
fn the_ipv4_special_purpose_ranges_are_not_public() {
    for ip in [
        "192.0.0.8",
        "192.0.0.255",
        "198.18.0.1",
        "198.19.255.255",
        "240.0.0.1",
        "254.1.2.3",
        "192.0.2.1",
        "198.51.100.7",
        "203.0.113.200",
    ] {
        assert!(range(ip).is_some(), "{ip} is special-purpose, not public");
    }
    for ip in ["192.0.1.1", "198.17.255.255", "198.20.0.1", "203.0.114.1"] {
        assert_eq!(range(ip), None, "{ip} is public");
    }
    assert_eq!(range("255.255.255.255"), Some(ReservedRange::Multicast));
}
