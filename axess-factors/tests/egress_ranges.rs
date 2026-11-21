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

/// The NAT64 prefix is `64:ff9b`, both groups: an address that has only one
/// of the two is not a NAT64 address, and its last 32 bits are not judged as
/// an IPv4 address.
#[test]
fn an_address_with_half_of_the_nat64_prefix_is_not_judged_as_nat64() {
    for ip in ["2606:ff9b::7f00:1", "64:ff9a::7f00:1", "64:1::a9fe:a9fe"] {
        assert_eq!(range(ip), None, "{ip} embeds no IPv4 address");
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

/// The table of forms and the screen agree: every form the table says
/// carries an IPv4 address is judged as that address.
#[test]
fn every_form_the_table_says_carries_an_ipv4_address_is_judged_as_that_address() {
    use axess_testing::ipv6_forms::IPV6_FORMS;
    for case in IPV6_FORMS.iter().filter(|c| c.carries_v4.is_some()) {
        let carried = case.carries_v4.expect("filtered");
        assert_eq!(
            range(case.address),
            range(carried),
            "{}: {} is not judged as {carried}",
            case.name,
            case.address
        );
        assert!(
            range(case.address).is_some(),
            "{}: the carried address is a documentation address, which is not public",
            case.name
        );
    }
}

/// Every embedding form of a reserved IPv4 address is refused under that
/// address's own name, for each reserved range the screen knows.
#[test]
fn every_embedding_form_of_a_reserved_ipv4_address_is_refused_by_its_name() {
    use axess_testing::ipv6_forms::embedding_v4;
    for (v4, want) in [
        ("127.0.0.1", ReservedRange::Loopback),
        ("10.0.0.1", ReservedRange::Private),
        ("169.254.169.254", ReservedRange::Metadata),
        ("169.254.0.9", ReservedRange::LinkLocal),
        ("100.64.0.1", ReservedRange::Shared),
    ] {
        for form in embedding_v4(v4.parse().unwrap()) {
            assert_eq!(
                ReservedRange::of(std::net::IpAddr::V6(form.addr)),
                Some(want),
                "{} of {v4}: {}",
                form.name,
                form.addr
            );
        }
    }
}

/// The IPv4-translated form is the address it carries; Teredo is the client
/// it carries when that one is reserved, and private otherwise, since the
/// prefix is a tunnel to a host behind a NAT and never a public server.
#[test]
fn translated_and_teredo_forms_are_screened() {
    assert_eq!(
        range("::ffff:0:169.254.169.254"),
        Some(ReservedRange::Metadata)
    );
    assert_eq!(range("::ffff:0:10.0.0.1"), Some(ReservedRange::Private));
    assert_eq!(
        range("::ffff:0:8.8.8.8"),
        None,
        "a public translated address stays reachable"
    );
    assert_eq!(
        range("2001:0:c000:201:8000:63bf:5601:5601"),
        Some(ReservedRange::Metadata),
        "a Teredo client at the metadata address"
    );
    assert_eq!(
        range("2001:0:c000:201:8000:63bf:f7f7:f7f7"),
        Some(ReservedRange::Private),
        "a Teredo tunnel to a public client is still not a public server"
    );
    assert!(
        EgressPolicy::screened()
            .check_url("https://[::ffff:0:169.254.169.254]/", "issuer URL")
            .is_err()
    );
}
