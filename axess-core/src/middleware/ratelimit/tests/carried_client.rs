//! The request rate limiter's key for a client address, one IPv6 form at a
//! time: a form that carries an IPv4 client is keyed and grouped as that
//! client, an address under the locally used NAT64 prefix is keyed whole, a
//! plain IPv6 address keys on its /64, and in every case the limiter keys
//! the address as the login throttle does.
//!
//! The throttle's own tests read the forms against the throttle; what these
//! add is the limiter's side and the check that the two agree.

use crate::authn::{TenantId, Throttle, UserId};
use crate::middleware::ratelimit::keys::{ip_bucket, ip_group};
use axess_testing::ipv6_forms::{
    IPV6_FORMS, different_64_pairs, embedding_v4, local_use_nat64, same_64_pairs,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The client every form carries first.
const ONE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
/// A second client, carried in the same form.
const TWO: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);

/// The address of the form `name` in axess-testing's table that carries
/// `client`.
fn form(name: &str, client: Ipv4Addr) -> IpAddr {
    match embedding_v4(client).into_iter().find(|f| f.name == name) {
        Some(found) => IpAddr::V6(found.addr),
        None => panic!("axess-testing has no IPv6 form named {name}"),
    }
}

/// The limiter keys `address` as the login throttle does: the network the
/// throttle keeps for it is the network the limiter's bucket names.
fn assert_the_throttle_agrees(address: IpAddr, label: &str) {
    let throttle = Throttle::default()
        .subject(&TenantId::system(), &UserId::system(), Some(address))
        .address;
    let bucket = ip_bucket(address);
    let limiter: IpAddr = bucket
        .split('/')
        .next()
        .and_then(|network| network.parse().ok())
        .expect("an address bucket names its network");
    assert_eq!(
        throttle,
        Some(limiter),
        "{label}: the login throttle keys {address} on another network than {bucket}"
    );
}

/// The form `name` is bucketed and grouped as the IPv4 client it carries,
/// two clients of one gateway are two buckets, and the login throttle keys
/// the address on that same client.
fn assert_keyed_as_the_carried_client(name: &str) {
    let (one, two) = (form(name, ONE), form(name, TWO));
    let client = IpAddr::V4(ONE);
    assert_eq!(ip_bucket(one), ip_bucket(client), "{name}: bucket");
    assert_eq!(ip_group(one), ip_group(client), "{name}: group");
    assert_ne!(
        ip_bucket(one),
        ip_bucket(two),
        "{name}: two clients share one bucket"
    );
    assert_the_throttle_agrees(one, name);
}

/// An IPv4 address is its own bucket and counts against its /24.
#[test]
fn an_ipv4_address_is_its_own_bucket_in_its_slash_24() {
    let address: IpAddr = "192.0.2.7".parse().expect("an IPv4 address");
    assert_eq!(ip_bucket(address), "192.0.2.7");
    assert_eq!(ip_group(address), "192.0.2.0/24");
    assert_the_throttle_agrees(address, "ipv4");
}

#[test]
fn an_ipv4_mapped_address_is_keyed_as_its_ipv4_client() {
    assert_keyed_as_the_carried_client("ipv4-mapped");
    assert_eq!(ip_bucket(form("ipv4-mapped", ONE)), "203.0.113.7");
}

#[test]
fn an_ipv4_translated_address_is_keyed_as_its_ipv4_client() {
    assert_keyed_as_the_carried_client("ipv4-translated");
}

#[test]
fn an_ipv4_compatible_address_is_keyed_as_its_ipv4_client() {
    assert_keyed_as_the_carried_client("ipv4-compatible");
}

#[test]
fn a_nat64_address_is_keyed_as_its_ipv4_client() {
    assert_keyed_as_the_carried_client("nat64");
}

#[test]
fn a_6to4_address_is_keyed_as_its_site_ipv4_address() {
    assert_keyed_as_the_carried_client("6to4");
    // Another subnet and host of the same 6to4 site is the same client.
    let elsewhere_in_site = IpAddr::V6(Ipv6Addr::new(0x2002, 0xcb00, 0x7107, 9, 1, 2, 3, 4));
    assert_eq!(ip_bucket(elsewhere_in_site), ip_bucket(IpAddr::V4(ONE)));
}

#[test]
fn a_teredo_address_is_keyed_as_its_ipv4_client() {
    assert_keyed_as_the_carried_client("teredo");
}

/// Under the locally used NAT64 prefix the client sits where the operator's
/// prefix length puts it, so the limiter, like the login throttle, keys the
/// whole address and groups it on its /120: two clients are two buckets.
#[test]
fn a_local_use_nat64_address_is_keyed_whole_as_the_login_throttle_keys_it() {
    let name = "local-use nat64";
    let (one, two) = (form(name, ONE), form(name, TWO));
    assert_eq!(ip_bucket(one), format!("{one}/128"));
    assert_eq!(ip_group(one), "64:ff9b:1:1234::cb00:7100/120");
    assert_ne!(ip_bucket(one), ip_bucket(two));
    assert_ne!(ip_group(one), ip_group(two));
    assert_the_throttle_agrees(one, name);
}

/// At every prefix length an operator may choose inside the locally used
/// NAT64 prefix, the whole-address key gives each client a bucket of its
/// own: two clients never share one, even two whose last 32 bits (the zero
/// suffix below /96) are equal, and the throttle agrees.
#[test]
fn a_local_use_nat64_address_is_one_bucket_per_client_at_every_prefix_length() {
    let clients = [ONE, TWO, Ipv4Addr::new(203, 0, 113, 8)];
    let per_client: Vec<_> = clients.iter().map(|c| local_use_nat64(*c)).collect();
    for (at, first) in per_client[0].iter().enumerate() {
        let buckets: Vec<String> = per_client
            .iter()
            .map(|forms| ip_bucket(IpAddr::V6(forms[at].addr)))
            .collect();
        for (i, bucket) in buckets.iter().enumerate() {
            assert!(bucket.ends_with("/128"), "{}: {bucket}", first.name);
            for other in &buckets[i + 1..] {
                assert_ne!(bucket, other, "{}: two clients share one", first.name);
            }
        }
        assert_the_throttle_agrees(IpAddr::V6(first.addr), first.name);
    }
}

/// Every form in axess-testing's text table that carries a client is keyed
/// as that client by the limiter, and the throttle agrees.
#[test]
fn every_text_form_that_carries_a_client_is_keyed_as_it() {
    for case in IPV6_FORMS {
        let Some(carried) = case.embedded_v4 else {
            continue;
        };
        let carried: IpAddr = carried.parse().expect("an IPv4 address in the table");
        let address: IpAddr = case.address.parse().expect("an IPv6 address in the table");
        assert_eq!(ip_bucket(address), ip_bucket(carried), "{}", case.name);
        assert_eq!(ip_group(address), ip_group(carried), "{}", case.name);
        assert_the_throttle_agrees(address, case.name);
    }
}

/// A plain IPv6 address is keyed on its /64 and grouped on its /48, and the
/// login throttle keys it on the same /64.
#[test]
fn a_plain_ipv6_address_still_keys_on_its_slash_64() {
    for (a, b) in same_64_pairs() {
        let (a, b) = (IpAddr::V6(a), IpAddr::V6(b));
        assert_eq!(ip_bucket(a), ip_bucket(b), "{a} and {b}");
        assert!(ip_bucket(a).ends_with("/64"), "{a}");
        assert_the_throttle_agrees(a, "same /64");
    }
    for (a, b) in different_64_pairs() {
        assert_ne!(
            ip_bucket(IpAddr::V6(a)),
            ip_bucket(IpAddr::V6(b)),
            "{a} and {b}"
        );
    }
    for case in IPV6_FORMS.iter().filter(|c| c.embedded_v4.is_none()) {
        let address: IpAddr = case.address.parse().expect("an IPv6 address in the table");
        assert!(ip_bucket(address).ends_with("/64"), "{}", case.name);
        assert!(ip_group(address).ends_with("/48"), "{}", case.name);
        assert_the_throttle_agrees(address, case.name);
    }
    assert_plain("2001:db8:1:2::1", "2001:db8:1:2::/64", "2001:db8:1::/48");
}

/// An address one bit outside a prefix that carries a client, the last bit
/// of the prefix flipped, is a plain IPv6 address: keyed on its /64, grouped
/// on its /48, the throttle agreeing. The unspecified and loopback addresses
/// sit inside the IPv4-compatible prefix but carry no client, and are read
/// the same way.
#[test]
fn an_address_one_bit_outside_each_carrying_prefix_keys_on_its_slash_64() {
    for (address, bucket, group) in [
        // IPv4-mapped `::ffff:0:0/96` and IPv4-translated `::ffff:0:0:0/96`.
        ("::fffe:cb00:7107", "::/64", "::/48"),
        ("::ffff:1:cb00:7107", "::/64", "::/48"),
        // IPv4-compatible `::/96`, and the two addresses inside it that are
        // not clients.
        ("::1:cb00:7107", "::/64", "::/48"),
        ("::", "::/64", "::/48"),
        ("::1", "::/64", "::/48"),
        // NAT64 `64:ff9b::/96`.
        ("64:ff9b::1:cb00:7107", "64:ff9b::/64", "64:ff9b::/48"),
        // The locally used NAT64 prefix `64:ff9b:1::/48`, from below and
        // from above.
        ("64:ff9b:0:1::1", "64:ff9b:0:1::/64", "64:ff9b::/48"),
        ("64:ff9b:3::1", "64:ff9b:3::/64", "64:ff9b:3::/48"),
        // Teredo `2001::/32` and 6to4 `2002::/16`.
        ("2001:1::1", "2001:1::/64", "2001:1::/48"),
        ("2003::1", "2003::/64", "2003::/48"),
    ] {
        assert_plain(address, bucket, group);
    }
}

/// `address` is bucketed on `bucket` and grouped on `group`, and the throttle
/// agrees.
fn assert_plain(address: &str, bucket: &str, group: &str) {
    let parsed: IpAddr = address.parse().expect("an IPv6 address");
    assert_eq!(ip_bucket(parsed), bucket, "{address}");
    assert_eq!(ip_group(parsed), group, "{address}");
    assert_the_throttle_agrees(parsed, address);
}
