//! Tests for the request-context helpers and the trusted-proxy
//! extraction in [`super`].

use super::*;
use axum::http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn ip_from_headers_reads_x_real_ip() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Real-IP", "203.0.113.5".parse().unwrap());
    assert_eq!(
        ip_from_headers_untrusted(&headers),
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)))
    );
}

#[test]
fn ip_from_headers_falls_back_to_x_forwarded_for_first_entry() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Forwarded-For",
        "198.51.100.10, 10.0.0.1".parse().unwrap(),
    );
    assert_eq!(
        ip_from_headers_untrusted(&headers),
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))
    );
}

#[test]
fn ip_from_headers_returns_none_when_neither_header_present() {
    let headers = HeaderMap::new();
    assert!(ip_from_headers_untrusted(&headers).is_none());
}

#[test]
fn trusted_proxies_loopback_only_contains_v4_and_v6_loopback() {
    let trusted = TrustedProxies::loopback_only();
    assert!(trusted.trusts(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(trusted.trusts(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn trusted_proxies_rejects_unrelated_peer() {
    let trusted = TrustedProxies::loopback_only();
    assert!(!trusted.trusts(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
}

#[test]
fn trusted_proxies_empty_set_trusts_nothing() {
    let trusted = TrustedProxies::new([]);
    assert!(!trusted.trusts(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

// ── CIDR trust ──────────────────────────────────────────────────────────

#[test]
fn trusted_proxies_matches_inside_a_v4_cidr_and_rejects_outside() {
    let trusted = TrustedProxies::from_cidrs(["10.0.0.0/8"]).expect("valid CIDR");
    assert!(trusted.trusts("10.0.0.1".parse().unwrap()));
    assert!(trusted.trusts("10.255.255.254".parse().unwrap()));
    assert!(!trusted.trusts("11.0.0.1".parse().unwrap()));
    assert!(!trusted.trusts("9.255.255.255".parse().unwrap()));
}

#[test]
fn trusted_proxies_cidr_respects_the_prefix_boundary() {
    // /31 is two addresses: .2 and .3. Pin both edges so an off-by-one
    // in the shift cannot pass.
    let trusted = TrustedProxies::from_cidrs(["192.0.2.2/31"]).expect("valid CIDR");
    assert!(trusted.trusts("192.0.2.2".parse().unwrap()));
    assert!(trusted.trusts("192.0.2.3".parse().unwrap()));
    assert!(!trusted.trusts("192.0.2.1".parse().unwrap()));
    assert!(!trusted.trusts("192.0.2.4".parse().unwrap()));
}

#[test]
fn trusted_proxies_cidr_prefix_zero_matches_the_whole_family() {
    // Shifting by the full width is undefined, so /0 takes its own path.
    let v4 = TrustedProxies::from_cidrs(["0.0.0.0/0"]).expect("valid CIDR");
    assert!(v4.trusts("203.0.113.9".parse().unwrap()));
    assert!(
        !v4.trusts("2001:db8::1".parse().unwrap()),
        "family must not cross"
    );

    let v6 = TrustedProxies::from_cidrs(["::/0"]).expect("valid CIDR");
    assert!(v6.trusts("2001:db8::1".parse().unwrap()));
    assert!(
        !v6.trusts("203.0.113.9".parse().unwrap()),
        "family must not cross"
    );
}

#[test]
fn trusted_proxies_matches_a_v6_cidr() {
    let trusted = TrustedProxies::from_cidrs(["2001:db8::/32"]).expect("valid CIDR");
    assert!(trusted.trusts("2001:db8::1".parse().unwrap()));
    assert!(trusted.trusts("2001:db8:ffff::1".parse().unwrap()));
    assert!(!trusted.trusts("2001:db9::1".parse().unwrap()));
}

#[test]
fn trusted_proxies_composes_exact_addresses_with_ranges() {
    let trusted = TrustedProxies::new(["203.0.113.9".parse().unwrap()])
        .with_cidrs(["10.0.0.0/8"])
        .expect("valid CIDR");
    assert!(trusted.trusts("203.0.113.9".parse().unwrap()));
    assert!(trusted.trusts("10.1.2.3".parse().unwrap()));
    assert!(!trusted.trusts("198.51.100.1".parse().unwrap()));
}

#[test]
fn cidr_parse_rejects_malformed_specs() {
    assert!(matches!(
        TrustedProxies::from_cidrs(["10.0.0.0"]),
        Err(CidrParseError::MissingPrefix(_))
    ));
    assert!(matches!(
        TrustedProxies::from_cidrs(["not-an-ip/8"]),
        Err(CidrParseError::Address(_))
    ));
    assert!(matches!(
        TrustedProxies::from_cidrs(["10.0.0.0/x"]),
        Err(CidrParseError::Prefix(_))
    ));
    // 33 bits of prefix on a 32-bit family would silently match nothing.
    assert!(matches!(
        TrustedProxies::from_cidrs(["10.0.0.0/33"]),
        Err(CidrParseError::Prefix(_))
    ));
}

// ── Forwarded-header extraction ─────────────────────────────────────────

fn xff(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", value.parse().unwrap());
    headers
}

fn proxy() -> IpAddr {
    "10.0.0.1".parse().unwrap()
}

fn trusted_proxy_set() -> TrustedProxies {
    TrustedProxies::from_cidrs(["10.0.0.0/8"]).expect("valid CIDR")
}

#[test]
fn untrusted_peer_ignores_forwarded_headers_entirely() {
    let peer: IpAddr = "203.0.113.9".parse().unwrap();
    let got = ip_from_headers_trusted(&xff("198.51.100.1"), peer, &trusted_proxy_set());
    assert_eq!(
        got, peer,
        "a peer we do not trust cannot name its own address"
    );
}

#[test]
fn client_prepended_forwarded_entry_does_not_win() {
    // The attack: the client sends its own X-Forwarded-For and the proxy
    // faithfully appends the address it saw. Taking the leftmost entry
    // returns the attacker's choice even though the proxy behaved.
    let got = ip_from_headers_trusted(
        &xff("192.0.2.5, 203.0.113.9"),
        proxy(),
        &trusted_proxy_set(),
    );
    assert_eq!(
        got,
        "203.0.113.9".parse::<IpAddr>().unwrap(),
        "must take the rightmost untrusted entry, not the client-supplied one"
    );
}

#[test]
fn walks_back_past_a_chain_of_trusted_hops() {
    // lb -> cdn -> app, both inside 10/8: the client is the first entry
    // from the right that is not one of ours.
    let got = ip_from_headers_trusted(
        &xff("192.0.2.5, 203.0.113.9, 10.0.0.7, 10.0.0.8"),
        proxy(),
        &trusted_proxy_set(),
    );
    assert_eq!(got, "203.0.113.9".parse::<IpAddr>().unwrap());
}

#[test]
fn all_entries_trusted_means_the_request_started_inside() {
    let got = ip_from_headers_trusted(&xff("10.0.0.7, 10.0.0.8"), proxy(), &trusted_proxy_set());
    assert_eq!(got, proxy());
}

#[test]
fn malformed_entry_stops_the_walk_rather_than_trusting_past_it() {
    // Once one hop's contribution cannot be parsed, which hop wrote what
    // is unknowable, so nothing further left may be believed.
    let got = ip_from_headers_trusted(
        &xff("203.0.113.9, junk, 10.0.0.8"),
        proxy(),
        &trusted_proxy_set(),
    );
    assert_eq!(got, proxy());
}

#[test]
fn forwarded_for_beats_a_forged_real_ip() {
    // A proxy that appends X-Forwarded-For but does not strip a
    // client-supplied X-Real-IP must not let the latter win.
    let mut headers = xff("203.0.113.9");
    headers.insert("X-Real-IP", "192.0.2.5".parse().unwrap());
    let got = ip_from_headers_trusted(&headers, proxy(), &trusted_proxy_set());
    assert_eq!(got, "203.0.113.9".parse::<IpAddr>().unwrap());
}

#[test]
fn real_ip_is_used_only_when_there_is_no_forwarded_for() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Real-IP", "203.0.113.9".parse().unwrap());
    let got = ip_from_headers_trusted(&headers, proxy(), &trusted_proxy_set());
    assert_eq!(got, "203.0.113.9".parse::<IpAddr>().unwrap());
}

#[test]
fn no_forwarded_headers_yields_the_peer() {
    let got = ip_from_headers_trusted(&HeaderMap::new(), proxy(), &trusted_proxy_set());
    assert_eq!(got, proxy());
}

#[test]
fn second_forwarded_for_line_cannot_hide_the_real_client() {
    // The bypass this walk would otherwise have. A client sends its own
    // `X-Forwarded-For`; the proxy adds a *separate* field line instead of
    // appending to the existing one. `HeaderMap::get` returns only the
    // first line, so a walk over it alone sees nothing but forged entries
    // and hands back whatever the attacker chose.
    let mut headers = axum::http::HeaderMap::new();
    headers.append("X-Forwarded-For", "9.9.9.9".parse().unwrap()); // client-supplied
    headers.append("X-Forwarded-For", "203.0.113.7".parse().unwrap()); // proxy-appended

    let proxy: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let trusted = TrustedProxies::new([proxy]);

    assert_eq!(
        ip_from_headers_trusted(&headers, proxy, &trusted),
        "203.0.113.7".parse::<std::net::IpAddr>().unwrap(),
        "the rightmost untrusted entry across ALL field lines is the client"
    );
}

#[test]
fn repeated_real_ip_lines_are_not_believed() {
    // Two lines means something appended rather than overwrote, so the
    // first is whatever the client sent. Fall back to the peer.
    let mut headers = axum::http::HeaderMap::new();
    headers.append("X-Real-IP", "9.9.9.9".parse().unwrap());
    headers.append("X-Real-IP", "203.0.113.7".parse().unwrap());

    let proxy: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let trusted = TrustedProxies::new([proxy]);

    assert_eq!(
        ip_from_headers_trusted(&headers, proxy, &trusted),
        proxy,
        "an ambiguous X-Real-IP must not be trusted"
    );
}

#[test]
fn single_real_ip_line_is_still_honoured() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Real-IP", "203.0.113.7".parse().unwrap());

    let proxy: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let trusted = TrustedProxies::new([proxy]);

    assert_eq!(
        ip_from_headers_trusted(&headers, proxy, &trusted),
        "203.0.113.7".parse::<std::net::IpAddr>().unwrap()
    );
}

#[test]
fn cidr_with_host_bits_is_rejected_not_widened() {
    // `10.0.0.5/8` reads like one host and means sixteen million. In a
    // list that decides whose headers are believed, that must not parse.
    let err = TrustedProxies::from_cidrs(["10.0.0.5/8"]).unwrap_err();
    assert!(
        matches!(err, CidrParseError::HostBitsSet(_)),
        "expected HostBitsSet, got {err:?}"
    );

    assert!(TrustedProxies::from_cidrs(["2001:db8::1/32"]).is_err());

    // The two unambiguous spellings both parse.
    assert!(TrustedProxies::from_cidrs(["10.0.0.0/8"]).is_ok());
    assert!(TrustedProxies::from_cidrs(["10.0.0.5/32"]).is_ok());
    assert!(TrustedProxies::from_cidrs(["2001:db8::/32"]).is_ok());
    assert!(TrustedProxies::from_cidrs(["::/0"]).is_ok());
}
