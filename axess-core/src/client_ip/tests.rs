//! Tests for the request-context helpers and the trusted-proxy
//! extraction in [`super`].

use super::*;

/// The walk with a peer that is known, which is most of this file.
///
/// `TrustedProxies::client_ip` takes `Option<IpAddr>` because a unix
/// socket has no peer. Where there is one the answer is always `Some`,
/// and the `expect` pins that: a `None` here would mean the method had
/// started losing an address it was handed.
fn ip_from_headers_trusted(
    headers: &axum::http::HeaderMap,
    peer: std::net::IpAddr,
    trusted: &TrustedProxies,
) -> std::net::IpAddr {
    trusted
        .client_ip(headers, Some(peer))
        .get()
        .expect("a known peer always resolves to an address")
}
use axum::http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn trusted_proxies_loopback_only_contains_v4_and_v6_loopback() {
    let trusted = TrustedProxies::loopback_only();
    assert!(trusted.trusts_hop(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(trusted.trusts_hop(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn trusted_proxies_rejects_unrelated_peer() {
    let trusted = TrustedProxies::loopback_only();
    assert!(!trusted.trusts_hop(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
}

#[test]
fn trusted_proxies_empty_set_trusts_nothing() {
    let trusted = TrustedProxies::new([]);
    assert!(!trusted.trusts_hop(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

// ── CIDR trust ──────────────────────────────────────────────────────────

#[test]
fn trusted_proxies_matches_inside_a_v4_cidr_and_rejects_outside() {
    let trusted = TrustedProxies::from_cidrs(["10.0.0.0/8"]).expect("valid CIDR");
    assert!(trusted.trusts_hop("10.0.0.1".parse().unwrap()));
    assert!(trusted.trusts_hop("10.255.255.254".parse().unwrap()));
    assert!(!trusted.trusts_hop("11.0.0.1".parse().unwrap()));
    assert!(!trusted.trusts_hop("9.255.255.255".parse().unwrap()));
}

#[test]
fn trusted_proxies_cidr_respects_the_prefix_boundary() {
    // /31 is two addresses: .2 and .3. Pin both edges so an off-by-one
    // in the shift cannot pass.
    let trusted = TrustedProxies::from_cidrs(["192.0.2.2/31"]).expect("valid CIDR");
    assert!(trusted.trusts_hop("192.0.2.2".parse().unwrap()));
    assert!(trusted.trusts_hop("192.0.2.3".parse().unwrap()));
    assert!(!trusted.trusts_hop("192.0.2.1".parse().unwrap()));
    assert!(!trusted.trusts_hop("192.0.2.4".parse().unwrap()));
}

#[test]
fn trusted_proxies_cidr_prefix_zero_matches_the_whole_family() {
    // Shifting by the full width is undefined, so /0 takes its own path.
    let v4 = TrustedProxies::from_cidrs(["0.0.0.0/0"]).expect("valid CIDR");
    assert!(v4.trusts_hop("203.0.113.9".parse().unwrap()));
    assert!(
        !v4.trusts_hop("2001:db8::1".parse().unwrap()),
        "family must not cross"
    );

    let v6 = TrustedProxies::from_cidrs(["::/0"]).expect("valid CIDR");
    assert!(v6.trusts_hop("2001:db8::1".parse().unwrap()));
    assert!(
        !v6.trusts_hop("203.0.113.9".parse().unwrap()),
        "family must not cross"
    );
}

#[test]
fn trusted_proxies_matches_a_v6_cidr() {
    let trusted = TrustedProxies::from_cidrs(["2001:db8::/32"]).expect("valid CIDR");
    assert!(trusted.trusts_hop("2001:db8::1".parse().unwrap()));
    assert!(trusted.trusts_hop("2001:db8:ffff::1".parse().unwrap()));
    assert!(!trusted.trusts_hop("2001:db9::1".parse().unwrap()));
}

#[test]
fn trusted_proxies_composes_exact_addresses_with_ranges() {
    let trusted = TrustedProxies::new(["203.0.113.9".parse().unwrap()])
        .with_cidrs(["10.0.0.0/8"])
        .expect("valid CIDR");
    assert!(trusted.trusts_hop("203.0.113.9".parse().unwrap()));
    assert!(trusted.trusts_hop("10.1.2.3".parse().unwrap()));
    assert!(!trusted.trusts_hop("198.51.100.1".parse().unwrap()));
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
    // client-supplied X-Real-IP must not let the latter win, even where
    // the operator has said the proxy overwrites it.
    let mut headers = xff("203.0.113.9");
    headers.insert("X-Real-IP", "192.0.2.5".parse().unwrap());
    let trusted = trusted_proxy_set().proxy_overwrites_real_ip();
    let got = ip_from_headers_trusted(&headers, proxy(), &trusted);
    assert_eq!(got, "203.0.113.9".parse::<IpAddr>().unwrap());
}

#[test]
fn real_ip_is_not_read_without_the_operator_assertion() {
    // The default, and the case that matters: a trusted peer that sets
    // neither forwarded header leaves `X-Real-IP` entirely in the
    // caller's hands. Believing it would hand an attacker the audit
    // address, the rate-limit bucket and the tenant IP policy in one
    // header they can rotate per request. Caddy is such a proxy: it never
    // sets `X-Real-IP` at all.
    let mut headers = HeaderMap::new();
    headers.insert("X-Real-IP", "203.0.113.9".parse().unwrap());
    let got = ip_from_headers_trusted(&headers, proxy(), &trusted_proxy_set());
    assert_eq!(
        got,
        proxy(),
        "an unasserted X-Real-IP must lose to the peer"
    );
}

#[test]
fn real_ip_is_read_where_the_operator_asserts_the_proxy_overwrites_it() {
    // nginx with `proxy_set_header X-Real-IP $remote_addr`, where the
    // value cannot be caller-supplied because the proxy replaces it.
    let mut headers = HeaderMap::new();
    headers.insert("X-Real-IP", "203.0.113.9".parse().unwrap());
    let trusted = trusted_proxy_set().proxy_overwrites_real_ip();
    let got = ip_from_headers_trusted(&headers, proxy(), &trusted);
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
    let trusted = TrustedProxies::new([proxy]).proxy_overwrites_real_ip();

    assert_eq!(
        ip_from_headers_trusted(&headers, proxy, &trusted),
        proxy,
        "an ambiguous X-Real-IP must not be trusted even where the \
         operator asserted the proxy overwrites it"
    );
}

#[test]
fn the_real_ip_assertion_survives_composition() {
    // `with_cidrs` rebuilds the set, and dropping the flag there would
    // quietly change what a configured deployment believes.
    let proxy: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let trusted = TrustedProxies::new([proxy])
        .proxy_overwrites_real_ip()
        .with_cidrs(["192.0.2.0/24"])
        .expect("valid cidr");

    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Real-IP", "203.0.113.7".parse().unwrap());

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

// ── The resolved seam ────────────────────────────────────────────────────────
//
// The walk itself is covered above. These cover the layer around it: what
// reaches a handler, and what happens where the layer is absent.

mod resolved {
    use super::super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use std::net::SocketAddr;

    fn parts_with(peer: Option<&str>, headers: &[(&str, &str)]) -> axum::http::request::Parts {
        let mut b = Request::builder();
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut req = b.body(Body::empty()).unwrap();
        if let Some(p) = peer {
            let addr: SocketAddr = format!("{p}:51234").parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
        }
        req.into_parts().0
    }

    /// A route mounted outside the layer answers "unknown" rather than
    /// reaching for a header. The forged values here are what the old
    /// `ForwardedIp` extractor would have believed.
    #[tokio::test]
    async fn without_the_layer_there_is_no_address() {
        let mut p = parts_with(
            Some("203.0.113.9"),
            &[("X-Real-IP", "8.8.8.8"), ("X-Forwarded-For", "8.8.4.4")],
        );
        let ip = ClientIp::from_request_parts(&mut p, &()).await.unwrap();
        assert_eq!(ip.get(), None);
    }

    /// What the layer put in the extensions is what the handler reads.
    #[tokio::test]
    async fn the_layer_s_answer_reaches_the_handler() {
        let mut p = parts_with(None, &[]);
        p.extensions
            .insert(ClientIp::for_test(Some("198.51.100.7".parse().unwrap())));
        let ip = ClientIp::from_request_parts(&mut p, &()).await.unwrap();
        assert_eq!(ip.get(), Some("198.51.100.7".parse().unwrap()));
    }

    /// `resolve` ignores an untrusted peer's headers, so one caller
    /// rotating `X-Real-IP` resolves to one address rather than many.
    #[tokio::test]
    async fn rotating_a_forged_header_does_not_move_the_answer() {
        let trusted = TrustedProxies::loopback_only();
        let peer: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Real-IP", "8.8.8.8".parse().unwrap());
        let first = trusted.client_ip(&headers, Some(peer)).get().unwrap();
        headers.insert("X-Real-IP", "9.9.9.9".parse().unwrap());
        let second = trusted.client_ip(&headers, Some(peer)).get().unwrap();
        assert_eq!(first, peer);
        assert_eq!(first, second);
    }
}

// ── Peer trust and chain trust are different questions ───────────────────────
//
// An address set answers both only while the proxies are enumerable. On a
// platform whose ingress has no address you can pin, the operator can still
// say something true and checkable: nothing reaches this process except
// through my infrastructure.

mod private_transport {
    use super::super::*;
    use axum::http::HeaderMap;

    fn xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("X-Forwarded-For", value.parse().unwrap());
        h
    }

    /// The whole point: an unpinnable ingress appended the real client on
    /// the right, and nothing in the chain is vouched for, so the rightmost
    /// entry is the answer rather than the peer.
    #[test]
    fn rightmost_entry_wins_when_the_peer_cannot_be_named() {
        let trusted = TrustedProxies::private_transport();
        let peer: std::net::IpAddr = "100.64.3.9".parse().unwrap(); // platform NAT
        let headers = xff("8.8.8.8, 198.51.100.7");
        assert_eq!(
            trusted.client_ip(&headers, Some(peer)).get().unwrap(),
            "198.51.100.7".parse::<std::net::IpAddr>().unwrap(),
            "the ingress appends the client last; a prepended entry must not win"
        );
    }

    /// Trusting every peer is not the same as trusting every hop. An
    /// address set that trusted both would walk the whole chain and fall
    /// back to the peer, which is the degenerate answer this replaces.
    #[test]
    fn trusting_the_peer_does_not_trust_the_chain() {
        let trusted = TrustedProxies::private_transport();
        let peer: std::net::IpAddr = "100.64.3.9".parse().unwrap();
        assert!(trusted.trusts_peer(peer));
        assert!(!trusted.trusts_hop(peer));
        assert!(!trusted.trusts_hop("198.51.100.7".parse().unwrap()));
    }

    /// A named hop in front of the unpinnable one composes: the walk steps
    /// past the CDN and returns the entry before it.
    #[test]
    fn a_named_hop_composes_with_an_unnamed_peer() {
        let trusted = TrustedProxies::private_transport()
            .with_cidrs(["203.0.113.0/24"])
            .expect("valid cidr");
        let peer: std::net::IpAddr = "100.64.3.9".parse().unwrap();
        let headers = xff("8.8.8.8, 198.51.100.7, 203.0.113.5");
        assert_eq!(
            trusted.client_ip(&headers, Some(peer)).get().unwrap(),
            "198.51.100.7".parse::<std::net::IpAddr>().unwrap(),
        );
    }

    /// With no forwarded header there is nothing to read, and the peer is
    /// the only address there is.
    #[test]
    fn no_chain_means_the_peer() {
        let trusted = TrustedProxies::private_transport();
        let peer: std::net::IpAddr = "100.64.3.9".parse().unwrap();
        assert_eq!(
            trusted
                .client_ip(&HeaderMap::new(), Some(peer))
                .get()
                .unwrap(),
            peer
        );
    }

    /// The default is unchanged: an enumerated set still refuses a peer it
    /// does not know, so nothing about this is opt-out.
    #[test]
    fn enumerated_sets_are_unaffected() {
        let trusted = TrustedProxies::loopback_only();
        let peer: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        assert!(!trusted.trusts_peer(peer));
        assert_eq!(
            trusted
                .client_ip(&xff("8.8.8.8"), Some(peer))
                .get()
                .unwrap(),
            peer
        );
    }
}

// ── Transports with no peer address ──────────────────────────────────────────
//
// A unix-domain socket has no IP peer, so an address set has nothing to
// match. It is also the strongest form of the private-transport premise:
// the socket is reachable through the filesystem and not the network, so
// "nothing reaches this process except through my infrastructure" is
// enforced by the transport rather than asserted by the operator.

mod no_peer {
    use super::super::*;
    use axum::http::HeaderMap;

    fn xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("X-Forwarded-For", value.parse().unwrap());
        h
    }

    #[test]
    fn private_transport_resolves_without_a_peer() {
        let trusted = TrustedProxies::private_transport();
        assert_eq!(
            trusted.client_ip(&xff("8.8.8.8, 198.51.100.7"), None).get(),
            Some("198.51.100.7".parse().unwrap()),
        );
    }

    /// An address set cannot be compared against a peer that does not
    /// exist, so there is nothing checkable and the answer is no address.
    /// Believing the header here is the forgery the module prevents.
    #[test]
    fn an_address_set_without_a_peer_yields_nothing() {
        let trusted = TrustedProxies::loopback_only();
        assert_eq!(
            trusted.client_ip(&xff("8.8.8.8, 198.51.100.7"), None).get(),
            None,
        );
    }

    #[test]
    fn no_peer_and_no_chain_yields_nothing() {
        let trusted = TrustedProxies::private_transport();
        assert_eq!(trusted.client_ip(&HeaderMap::new(), None).get(), None);
    }

    /// With a peer present the answer is exactly what the peer-taking
    /// function gives, so the two entry points cannot drift.
    #[test]
    fn with_a_peer_it_agrees_with_the_peer_taking_form() {
        let trusted = TrustedProxies::loopback_only();
        let peer: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let headers = xff("8.8.8.8, 198.51.100.7");
        assert_eq!(
            trusted.client_ip(&headers, Some(peer)).get(),
            Some("198.51.100.7".parse().unwrap()),
        );
    }
}

// ── The address axess cannot resolve for you ─────────────────────────────────

mod resolved_elsewhere {
    use super::super::*;

    /// A front end whose header axess does not parse, authenticated by
    /// something axess cannot see. The value has to be able to reach the
    /// audit row and the rate-limit key, or the deployment has no way to
    /// record where a request came from.
    #[test]
    fn an_address_resolved_elsewhere_reaches_the_consumers() {
        let ip: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(ClientIp::resolved(Some(ip)).get(), Some(ip));
    }

    /// Saying "no address" stays possible, for a caller that ran its own
    /// resolution and came up with nothing.
    #[test]
    fn resolving_to_nothing_is_expressible() {
        assert_eq!(ClientIp::resolved(None).get(), None);
        assert_eq!(ClientIp::default().get(), None);
    }
}

// ── Provenance ───────────────────────────────────────────────────────────────
//
// The address alone does not say what it is worth, and it cannot
// distinguish the two silent failures: a missing layer and a trusted set
// that does not name the proxy in front. Both produce "everyone in one
// bucket" or "every row null" and look identical from the outside.

mod provenance {
    use super::super::*;
    use axum::http::HeaderMap;

    fn xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("X-Forwarded-For", value.parse().unwrap());
        h
    }

    /// The deployment has a proxy but has not named it, so the peer wins
    /// and every caller behind that proxy shares one address. `Peer` where
    /// `Forwarded` was expected is what says so.
    #[test]
    fn an_unnamed_proxy_reports_peer_not_forwarded() {
        let trusted = TrustedProxies::default();
        let proxy: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let got = trusted.client_ip(&xff("198.51.100.7"), Some(proxy));
        assert_eq!(got.get(), Some(proxy));
        assert_eq!(got.source(), Source::Peer);
    }

    /// The same request with the proxy named.
    #[test]
    fn a_named_proxy_reports_forwarded() {
        let trusted = TrustedProxies::from_cidrs(["10.0.0.0/8"]).unwrap();
        let proxy: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let got = trusted.client_ip(&xff("198.51.100.7"), Some(proxy));
        assert_eq!(got.get(), Some("198.51.100.7".parse().unwrap()));
        assert_eq!(got.source(), Source::Forwarded);
    }

    /// No layer at all, which is the other silent failure.
    #[test]
    fn nothing_resolved_reports_unknown() {
        assert_eq!(ClientIp::default().source(), Source::Unknown);
        assert_eq!(ClientIp::default().get(), None);
    }

    /// A trusted peer with an empty chain began the request itself, so the
    /// answer is the peer and the provenance says so rather than claiming
    /// a forwarded entry that was never there.
    #[test]
    fn a_trusted_peer_with_no_chain_reports_peer() {
        let trusted = TrustedProxies::loopback_only();
        let peer: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let got = trusted.client_ip(&HeaderMap::new(), Some(peer));
        assert_eq!(got.get(), Some(peer));
        assert_eq!(got.source(), Source::Peer);
    }

    /// An address the application resolved by means axess cannot see is
    /// distinguishable from one axess worked out, which is the difference
    /// an auditor asking "how do you know" is asking about.
    #[test]
    fn an_application_supplied_address_says_so() {
        let ip: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(ClientIp::resolved(Some(ip)).source(), Source::Supplied);
    }
}
