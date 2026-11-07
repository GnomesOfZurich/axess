#![cfg(feature = "oidc")]
//! The egress screen: which addresses and URLs a screened policy refuses, and
//! that the refusal holds at the moment of connecting, not only on the URL.

use axess_factors::egress::{EgressPolicy, ReservedRange};
use std::net::IpAddr;

fn range(ip: &str) -> Option<ReservedRange> {
    ReservedRange::of(ip.parse::<IpAddr>().unwrap())
}

#[test]
fn reserved_ranges_are_named() {
    for (ip, want) in [
        ("127.0.0.1", ReservedRange::Loopback),
        ("127.9.9.9", ReservedRange::Loopback),
        ("::1", ReservedRange::Loopback),
        ("::ffff:127.0.0.1", ReservedRange::Loopback),
        ("10.1.2.3", ReservedRange::Private),
        ("172.31.255.255", ReservedRange::Private),
        ("192.168.0.1", ReservedRange::Private),
        ("169.254.169.254", ReservedRange::Metadata),
        ("fd00:ec2::254", ReservedRange::Metadata),
        ("169.254.0.1", ReservedRange::LinkLocal),
        ("fe80::1", ReservedRange::LinkLocal),
        ("fc00::1", ReservedRange::UniqueLocal),
        ("fdff::1", ReservedRange::UniqueLocal),
        ("100.64.0.1", ReservedRange::Shared),
        ("100.127.255.255", ReservedRange::Shared),
        ("0.0.0.0", ReservedRange::Unspecified),
        ("::", ReservedRange::Unspecified),
        ("224.0.0.1", ReservedRange::Multicast),
        ("255.255.255.255", ReservedRange::Multicast),
    ] {
        assert_eq!(range(ip), Some(want), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "1.1.1.1",
        "172.32.0.1",
        "100.128.0.1",
        "2606:4700::1111",
    ] {
        assert_eq!(range(ip), None, "{ip} is public");
    }
}

#[test]
fn the_default_policy_is_screened() {
    assert_eq!(EgressPolicy::default(), EgressPolicy::screened());
    assert!(EgressPolicy::default().is_screened());
    assert!(!EgressPolicy::unscreened().is_screened());
}

#[test]
fn a_screened_policy_takes_https_hosts_and_refuses_the_rest() {
    let p = EgressPolicy::screened();
    assert!(
        p.check_url("https://idp.example/realms/a", "issuer URL")
            .is_ok()
    );
    for bad in [
        "http://idp.example",
        "http://127.0.0.1:9000",
        "https://user@idp.example",
        "ftp://idp.example",
        "https://localhost:8443",
        "https://app.localhost",
        "https://[::ffff:192.168.0.1]",
        "not a url",
    ] {
        assert!(p.check_url(bad, "issuer URL").is_err(), "{bad}");
    }
}

#[test]
fn the_test_opt_in_allows_only_loopback_over_http() {
    let p = EgressPolicy::screened_allowing_loopback_http();
    assert!(p.check_url("http://127.0.0.1:9000", "t").is_ok());
    assert!(p.check_url("http://localhost:9000", "t").is_ok());
    assert!(p.check_url("http://[::1]:9000", "t").is_ok());
    assert!(p.check_url("http://10.0.0.5", "t").is_err());
    assert!(p.check_url("https://10.0.0.5", "t").is_err());
    assert!(p.check_url("http://idp.example", "t").is_err());
}

#[test]
fn the_refusal_names_the_setting_and_not_the_url() {
    let err = EgressPolicy::screened()
        .check_url("https://10.0.0.5/secret-path", "token_endpoint")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("token_endpoint") && err.contains("private"),
        "{err}"
    );
    assert!(!err.contains("secret-path"), "{err}");
}

#[tokio::test]
async fn a_name_that_resolves_to_loopback_is_not_connected_to() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = EgressPolicy::screened()
        .client_builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();

    // `check_url` is not consulted: this is the connect-time screen.
    let res = client.get(format!("http://localhost:{port}/")).send().await;

    assert!(res.is_err(), "the request to a loopback name went through");
    assert!(
        listener.accept().is_err(),
        "the server connected to loopback"
    );
}

#[tokio::test]
async fn the_opt_in_connects_to_loopback() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = EgressPolicy::screened_allowing_loopback_http()
        .client_builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();

    let _ = client.get(format!("http://localhost:{port}/")).send().await;

    listener.set_nonblocking(true).unwrap();
    assert!(
        listener.accept().is_ok(),
        "the opted-in client did not connect"
    );
}
