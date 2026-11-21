//! The endpoint address: what its constructors accept, and that nothing else
//! builds one.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use proptest::prelude::*;

use super::*;

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

#[test]
fn a_unix_uri_names_an_absolute_path() {
    let expected = Endpoint::unix("/run/spire/sockets/agent.sock").expect("an absolute path");
    assert_eq!(
        Endpoint::parse("unix:///run/spire/sockets/agent.sock"),
        Ok(expected.clone())
    );
    // The form with no authority at all.
    assert_eq!(
        Endpoint::parse("unix:/run/spire/sockets/agent.sock"),
        Ok(expected.clone())
    );
    assert_eq!(
        expected.unix_path(),
        Some(Path::new("/run/spire/sockets/agent.sock"))
    );
    assert_eq!(expected.tcp_address(), None);
}

#[test]
fn a_tcp_uri_names_a_loopback_address_and_a_port() {
    for uri in [
        "tcp://127.0.0.1:8081",
        "tcp://127.8.9.10:8081",
        "tcp://[::1]:8081",
    ] {
        let endpoint = Endpoint::parse(uri).expect("a loopback address");
        let expected = address(uri.trim_start_matches("tcp://"));
        assert_eq!(endpoint.tcp_address(), Some(expected));
        assert_eq!(endpoint.unix_path(), None);
        assert_eq!(Endpoint::tcp_loopback(expected), Ok(endpoint));
    }
}

#[test]
fn a_tcp_address_off_the_loopback_interface_is_refused_by_every_checked_way_in() {
    for off_host in [
        "10.0.0.7:8081",
        "192.168.1.1:8081",
        "169.254.169.254:80",
        "0.0.0.0:8081",
        "8.8.8.8:8081",
        "[2001:db8::1]:8081",
        "[::]:8081",
        // An IPv4 loopback address written as IPv6 is not `::1`.
        "[::ffff:127.0.0.1]:8081",
    ] {
        let uri = format!("tcp://{off_host}");
        let Err(SpireError::Endpoint(text)) = Endpoint::parse(&uri) else {
            panic!("{uri} must be refused");
        };
        assert!(text.contains("off the loopback interface"), "{text}");
        assert!(text.contains("clear text"), "{text}");
        assert!(
            matches!(
                Endpoint::tcp_loopback(address(off_host)),
                Err(SpireError::Endpoint(_))
            ),
            "{off_host} must be refused"
        );
        assert!(uri.parse::<Endpoint>().is_err());
    }
}

#[test]
fn an_address_off_the_loopback_interface_takes_the_call_that_names_what_it_gives_up() {
    let off_host = address("10.0.0.7:8081");
    let endpoint = Endpoint::tcp_clear_text(off_host);
    assert_eq!(endpoint.tcp_address(), Some(off_host));
    assert_eq!(endpoint.to_string(), "tcp://10.0.0.7:8081");
    // What it prints is not a way back in: the URI is still refused.
    assert!(Endpoint::parse(&endpoint.to_string()).is_err());
}

#[test]
fn what_the_workload_endpoint_rules_exclude_is_refused() {
    for refused in [
        "",
        "agent.sock",
        "/run/spire/sockets/agent.sock",
        "http://127.0.0.1:8081",
        "unix://",
        "unix:///",
        "unix:agent.sock",
        "unix://agent.sock",
        "unix://host/run/agent.sock",
        "unix:///run/agent.sock?x=1",
        "unix:///run/agent.sock#frag",
        "unix:///run/agent\0.sock",
        "tcp://",
        "tcp://127.0.0.1",
        "tcp://localhost:8081",
        "tcp://example.org:8081",
        "tcp://127.0.0.1:8081/",
        "tcp://127.0.0.1:8081/path",
        "tcp://user@127.0.0.1:8081",
        "tcp://127.0.0.1:8081?x=1",
        "tcp://127.0.0.1:99999",
        "TCP://127.0.0.1:8081",
    ] {
        assert!(
            matches!(Endpoint::parse(refused), Err(SpireError::Endpoint(_))),
            "{refused:?} must be refused"
        );
    }
}

#[test]
fn a_refusal_quotes_the_address_escaped_and_cut() {
    let hostile = format!("unix:relative\n\u{1b}[31mFORGED{}", "x".repeat(4096));
    let Err(SpireError::Endpoint(text)) = Endpoint::parse(&hostile) else {
        panic!("a relative path is refused");
    };
    assert!(!text.contains('\n') && !text.contains('\u{1b}'), "{text:?}");
    assert!(text.contains("\\n") && text.contains("\\u{1b}"), "{text:?}");
    assert!(text.len() < 400, "the text is {} bytes", text.len());

    let hostile = format!("/run/agent\n\u{1b}[31m{}\0", "x".repeat(4096));
    let Err(SpireError::Endpoint(text)) = Endpoint::unix(hostile) else {
        panic!("a path with a NUL is refused");
    };
    assert!(!text.contains('\n') && !text.contains('\u{1b}'), "{text:?}");
    assert!(text.len() < 400, "the text is {} bytes", text.len());
}

#[test]
fn the_path_constructor_applies_the_checks_the_parser_does() {
    for refused in [
        "agent.sock",
        "./agent.sock",
        "",
        "/",
        "///",
        "/run/agent\0.sock",
    ] {
        assert!(
            matches!(Endpoint::unix(refused), Err(SpireError::Endpoint(_))),
            "{refused:?} must be refused"
        );
    }
    let endpoint = Endpoint::unix("/run/agent.sock").expect("an absolute path");
    assert_eq!(endpoint.unix_path(), Some(Path::new("/run/agent.sock")));
}

#[test]
fn an_endpoint_prints_as_the_uri_it_parses_from() {
    for uri in [
        "unix:///run/spire/sockets/agent.sock",
        "tcp://127.0.0.1:8081",
        "tcp://[::1]:8081",
    ] {
        let endpoint: Endpoint = uri.parse().expect("a valid endpoint");
        assert_eq!(endpoint.to_string(), uri);
    }
}

proptest! {
    /// No text makes the parser panic, and what it accepts prints as a URI
    /// that parses to the same endpoint.
    #[test]
    fn any_text_is_parsed_or_refused(text in "\\PC{0,64}") {
        if let Ok(endpoint) = Endpoint::parse(&text) {
            prop_assert_eq!(Endpoint::parse(&endpoint.to_string()), Ok(endpoint));
        }
    }

    /// Texts that start like an endpoint, where the rules have something to
    /// decide: whatever is accepted is an absolute path or a loopback
    /// address.
    #[test]
    fn any_endpoint_like_text_is_parsed_or_refused(
        scheme in prop_oneof![Just("unix:"), Just("unix://"), Just("unix:///"), Just("tcp://")],
        rest in "[a-z0-9./:@\\[\\]?#-]{0,32}",
    ) {
        let text = format!("{scheme}{rest}");
        match Endpoint::parse(&text) {
            Ok(endpoint) => {
                let absolute = endpoint.unix_path().is_some_and(Path::is_absolute);
                let loopback = endpoint
                    .tcp_address()
                    .is_some_and(|address| address.ip().is_loopback());
                prop_assert!(absolute || loopback, "{text} gave {endpoint}");
            }
            Err(error) => prop_assert!(matches!(error, SpireError::Endpoint(_))),
        }
    }

    /// A socket address is an endpoint by a URI exactly when it is on the
    /// loopback interface; the clear-text call takes any.
    #[test]
    fn a_socket_address_parses_exactly_when_it_is_loopback(ip in any::<IpAddr>(), port in any::<u16>()) {
        let address = SocketAddr::new(ip, port);
        let uri = Endpoint::tcp_clear_text(address).to_string();
        let parsed = Endpoint::parse(&uri);
        prop_assert_eq!(parsed.is_ok(), ip.is_loopback());
        prop_assert_eq!(Endpoint::tcp_loopback(address).is_ok(), ip.is_loopback());
        if let Ok(endpoint) = parsed {
            prop_assert_eq!(endpoint.tcp_address(), Some(address));
        }
    }

    /// Every loopback address round-trips through its URI.
    #[test]
    fn every_loopback_address_round_trips(last in any::<[u8; 3]>(), port in any::<u16>(), v6 in any::<bool>()) {
        let ip: IpAddr = if v6 {
            std::net::Ipv6Addr::LOCALHOST.into()
        } else {
            std::net::Ipv4Addr::new(127, last[0], last[1], last[2]).into()
        };
        let endpoint = Endpoint::tcp_loopback(SocketAddr::new(ip, port)).expect("a loopback address");
        prop_assert_eq!(Endpoint::parse(&endpoint.to_string()), Ok(endpoint));
    }
}
