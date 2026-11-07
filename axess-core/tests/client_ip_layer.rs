//! `client_ip::layer` observed through a request, and the names a
//! [`Source`] is written under.
//!
//! The walk itself is tested beside the module; these pin the two things
//! only a request or a stored row can see: that the layer resolves the
//! address and puts it where a handler reads it, and that the provenance
//! strings an audit row carries do not change under it.

use axess_core::client_ip::{self, ClientIp, Source, TrustedProxies};
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use http_body_util::BodyExt;
use std::net::SocketAddr;
use tower::ServiceExt;

/// What the handler saw, as "<address or none> <source>".
async fn seen(ip: ClientIp) -> String {
    let addr = ip
        .get()
        .map_or_else(|| "none".to_owned(), |a| a.to_string());
    format!("{addr} {}", ip.source())
}

fn app(trusted: TrustedProxies) -> Router {
    client_ip::layer(Router::new().route("/", get(seen)), trusted)
}

/// Send one request from `peer` (none: no `ConnectInfo`, as when the
/// router is served without it) and return the status and body.
async fn send(app: Router, peer: Option<&str>, xff: Option<&str>) -> (StatusCode, String) {
    let mut req = Request::builder().uri("/");
    if let Some(chain) = xff {
        req = req.header("X-Forwarded-For", chain);
    }
    let mut req = req.body(Body::empty()).expect("a valid request");
    if let Some(peer) = peer {
        let addr: SocketAddr = peer.parse().expect("a socket address");
        req.extensions_mut().insert(ConnectInfo(addr));
    }
    let res = app.oneshot(req).await.expect("the router is infallible");
    let status = res.status();
    let body = res.into_body().collect().await.expect("a body").to_bytes();
    (status, String::from_utf8(body.to_vec()).expect("utf-8"))
}

/// Behind a trusted proxy the layer walks the chain, and the handler reads
/// the client it found, marked as forwarded.
#[tokio::test]
async fn the_layer_hands_the_handler_the_forwarded_client() {
    let got = send(
        app(TrustedProxies::loopback_only()),
        Some("127.0.0.1:40000"),
        Some("198.51.100.7"),
    )
    .await;
    assert_eq!(got, (StatusCode::OK, "198.51.100.7 forwarded".to_owned()));
}

/// A peer the deployment does not trust is the answer, and the forged
/// chain it sent is not read.
#[tokio::test]
async fn the_layer_ignores_the_chain_of_an_untrusted_peer() {
    let got = send(
        app(TrustedProxies::loopback_only()),
        Some("203.0.113.9:40000"),
        Some("198.51.100.7"),
    )
    .await;
    assert_eq!(got, (StatusCode::OK, "203.0.113.9 peer".to_owned()));
}

/// Served without `ConnectInfo` there is no peer to check, so nothing is
/// believed: the handler gets no address rather than the header's.
#[tokio::test]
async fn the_layer_without_a_peer_resolves_nothing() {
    let got = send(
        app(TrustedProxies::loopback_only()),
        None,
        Some("198.51.100.7"),
    )
    .await;
    assert_eq!(got, (StatusCode::OK, "none unknown".to_owned()));
}

/// The same route without the layer: the extractor still answers, and says
/// the layer is missing.
#[tokio::test]
async fn a_route_outside_the_layer_reads_unknown() {
    let bare = Router::new().route("/", get(seen));
    let got = send(bare, Some("127.0.0.1:40000"), Some("198.51.100.7")).await;
    assert_eq!(got, (StatusCode::OK, "none unknown".to_owned()));
}

/// The wire names, pinned: they end up in audit rows that outlive the
/// code. `Display`, `as_str` and the serde form agree on each.
#[test]
fn source_names_are_pinned_in_every_form() {
    let cases = [
        (Source::Unknown, "unknown"),
        (Source::Peer, "peer"),
        (Source::Forwarded, "forwarded"),
        (Source::Supplied, "supplied"),
    ];
    for (source, name) in cases {
        assert_eq!(source.as_str(), name);
        assert_eq!(source.to_string(), name);
        assert_eq!(
            serde_json::to_string(&source).expect("serialises"),
            format!("\"{name}\"")
        );
    }
}
