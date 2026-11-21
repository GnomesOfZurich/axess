//! A WebSocket upgrade through the session layer carries the Origin check,
//! so a socket route outside the CSRF layer is covered too.

#![cfg(all(feature = "memory", feature = "testing"))]

use axess_core::testing::fixtures as common;

use axess_core::session::{layer::SessionLayer, store::MemorySessionStore};
use axess_testing::mock_tracing::LineCapture;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use tower::ServiceExt;

fn app(layer: SessionLayer<MemorySessionStore>) -> Router {
    Router::new()
        .route("/ws", get(|| async { "upgraded" }))
        .layer(layer)
}

fn layer() -> SessionLayer<MemorySessionStore> {
    let clock = common::test_clock();
    SessionLayer::without_registry_insecure(
        MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone())),
        axess_core::testing::test_key(1),
        std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
    )
    .with_clock(clock.clone())
}

/// An upgrade to `app.example.com` as a browser sends it, with `origin`.
fn upgrade(origin: Option<&str>) -> Request<Body> {
    let mut req = Request::get("/ws")
        .header(header::HOST, "app.example.com")
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade");
    if let Some(origin) = origin {
        req = req.header(header::ORIGIN, origin);
    }
    req.body(Body::empty()).unwrap()
}

async fn status(app: &Router, req: Request<Body>) -> StatusCode {
    app.clone().oneshot(req).await.unwrap().status()
}

/// Without an allow-list the one origin an upgrade may come from is its own
/// host under `https` (the cookies are `Secure` by default); an upgrade with
/// no `Origin` is not a browser's and passes.
#[tokio::test]
async fn a_cross_site_upgrade_is_refused_before_the_handler_runs() {
    let app = app(layer());
    assert_eq!(
        status(&app, upgrade(Some("https://evil.example.net"))).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&app, upgrade(Some("http://app.example.com"))).await,
        StatusCode::FORBIDDEN,
        "Secure cookies: an http page is not the own origin"
    );
    assert_eq!(
        status(&app, upgrade(Some("https://APP.example.com:443"))).await,
        StatusCode::OK
    );
    assert_eq!(status(&app, upgrade(None)).await, StatusCode::OK);
}

/// With an allow-list only those origins pass, and an upgrade with no
/// `Origin` does not.
#[tokio::test]
async fn an_allow_list_names_the_origins_that_may_open_a_socket() {
    let app = app(layer().with_websocket_origins(["https://app.example.com"]));
    assert_eq!(
        status(&app, upgrade(Some("https://app.example.com"))).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&app, upgrade(Some("https://other.example.com"))).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(status(&app, upgrade(None)).await, StatusCode::FORBIDDEN);
}

/// Only upgrades are checked: an ordinary request with a foreign `Origin`
/// reaches the handler.
#[tokio::test]
async fn an_ordinary_request_is_not_origin_checked() {
    let app = app(layer());
    let plain = Request::get("/ws")
        .header(header::HOST, "app.example.com")
        .header(header::ORIGIN, "https://evil.example.net")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status(&app, plain).await, StatusCode::OK);
}

/// A refused upgrade's log line names the route the router matched, never
/// the path the client sent: a path can carry a credential.
#[tokio::test]
async fn a_refused_upgrade_logs_its_route_and_not_its_path() {
    let printed = LineCapture::install();
    let app = Router::new()
        .route("/ws/{token}", get(|| async { "upgraded" }))
        .layer(layer());
    let req = Request::get("/ws/marker-7c1e")
        .header(header::HOST, "app.example.com")
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header(header::ORIGIN, "https://evil.example.net")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status(&app, req).await, StatusCode::FORBIDDEN);
    let text = printed.text();
    assert!(
        !text.contains("marker-7c1e"),
        "the concrete path reached a line: {text}"
    );
    let line = printed
        .lines()
        .into_iter()
        .find(|l| l.contains("WebSocket upgrade refused"))
        .unwrap_or_else(|| panic!("no refusal line: {text}"));
    assert!(line.contains("route=/ws/{token}"), "{line}");
}
