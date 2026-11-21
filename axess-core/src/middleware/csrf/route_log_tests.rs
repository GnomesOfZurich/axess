//! A refused request's log line names the route the router matched, never
//! the path the client sent: a path can carry a credential, and the line
//! outlives the request.

use super::*;
use axess_testing::mock_tracing::LineCapture;
use axum::routing::{get, post};
use std::convert::Infallible;
use tower::{Layer, ServiceExt, service_fn};

/// The credential a path carries in these tests.
const MARKER: &str = "marker-7c1e";

fn config() -> CsrfConfig {
    CsrfConfig::new(std::array::from_fn(|i| i as u8))
}

fn app(config: CsrfConfig) -> axum::Router {
    axum::Router::new()
        .route("/ws/{token}", get(|| async { "upgraded" }))
        .route("/invites/{token}/accept", post(|| async { "accepted" }))
        .layer(CsrfLayer::new(config))
}

/// A browser's upgrade to `/ws/<MARKER>` from a foreign page.
fn foreign_upgrade() -> Request<Body> {
    Request::get(format!("/ws/{MARKER}"))
        .header(header::HOST, "app.example.com")
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header(header::ORIGIN, "https://evil.example.net")
        .body(Body::empty())
        .unwrap()
}

/// A POST to `/invites/<MARKER>/accept` with no CSRF token, from `origin`,
/// in the session `handle` when one is given.
fn accept(origin: &str, handle: Option<SessionHandle>) -> Request<Body> {
    let mut req = Request::post(format!("/invites/{MARKER}/accept"))
        .header(header::HOST, "app.example.com")
        .header(header::ORIGIN, origin)
        .body(Body::empty())
        .unwrap();
    if let Some(handle) = handle {
        req.extensions_mut().insert(handle);
    }
    req
}

/// No printed line holds the marker, and the line holding `needle` reads
/// `route=<route>`.
fn assert_route_logged(printed: &LineCapture, needle: &str, route: &str) {
    let text = printed.text();
    assert!(
        !text.contains(MARKER),
        "the concrete path reached a line: {text}"
    );
    let line = printed
        .lines()
        .into_iter()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line holds {needle:?}: {text}"));
    assert!(line.contains(&format!("route={route}")), "{line}");
}

#[tokio::test]
async fn a_refused_upgrade_logs_its_route_and_not_its_path() {
    let printed = LineCapture::install();
    let app = app(config().require_origin(["https://app.example.com"]));
    let refused = app.oneshot(foreign_upgrade()).await.unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_route_logged(&printed, "WebSocket upgrade refused", "/ws/{token}");
}

/// Wrapped around a bare service no router matched, the field reads the
/// placeholder; the path is not the fallback.
#[tokio::test]
async fn a_refused_upgrade_outside_a_router_logs_no_path() {
    let printed = LineCapture::install();
    let service = CsrfLayer::new(config().require_origin(["https://app.example.com"])).layer(
        service_fn(|_: Request<Body>| async {
            Ok::<_, Infallible>(Response::builder().status(200).body(Body::empty()).unwrap())
        }),
    );
    let refused = service.oneshot(foreign_upgrade()).await.unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_route_logged(
        &printed,
        "WebSocket upgrade refused",
        crate::logged_route::UNMATCHED,
    );
}

#[tokio::test]
async fn a_state_changing_request_with_no_session_logs_its_route_and_not_its_path() {
    let printed = LineCapture::install();
    let refused = app(config())
        .oneshot(accept("https://app.example.com", None))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_route_logged(&printed, "no session id", "/invites/{token}/accept");
}

#[tokio::test]
async fn a_foreign_origin_logs_its_route_and_not_its_path() {
    let printed = LineCapture::install();
    let refused = app(config().require_origin(["https://app.example.com"]))
        .oneshot(accept(
            "https://evil.example.net",
            Some(super::tests::session_handle(1)),
        ))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_route_logged(
        &printed,
        "Origin/Referer validation failed",
        "/invites/{token}/accept",
    );
}

#[tokio::test]
async fn a_missing_token_logs_its_route_and_not_its_path() {
    let printed = LineCapture::install();
    let refused = app(config())
        .oneshot(accept(
            "https://app.example.com",
            Some(super::tests::session_handle(1)),
        ))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_route_logged(
        &printed,
        "token validation failed",
        "/invites/{token}/accept",
    );
}
