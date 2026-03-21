//! Tests for login_required!() and require_partial_authn!() macros.
//!
//! These must live in the `axess` crate (not `axess-core`) because the macros
//! are defined in `axess-macros` and re-exported via `axess`.

use axess::{MemorySessionStore, SessionLayer, login_required, require_partial_authn};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use std::time::Duration;
use tower::ServiceExt;

fn session_layer() -> SessionLayer<MemorySessionStore> {
    SessionLayer::new(MemorySessionStore::new(), [42u8; 32])
        .with_ttl(Duration::from_secs(3600))
        .with_secure(false)
}

// ── login_required!() ────────────────────────────────────────────────────────

#[tokio::test]
async fn login_required_returns_401_for_unauthenticated() {
    let app = Router::new()
        .route("/protected", get(|| async { "secret" }))
        .layer(login_required!())
        .layer(session_layer());

    let response = app
        .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_required_with_redirect_returns_307() {
    let app = Router::new()
        .route("/protected", get(|| async { "secret" }))
        .layer(login_required!("/login"))
        .layer(session_layer());

    let response = app
        .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("/login"), "should redirect to /login");
    assert!(
        location.contains("next="),
        "should include next query param"
    );
}

#[tokio::test]
async fn login_required_with_redirect_and_custom_field() {
    let app = Router::new()
        .route("/protected", get(|| async { "secret" }))
        .layer(login_required!("/auth/login", "return_to"))
        .layer(session_layer());

    let response = app
        .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.contains("return_to="),
        "should use custom redirect field name"
    );
}

// ── require_partial_authn!() ─────────────────────────────────────────────────

#[tokio::test]
async fn require_partial_authn_returns_401_for_guest() {
    let app = Router::new()
        .route("/mfa", get(|| async { "mfa page" }))
        .layer(require_partial_authn!())
        .layer(session_layer());

    let response = app
        .oneshot(Request::get("/mfa").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
