//! HTTP-level tests for SessionLayer, macros, and cookie round-trips.
//!
//! Uses `tower::ServiceExt::oneshot` to test the full Axum middleware stack
//! without binding a TCP port.

use axess_core::session::{
    binding::UserAgentBinding, extractor::AuthSession, layer::SessionLayer,
    store::MemorySessionStore,
};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

fn test_router() -> Router {
    let store = MemorySessionStore::new();
    let signing_key = [42u8; 32];
    let session_layer = SessionLayer::new(store, signing_key)
        .with_ttl(Duration::from_secs(3600))
        .with_secure(false);

    Router::new()
        .route("/set", get(set_handler))
        .route("/get", get(get_handler))
        .route("/authed", get(authed_handler))
        .layer(session_layer)
}

async fn set_handler(session: AuthSession) -> impl IntoResponse {
    session
        .set_custom("test_key", serde_json::json!("hello"))
        .await;
    "set"
}

async fn get_handler(session: AuthSession) -> impl IntoResponse {
    let val = session.get_custom("test_key").await;
    match val {
        Some(v) => format!("got: {v}"),
        None => "empty".to_string(),
    }
}

async fn authed_handler(session: AuthSession) -> impl IntoResponse {
    if session.is_authenticated().await {
        (StatusCode::OK, "authenticated")
    } else {
        (StatusCode::UNAUTHORIZED, "not authenticated")
    }
}

// ── SessionLayer basic tests ─────────────────────────────────────────────────

#[tokio::test]
async fn session_layer_sets_cookie_on_first_request() {
    let app = test_router();

    let response = app
        .oneshot(Request::get("/set").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let set_cookie = response.headers().get(header::SET_COOKIE);
    assert!(set_cookie.is_some(), "first request should set a cookie");

    let cookie_str = set_cookie.unwrap().to_str().unwrap();
    assert!(
        cookie_str.contains("axess.sid="),
        "cookie should have axess.sid name"
    );
    assert!(cookie_str.contains("HttpOnly"), "cookie should be HttpOnly");
    assert!(
        cookie_str.contains("SameSite=Lax"),
        "cookie should be SameSite=Lax"
    );
    assert!(
        cookie_str.contains("Max-Age="),
        "cookie should have Max-Age"
    );
    assert!(cookie_str.contains("Path=/"), "cookie should have Path=/");
}

#[tokio::test]
async fn session_cookie_contains_hmac_signature() {
    let app = test_router();

    let response = app
        .oneshot(Request::get("/set").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let cookie_str = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();

    // Extract the cookie value (before the first ';').
    let cookie_value = cookie_str
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("axess.sid=")
        .unwrap();

    // Cookie format: base64url(session_id).base64url(hmac)
    assert!(
        cookie_value.contains('.'),
        "cookie should contain a dot separator"
    );
    let parts: Vec<&str> = cookie_value.split('.').collect();
    assert_eq!(parts.len(), 2, "cookie should have exactly two parts");
    assert!(!parts[0].is_empty(), "session ID part should not be empty");
    assert!(!parts[1].is_empty(), "HMAC part should not be empty");
}

#[tokio::test]
async fn unmodified_session_does_not_set_cookie() {
    let store = MemorySessionStore::new();
    let signing_key = [42u8; 32];
    let session_layer = SessionLayer::new(store, signing_key).with_secure(false);

    let app = Router::new()
        .route("/noop", get(|| async { "noop" }))
        .layer(session_layer);

    // First request — creates session, sets cookie.
    let resp1 = app
        .clone()
        .oneshot(Request::get("/noop").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let cookie = resp1.headers().get(header::SET_COOKIE);
    // First request always sets a cookie (new session).
    assert!(cookie.is_some());

    // Extract the cookie to send on the second request.
    let cookie_header = cookie.unwrap().to_str().unwrap();
    let cookie_value = cookie_header.split(';').next().unwrap();

    // Second request with the cookie — session exists, not modified → no Set-Cookie.
    let resp2 = app
        .oneshot(
            Request::get("/noop")
                .header(header::COOKIE, cookie_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let set_cookie2 = resp2.headers().get(header::SET_COOKIE);
    assert!(
        set_cookie2.is_none(),
        "unmodified session should not produce Set-Cookie"
    );
}

// ── Session binding tests ───────────────────────────────────────────────────

fn binding_router() -> Router {
    let store = MemorySessionStore::new();
    let signing_key = [42u8; 32];
    let session_layer = SessionLayer::new(store, signing_key)
        .with_ttl(Duration::from_secs(3600))
        .with_secure(false)
        .with_binding(UserAgentBinding);

    Router::new()
        .route("/login", post(login_handler))
        .route("/check", get(check_handler))
        .layer(session_layer)
}

async fn login_handler(session: AuthSession) -> impl IntoResponse {
    session
        .set_authenticated(Arc::from("user1"), Arc::from("tenant1"), chrono::Utc::now())
        .await;
    "logged in"
}

async fn check_handler(session: AuthSession) -> impl IntoResponse {
    if session.is_authenticated().await {
        (StatusCode::OK, "authenticated")
    } else {
        (StatusCode::UNAUTHORIZED, "not authenticated")
    }
}

/// Extract the cookie value from a Set-Cookie header for replay in subsequent requests.
fn extract_cookie(response: &axum::http::Response<Body>) -> String {
    response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn binding_allows_same_user_agent() {
    let app = binding_router();

    // 1. Login with User-Agent "TestBrowser/1.0".
    let resp = app
        .clone()
        .oneshot(
            Request::post("/login")
                .header(header::USER_AGENT, "TestBrowser/1.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = extract_cookie(&resp);

    // 2. Check with the SAME User-Agent — should still be authenticated.
    let resp = app
        .oneshot(
            Request::get("/check")
                .header(header::COOKIE, &cookie)
                .header(header::USER_AGENT, "TestBrowser/1.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn binding_invalidates_on_different_user_agent() {
    let app = binding_router();

    // 1. Login with User-Agent "BrowserA".
    let resp = app
        .clone()
        .oneshot(
            Request::post("/login")
                .header(header::USER_AGENT, "BrowserA")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = extract_cookie(&resp);

    // 2. Replay cookie with a DIFFERENT User-Agent — session should be invalidated.
    let resp = app
        .oneshot(
            Request::get("/check")
                .header(header::COOKIE, &cookie)
                .header(header::USER_AGENT, "BrowserB")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn binding_not_set_for_unauthenticated_sessions() {
    let store = MemorySessionStore::new();
    let signing_key = [42u8; 32];
    let session_layer = SessionLayer::new(store.clone(), signing_key)
        .with_secure(false)
        .with_binding(UserAgentBinding);

    let app = Router::new()
        .route(
            "/noop",
            get(|session: AuthSession| async move {
                // Just read the data to verify fingerprint is None for guests.
                let data = session.data().await;
                if data.fingerprint.is_some() {
                    "has_binding"
                } else {
                    "no_binding"
                }
            }),
        )
        .layer(session_layer);

    let resp = app
        .oneshot(
            Request::get("/noop")
                .header(header::USER_AGENT, "TestBrowser")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(&body[..], b"no_binding");
}

// Note: login_required!() and require_partial_authn!() macros live in
// axess-macros and are re-exported via the `axess` facade crate. They cannot
// be tested from axess-core. See the macro test TODO in the ROADMAP —
// these tests should go in an `axess/tests/` integration test file that
// depends on the `axess` crate directly.
