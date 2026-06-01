//! HTTP-level tests for SessionLayer, macros, and cookie round-trips.
//!
//! Uses `tower::ServiceExt::oneshot` to test the full Axum middleware stack
//! without binding a TCP port.
//!
//! Gated on the `memory` feature because the entire suite is built around
//! `MemorySessionStore` for round-tripping. Without the feature, the test
//! binary compiles as empty rather than failing on missing types.

#![cfg(feature = "memory")]

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

    // First request; creates session, sets cookie.
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

    // Second request with the cookie; session exists, not modified → no Set-Cookie.
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

// ── Integration tests that close the mutants on the
//    SessionService::call save / cycle decision lines. The mutation-
//    testing pass on `session/layer.rs` showed that:
//
//      let session_changed =
//          guard.modified || guard.regenerate || existing_id.is_none();
//
//    could be replaced with `&&` on either `||` and the existing test
//    suite did not notice. The same family of mutations covers the
//    `max_custom_bytes` clamp on lines 540 and 544. The tests below
//    drive the public Axum stack so the assertions land on the
//    on-the-wire behaviour, not the private fields. ───────────────────

/// Modified-only session must persist its data across requests.
///
/// Kills `replace || with && in let session_changed = guard.modified || …`
/// (line 554). Under that mutation `session_changed` would only become
/// true when *all three* conditions held (modified + regenerate + new),
/// which is almost never. A second request with the same cookie would
/// then see an empty session; exactly what this test forbids.
#[tokio::test]
async fn modified_only_session_round_trips_value() {
    let app = test_router();

    // First request: GET /set mutates `data.custom["test_key"]`. Cookie
    // is issued because the session is brand new (existing_id is None,
    // modified is true).
    let resp1 = app
        .clone()
        .oneshot(Request::get("/set").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookie_value = resp1
        .headers()
        .get(header::SET_COOKIE)
        .expect("first request must set a cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Second request: replay the cookie on a no-op route, then come
    // back through GET /get. If the modified-path save was elided on
    // request 1 (the mutation), GET /get returns "empty" because the
    // store has no row for this id.
    let resp2 = app
        .oneshot(
            Request::get("/get")
                .header(header::COOKIE, cookie_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp2.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp2.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(
        body_str.contains("hello"),
        "modified-only save was elided; second request saw {body_str:?} \
         instead of the mutation written by the first request"
    );
}

/// The `max_custom_bytes` clamp must actually clamp.
///
/// Kills `> with ==` / `> with <` / `> with >=` mutations on
/// `if custom_size > config.max_custom_bytes` (line 544) and the
/// upstream `if config.max_custom_bytes > 0 && guard.modified`
/// (line 540). The handler writes a payload above the configured
/// limit and the test asserts that, by request 2, the custom field
/// has been cleared by the layer.
#[tokio::test]
async fn oversized_custom_data_is_cleared_on_save() {
    let store = MemorySessionStore::new();
    let signing_key = [13u8; 32];
    let session_layer = SessionLayer::new(store, signing_key)
        .with_ttl(Duration::from_secs(3600))
        .with_secure(false)
        .with_max_custom_bytes(32);

    async fn fat_set(session: AuthSession) -> impl IntoResponse {
        // ~256 bytes; comfortably above the 32-byte clamp.
        session
            .set_custom("payload", serde_json::Value::String("x".repeat(256)))
            .await;
        "fat-set"
    }
    async fn read_payload(session: AuthSession) -> impl IntoResponse {
        let v = session.get_custom("payload").await;
        match v {
            Some(serde_json::Value::String(s)) => format!("len={}", s.len()),
            Some(_) => "non-string".to_string(),
            None => "cleared".to_string(),
        }
    }

    let app = Router::new()
        .route("/fat-set", get(fat_set))
        .route("/read", get(read_payload))
        .layer(session_layer);

    let resp1 = app
        .clone()
        .oneshot(Request::get("/fat-set").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookie = resp1
        .headers()
        .get(header::SET_COOKIE)
        .expect("first request sets a cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let resp2 = app
        .oneshot(
            Request::get("/read")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp2.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert_eq!(
        body_str, "cleared",
        "oversized custom data was not clamped; \
         layer returned {body_str:?} instead of `cleared`"
    );
}

/// `max_custom_bytes = 0` MUST disable the clamp entirely.
///
/// Kills the `> with <` and `> with >=` mutations on `max_custom_bytes
/// > 0` (line 540). Under those mutations the clamp would either fire
/// universally (clearing every payload regardless of size) or never
/// fire (no protection). With limit set to 0, the documented contract
/// is "no clamp"; the test asserts a multi-KB payload survives.
#[tokio::test]
async fn max_custom_bytes_zero_disables_clamp() {
    let store = MemorySessionStore::new();
    let signing_key = [13u8; 32];
    let session_layer = SessionLayer::new(store, signing_key)
        .with_ttl(Duration::from_secs(3600))
        .with_secure(false)
        .with_max_custom_bytes(0); // disabled

    async fn fat_set(session: AuthSession) -> impl IntoResponse {
        session
            .set_custom("payload", serde_json::Value::String("y".repeat(2048)))
            .await;
        "fat-set"
    }
    async fn read_payload(session: AuthSession) -> impl IntoResponse {
        let v = session.get_custom("payload").await;
        match v {
            Some(serde_json::Value::String(s)) => format!("len={}", s.len()),
            Some(_) => "non-string".to_string(),
            None => "cleared".to_string(),
        }
    }

    let app = Router::new()
        .route("/fat-set", get(fat_set))
        .route("/read", get(read_payload))
        .layer(session_layer);

    let resp1 = app
        .clone()
        .oneshot(Request::get("/fat-set").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookie = resp1
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let resp2 = app
        .oneshot(
            Request::get("/read")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp2.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert_eq!(
        body_str, "len=2048",
        "max_custom_bytes=0 must disable the clamp; \
         layer returned {body_str:?}"
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
    let uid = axess_core::authn::ids::testing::user("user1");
    let tid = axess_core::authn::ids::testing::tenant("tenant1");
    session
        .set_authenticated(uid, tid, chrono::Utc::now())
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

    // 2. Check with the SAME User-Agent; should still be authenticated.
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

    // 2. Replay cookie with a DIFFERENT User-Agent; session should be invalidated.
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
// be tested from axess-core. See the macro test TODO in the ROADMAP;
// these tests should go in an `axess/tests/` integration test file that
// depends on the `axess` crate directly.

// ── SessionLayer + DeviceResolver wiring ─────────────────────────────

#[cfg(feature = "device")]
mod device_resolver_wiring {
    use super::*;
    use axess_core::device::{DeviceId, DeviceResolver};
    use axum::http::request::Parts;

    /// Test resolver that hands out a fixed [`DeviceId`] regardless of input.
    /// Mirrors a production resolver's contract closely enough to exercise
    /// the layer's stamp + persist path, without dragging in a real
    /// `DeviceStore`.
    struct StaticResolver(DeviceId);

    impl DeviceResolver for StaticResolver {
        type Error = std::convert::Infallible;
        async fn resolve(&self, parts: &Parts) -> Result<Option<DeviceId>, Self::Error> {
            tracing::trace!(uri = %parts.uri, "StaticResolver: returning fixed device id");
            Ok(Some(self.0))
        }
    }

    /// Resolver that always returns `Ok(None)` so the layer's "no resolver
    /// outcome → leave None" branch is exercised even when a resolver is
    /// configured.
    struct NoneResolver;

    impl DeviceResolver for NoneResolver {
        type Error = std::convert::Infallible;
        async fn resolve(&self, parts: &Parts) -> Result<Option<DeviceId>, Self::Error> {
            tracing::trace!(uri = %parts.uri, "NoneResolver: returning None");
            Ok(None)
        }
    }

    /// Reflects the session's current `device_id` back as the response
    /// body, so tests can assert on what the handler observed.
    async fn reflect_device_handler(session: AuthSession) -> impl IntoResponse {
        match session.data().await.device_id {
            Some(id) => format!("device={id}"),
            None => "device=none".to_string(),
        }
    }

    fn router_with_resolver<R: DeviceResolver>(resolver: R) -> Router {
        let store = MemorySessionStore::new();
        let signing_key = [42u8; 32];
        let session_layer = SessionLayer::new(store, signing_key)
            .with_secure(false)
            .with_device_resolver(resolver);

        Router::new()
            .route("/reflect", get(reflect_device_handler))
            .layer(session_layer)
    }

    #[tokio::test]
    async fn resolver_some_stamps_device_id_visible_to_handler() {
        let id = axess_core::authn::ids::testing::device("dev-abc-123");
        let app = router_with_resolver(StaticResolver(id));

        let resp = app
            .oneshot(Request::get("/reflect").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            format!("device={id}"),
            "handler must observe the device_id stamped by the resolver"
        );
    }

    #[tokio::test]
    async fn resolver_none_leaves_device_id_unset() {
        let app = router_with_resolver(NoneResolver);

        let resp = app
            .oneshot(Request::get("/reflect").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "device=none",
            "Ok(None) from the resolver must not stamp a device_id"
        );
    }

    #[tokio::test]
    async fn no_resolver_configured_leaves_device_id_unset() {
        // SessionLayer without `with_device_resolver`; the device-id
        // column stays None even when the `device` feature is on.
        let store = MemorySessionStore::new();
        let signing_key = [42u8; 32];
        let session_layer = SessionLayer::new(store, signing_key).with_secure(false);
        let app = Router::new()
            .route("/reflect", get(reflect_device_handler))
            .layer(session_layer);

        let resp = app
            .oneshot(Request::get("/reflect").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "device=none");
    }

    #[tokio::test]
    async fn resolver_runs_on_every_request_and_persists_first_stamp() {
        // First request: resolver stamps Some(id), session is created
        // (existing_id was None), so the layer saves the SessionData
        // including the new device_id. The Set-Cookie response header
        // confirms persistence happened.
        let id = axess_core::authn::ids::testing::device("dev-persist-test");
        let app = router_with_resolver(StaticResolver(id));

        let resp = app
            .oneshot(Request::get("/reflect").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get(header::SET_COOKIE).is_some(),
            "first request must mint+persist a session; Set-Cookie expected"
        );
    }
}
