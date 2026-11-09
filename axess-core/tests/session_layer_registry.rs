//! A session layer is built with a registry, so a revocation reaches the
//! stored row on every route; the named opt-out says so in the log.

#![cfg(all(feature = "memory", feature = "testing"))]

use axess_core::authn::ids::testing;
use axess_core::session::{
    extractor::AuthSession,
    layer::SessionLayer,
    store::{
        MemorySessionRegistry, MemorySessionStore, SessionRegistryAdapter, SessionRegistryHandle,
    },
};
use axess_core::testing::AuthSessionTestExt;
use axess_testing::mock_tracing::TracingCapture;
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    routing::get,
};
use chrono::Utc;
use std::sync::Arc;
use tower::ServiceExt;

const KEY: [u8; 32] = [
    7, 1, 9, 4, 8, 2, 6, 3, 5, 0, 11, 14, 13, 12, 10, 15, 21, 24, 23, 22, 20, 25, 27, 26, 29, 28,
    31, 30, 17, 16, 19, 18,
];

fn app(layer: SessionLayer<MemorySessionStore>, reg: Arc<dyn SessionRegistryHandle>) -> Router {
    Router::new()
        .route(
            "/login",
            get(move |s: AuthSession| {
                let reg = reg.clone();
                async move {
                    let u = testing::user("u1");
                    s.set_authenticated(u, testing::tenant("t1"), Utc::now())
                        .await;
                    reg.register(&u, &s.session_id().await).await;
                    "in"
                }
            }),
        )
        .route(
            "/whoami",
            get(|s: AuthSession| async move {
                if s.is_authenticated().await {
                    "user"
                } else {
                    "guest"
                }
            }),
        )
        .layer(layer)
}

async fn call(app: &Router, jar: &mut Option<String>, path: &str) -> String {
    let mut req = Request::get(path);
    if let Some(c) = jar.as_deref() {
        req = req.header(header::COOKIE, c);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    if let Some(v) = resp.headers().get(header::SET_COOKIE) {
        *jar = Some(v.to_str().unwrap().split(';').next().unwrap().to_owned());
    }
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn a_layer_built_with_a_registry_ends_a_revoked_session_on_any_route() {
    let reg: Arc<dyn SessionRegistryHandle> =
        Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new()));
    let layer = SessionLayer::new(MemorySessionStore::new(), KEY, reg.clone()).with_secure(false);
    let app = app(layer, reg.clone());
    let mut jar = None;
    assert_eq!(call(&app, &mut jar, "/login").await, "in");
    assert_eq!(call(&app, &mut jar, "/whoami").await, "user");
    reg.invalidate_user(&testing::user("u1")).await.unwrap();
    assert_eq!(call(&app, &mut jar, "/whoami").await, "guest");
}

#[tokio::test]
async fn the_insecure_opt_out_keeps_the_stored_row_valid_and_logs_an_error_once() {
    let capture = TracingCapture::install();
    let reg: Arc<dyn SessionRegistryHandle> =
        Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new()));
    let layer =
        SessionLayer::without_registry_insecure(MemorySessionStore::new(), KEY).with_secure(false);
    let app = app(layer, reg.clone());
    let mut jar = None;
    assert_eq!(call(&app, &mut jar, "/login").await, "in");
    reg.invalidate_user(&testing::user("u1")).await.unwrap();
    assert_eq!(
        call(&app, &mut jar, "/whoami").await,
        "user",
        "without a registry the stored row outlives revocation"
    );
    let errors = capture
        .events()
        .iter()
        .filter(|e| e.level == tracing::Level::ERROR && e.message.contains("without a registry"))
        .count();
    assert_eq!(errors, 1, "events: {:?}", capture.events());
}
