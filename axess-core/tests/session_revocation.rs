//! A session layer built with a registry enforces revocation on every
//! request, whatever guards the route, and moves the registry entry when a
//! handler rotates the session id.

#![cfg(all(feature = "memory", feature = "testing"))]

use axess_clock::testing::MockClock;
use axess_core::authn::ids::testing;
use axess_core::session::{
    extractor::AuthSession,
    id::SessionId,
    layer::SessionLayer,
    store::{
        MemorySessionRegistry, MemorySessionStore, SessionRegistryAdapter, SessionRegistryHandle,
        SessionStore,
    },
};
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    routing::get,
};
use chrono::{TimeZone, Utc};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

#[derive(Clone)]
struct World {
    store: MemorySessionStore,
    registry: Arc<dyn SessionRegistryHandle>,
    clock: MockClock,
    app: Router,
}

fn world(max_age: Option<Duration>) -> World {
    let store = MemorySessionStore::new();
    let registry: Arc<dyn SessionRegistryHandle> =
        Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new()));
    let clock = MockClock::at(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    let reg = registry.clone();
    let mut layer = SessionLayer::new(store.clone(), [9u8; 32])
        .with_secure(false)
        .with_registry(registry.clone())
        .with_clock(clock.clone());
    if let Some(max_age) = max_age {
        layer = layer.with_max_session_age(max_age);
    }
    let clock_login = clock.clone();
    let app = Router::new()
        .route(
            "/login",
            get(move |s: AuthSession| {
                let reg = reg.clone();
                let clock = clock_login.clone();
                async move {
                    let (u, t) = (testing::user("u1"), testing::tenant("t1"));
                    s.set_authenticated(u, t, axess_clock::Clock::now(&clock))
                        .await;
                    let sid = s.session_id().await;
                    assert!(reg.register(&u, &sid).await);
                    "in"
                }
            }),
        )
        .route(
            "/whoami",
            get(|s: AuthSession| async move {
                if s.is_authenticated().await {
                    s.session_id().await.to_string()
                } else {
                    "guest".to_owned()
                }
            }),
        )
        .route(
            "/regen",
            get(|s: AuthSession| async move {
                s.regenerate().await;
                "regen"
            }),
        )
        .layer(layer);
    World {
        store,
        registry,
        clock,
        app,
    }
}

/// Send a GET with the cookie jar and fold the response's cookies back in.
async fn get_as(app: &Router, jar: &mut Option<String>, path: &str) -> String {
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
async fn a_session_the_registry_dropped_is_ended_and_its_row_deleted() {
    let w = world(None);
    let mut jar = None;
    assert_eq!(get_as(&w.app, &mut jar, "/login").await, "in");
    let sid = get_as(&w.app, &mut jar, "/whoami").await;
    assert_ne!(sid, "guest", "the session works before revocation");
    let sid: SessionId = sid.parse().unwrap();
    assert!(w.store.load(&sid).await.unwrap().is_some());

    w.registry
        .invalidate_user(&testing::user("u1"))
        .await
        .expect("revoke");

    let stale_cookie = jar.clone();
    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    assert!(
        w.store.load(&sid).await.unwrap().is_none(),
        "the store must not keep an Authenticated row for a revoked session"
    );
    // The old cookie keeps being a guest.
    let mut old = stale_cookie;
    assert_eq!(get_as(&w.app, &mut old, "/whoami").await, "guest");
}

#[tokio::test]
async fn without_a_registry_on_the_layer_the_row_outlives_revocation() {
    // The behaviour the registry option exists to fix: documented here so a
    // change in it is deliberate.
    let store = MemorySessionStore::new();
    let registry: Arc<dyn SessionRegistryHandle> =
        Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new()));
    let reg = registry.clone();
    let app = Router::new()
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
            get(|s: AuthSession| async move { s.is_authenticated().await.to_string() }),
        )
        .layer(SessionLayer::new(store, [9u8; 32]).with_secure(false));
    let mut jar = None;
    get_as(&app, &mut jar, "/login").await;
    registry
        .invalidate_user(&testing::user("u1"))
        .await
        .expect("revoke");
    assert_eq!(get_as(&app, &mut jar, "/whoami").await, "true");
}

#[tokio::test]
async fn a_handler_regenerate_keeps_a_registry_backed_session_alive() {
    let w = world(None);
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    let before = get_as(&w.app, &mut jar, "/whoami").await;
    get_as(&w.app, &mut jar, "/regen").await;
    let after = get_as(&w.app, &mut jar, "/whoami").await;
    assert_ne!(after, "guest", "the rotated session stays signed in");
    assert_ne!(before, after, "the id really changed");
    let old: SessionId = before.parse().unwrap();
    let user = testing::user("u1");
    assert_eq!(
        w.registry.liveness(&user, &old).await,
        axess_core::session::store::SessionLiveness::Gone,
        "the old id left the registry"
    );
}

#[tokio::test]
async fn a_session_older_than_the_absolute_cap_is_ended_however_active() {
    let w = world(Some(Duration::from_secs(3600)));
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    w.clock.advance_secs(1800);
    assert_ne!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    w.clock.advance_secs(1801);
    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
}
