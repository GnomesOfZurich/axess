//! A value taken from the session is single-use across concurrent requests
//! and nodes; a read-only request keeps its session alive past half the TTL;
//! a request dropped mid-handler still has its session finalized.

#![cfg(all(feature = "memory", feature = "testing"))]

use axess_clock::testing::MockClock;
use axess_core::authn::ids::testing;
use axess_core::session::{
    extractor::AuthSession,
    id::SessionId,
    layer::SessionLayer,
    store::{ConditionalUpdate, MemorySessionStore, SessionStore},
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
use tokio::sync::Barrier;
use tower::ServiceExt;

const TTL: Duration = Duration::from_secs(1000);

struct World {
    store: MemorySessionStore,
    clock: MockClock,
    app: Router,
}

fn world(rendezvous: Option<Arc<Barrier>>) -> World {
    let clock = MockClock::at(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    let store = MemorySessionStore::new().with_clock(Arc::new(clock.clone()));
    let layer = SessionLayer::new(store.clone(), [9u8; 32])
        .with_secure(false)
        .with_ttl(TTL)
        .with_clock(clock.clone());
    let clock_login = clock.clone();
    let app = Router::new()
        .route(
            "/login",
            get(move |s: AuthSession| {
                let clock = clock_login.clone();
                async move {
                    s.set_authenticated(
                        testing::user("u1"),
                        testing::tenant("t1"),
                        axess_clock::Clock::now(&clock),
                    )
                    .await;
                    s.set_custom("ceremony", serde_json::json!("state")).await;
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
            "/take",
            get(move |s: AuthSession| {
                let rendezvous = rendezvous.clone();
                async move {
                    // Both requests hold the session as loaded before either
                    // takes the value.
                    if let Some(b) = &rendezvous {
                        b.wait().await;
                    }
                    match s.take_custom("ceremony").await {
                        Some(_) => "got",
                        None => "none",
                    }
                }
            }),
        )
        .route(
            "/end-then-take",
            get({
                let store = store.clone();
                move |s: AuthSession| {
                    let store = store.clone();
                    async move {
                        // A logout on another node removes the row while this
                        // request runs.
                        store.delete(&s.session_id().await).await.unwrap();
                        match s.take_custom("ceremony").await {
                            Some(_) => "got",
                            None => "none",
                        }
                    }
                }
            }),
        )
        .route(
            "/logout-then-hang",
            get(|s: AuthSession| async move {
                s.clear().await;
                std::future::pending::<()>().await;
                "unreachable"
            }),
        )
        .layer(layer);
    World { store, clock, app }
}

async fn send(app: &Router, cookie: Option<&str>, path: &str) -> (String, Option<String>) {
    let mut req = Request::get(path);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let set = resp
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    (String::from_utf8(bytes.to_vec()).unwrap(), set)
}

async fn login(w: &World) -> String {
    let (body, cookie) = send(&w.app, None, "/login").await;
    assert_eq!(body, "in");
    cookie.expect("login sets the session cookie")
}

#[tokio::test]
async fn of_two_concurrent_requests_only_one_takes_the_value() {
    let w = world(Some(Arc::new(Barrier::new(2))));
    let cookie = login(&w).await;
    let (a, b) = tokio::join!(
        send(&w.app, Some(&cookie), "/take"),
        send(&w.app, Some(&cookie), "/take")
    );
    let mut got = [a.0, b.0];
    got.sort();
    assert_eq!(got, ["got", "none"], "exactly one request gets the value");
}

#[tokio::test]
async fn a_value_taken_once_is_gone_for_the_next_request() {
    let w = world(None);
    let cookie = login(&w).await;
    assert_eq!(send(&w.app, Some(&cookie), "/take").await.0, "got");
    assert_eq!(send(&w.app, Some(&cookie), "/take").await.0, "none");
}

#[tokio::test]
async fn a_session_deleted_while_its_request_runs_hands_out_nothing() {
    let w = world(None);
    let cookie = login(&w).await;
    assert_eq!(
        send(&w.app, Some(&cookie), "/end-then-take").await.0,
        "none"
    );
}

#[tokio::test]
async fn the_store_refuses_a_write_against_a_stale_revision() {
    let w = world(None);
    let cookie = login(&w).await;
    let sid: SessionId = send(&w.app, Some(&cookie), "/whoami")
        .await
        .0
        .parse()
        .unwrap();
    let stored = w.store.load(&sid).await.unwrap().unwrap();
    let mut next = stored.clone();
    next.revision = stored.revision + 1;
    assert_eq!(
        w.store
            .update_if_revision(&sid, stored.revision, &next, TTL)
            .await
            .unwrap(),
        ConditionalUpdate::Written
    );
    assert_eq!(
        w.store
            .update_if_revision(&sid, stored.revision, &next, TTL)
            .await
            .unwrap(),
        ConditionalUpdate::Conflict,
        "the second writer still holds the old revision"
    );
    w.store.delete(&sid).await.unwrap();
    assert_eq!(
        w.store
            .update_if_revision(&sid, next.revision, &next, TTL)
            .await
            .unwrap(),
        ConditionalUpdate::Gone
    );
}

#[tokio::test]
async fn a_read_only_request_past_half_the_ttl_keeps_the_session_alive() {
    let w = world(None);
    let cookie = login(&w).await;

    // Within half the lifetime nothing is written and no cookie is set.
    w.clock.advance(chrono::Duration::seconds(400));
    let (sid, set) = send(&w.app, Some(&cookie), "/whoami").await;
    assert_ne!(sid, "guest");
    assert!(set.is_none(), "no refresh before half the TTL has passed");

    // Past half, the read re-arms the row and the cookie.
    w.clock.advance(chrono::Duration::seconds(200));
    let (_, set) = send(&w.app, Some(&cookie), "/whoami").await;
    assert!(set.is_some(), "the cookie is re-issued once the row is due");

    // 1400 s after login is past the original expiry (1000 s) and inside the
    // refreshed one (600 + 1000 s).
    w.clock.advance(chrono::Duration::seconds(800));
    let (body, _) = send(&w.app, Some(&cookie), "/whoami").await;
    assert_ne!(body, "guest", "activity kept the session alive");
}

#[tokio::test]
async fn an_idle_session_still_expires_at_the_ttl() {
    let w = world(None);
    let cookie = login(&w).await;
    w.clock.advance(chrono::Duration::seconds(1100));
    assert_eq!(send(&w.app, Some(&cookie), "/whoami").await.0, "guest");
}

#[tokio::test]
async fn a_request_dropped_mid_handler_still_has_its_session_finalized() {
    let w = world(None);
    let cookie = login(&w).await;
    let sid: SessionId = send(&w.app, Some(&cookie), "/whoami")
        .await
        .0
        .parse()
        .unwrap();
    assert!(
        w.store
            .load(&sid)
            .await
            .unwrap()
            .unwrap()
            .auth_state
            .is_authenticated()
    );

    // The handler clears the session and then never returns; the client goes
    // away (the future is dropped) before the response exists.
    let req = Request::get("/logout-then-hang")
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let dropped =
        tokio::time::timeout(Duration::from_millis(100), w.app.clone().oneshot(req)).await;
    assert!(dropped.is_err(), "the request never completed");

    // The finalize runs in a task of its own: wait for it.
    let mut gone = false;
    for _ in 0..50 {
        if w.store.load(&sid).await.unwrap().is_none() {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        gone,
        "the row of the cleared session must not stay Authenticated"
    );
}

#[tokio::test]
async fn the_memory_store_keeps_the_compare_and_swap_contract() {
    axess_core::testing::store_contract::assert_update_if_revision_contract(
        &MemorySessionStore::new(),
    )
    .await;
}
