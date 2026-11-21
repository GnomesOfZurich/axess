//! The session layer draws every id it mints from the RNG it was given.

#![cfg(feature = "testing")]

use axess_core::testing::fixtures as common;

use axess_core::authn::ids::testing as ids;
use axess_core::session::id::{SessionId, SessionKey};
use axess_core::session::{extractor::AuthSession, layer::SessionLayer, store::MemorySessionStore};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::MockRng;
use axum::{Router, body::Body, http::Request, routing::get};
use tower::ServiceExt;

async fn whoami(session: AuthSession) -> String {
    session.session_key().await.to_string()
}

async fn login(session: AuthSession) -> String {
    session
        .set_authenticated(ids::user("u"), ids::tenant("t"), common::start())
        .await;
    session.session_key().await.to_string()
}

fn app(seed: u64) -> Router {
    let clock = common::test_clock();
    Router::new()
        .route("/whoami", get(whoami))
        .route("/login", get(login))
        .layer(
            SessionLayer::new(
                MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone())),
                axess_core::testing::test_key(7),
                axess_core::MemorySessionRegistry::new()
                    .with_clock(std::sync::Arc::new(clock.clone()))
                    .handle(),
                std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
            )
            .with_clock(clock.clone())
            .with_secure(false)
            .with_rng(MockRng::new(seed)),
        )
}

async fn body(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 256).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The key of the `n`th id drawn from `seed`: a handler reads the key, and
/// the key is of the id the layer drew.
fn nth_id(seed: u64, n: usize) -> String {
    let rng = MockRng::new(seed);
    let mut id = SessionId::new(&rng);
    for _ in 1..n {
        id = SessionId::new(&rng);
    }
    SessionKey::of(&id).to_string()
}

#[tokio::test]
async fn a_new_session_gets_the_first_id_from_the_layer_rng() {
    let resp = app(11)
        .oneshot(Request::get("/whoami").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(body(resp).await, nth_id(11, 1));
}

#[tokio::test]
async fn a_rotation_takes_the_next_id_from_the_layer_rng() {
    let resp = app(11)
        .oneshot(Request::get("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    // Draw one minted the request's guest id; the login rotation took draw two.
    assert_eq!(body(resp).await, nth_id(11, 2));
}
