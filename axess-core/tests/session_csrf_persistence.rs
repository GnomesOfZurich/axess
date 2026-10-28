//! Why a CSRF route persists a guest session on a request without a session
//! cookie: the token is bound to the session id, and the next request can
//! only present it if the session is stored and its cookie set. A store that
//! forgets the session breaks the follow-up request, so the write is the
//! price of the binding, not an accident.

#![cfg(feature = "memory")]

use axess_core::middleware::csrf::{CsrfConfig, CsrfLayer};
use axess_core::session::{
    data::SessionData,
    id::SessionId,
    layer::SessionLayer,
    store::{CycleOutcome, MemorySessionStore, SessionStore},
};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use std::time::Duration;
use tower::ServiceExt;

/// A store that accepts every write and keeps nothing.
#[derive(Clone, Default)]
struct ForgetfulStore;

impl SessionStore for ForgetfulStore {
    type Error = <MemorySessionStore as SessionStore>::Error;

    async fn load(&self, _id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        Ok(None)
    }
    async fn save(&self, _: &SessionId, _: &SessionData, _: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn update(
        &self,
        _: &SessionId,
        _: &SessionData,
        _: Duration,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
    async fn delete(&self, _id: &SessionId) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn cycle(
        &self,
        _: &SessionId,
        _: &SessionId,
        _: &SessionData,
        _: Duration,
        _: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        Ok(CycleOutcome::Rotated)
    }
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        Ok(0)
    }
}

fn router<S: SessionStore>(store: S) -> Router {
    Router::new()
        .route(
            "/form",
            get(|| async { "form" }).post(|| async { "posted" }),
        )
        .layer(CsrfLayer::new(CsrfConfig::new([42u8; 32])))
        .layer(
            SessionLayer::new(store, [42u8; 32])
                .with_ttl(Duration::from_secs(3600))
                .with_secure(false),
        )
}

/// GET the form, then POST it back with the cookies and the token, the way a
/// browser would; returns the POST's status.
async fn get_then_post<S: SessionStore>(store: S) -> StatusCode {
    let app = router(store);
    let first = app
        .clone()
        .oneshot(Request::get("/form").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookies: Vec<String> = first
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
        .collect();
    let token = cookies
        .iter()
        .find_map(|c| c.strip_prefix("axess.csrf="))
        .expect("the GET sets the CSRF cookie")
        .to_string();
    let second = app
        .oneshot(
            Request::post("/form")
                .header(header::COOKIE, cookies.join("; "))
                .header("x-csrf-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    second.status()
}

#[tokio::test]
async fn the_follow_up_post_passes_when_the_guest_session_was_persisted() {
    assert_eq!(
        get_then_post(MemorySessionStore::new()).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_follow_up_post_is_refused_when_the_guest_session_was_not_kept() {
    assert_eq!(get_then_post(ForgetfulStore).await, StatusCode::FORBIDDEN);
}
