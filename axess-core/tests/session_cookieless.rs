//! A request without a session cookie persists a session and sets a cookie
//! only when something needs the session.

#![cfg(feature = "memory")]

use axess_core::middleware::csrf::{CsrfConfig, CsrfLayer};
use axess_core::session::{
    data::SessionData,
    extractor::AuthSession,
    id::SessionId,
    layer::SessionLayer,
    store::{MemorySessionStore, SessionStore},
};
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    routing::get,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tower::ServiceExt;

/// A store that counts the writes reaching the wrapped memory store.
#[derive(Clone, Default)]
struct CountingStore {
    inner: MemorySessionStore,
    writes: Arc<AtomicUsize>,
}

impl SessionStore for CountingStore {
    type Error = <MemorySessionStore as SessionStore>::Error;

    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        self.inner.load(id).await
    }

    async fn save(
        &self,
        id: &SessionId,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.save(id, d, ttl).await
    }

    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.delete(id).await
    }

    async fn cycle(
        &self,
        old: &SessionId,
        new: &SessionId,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.cycle(old, new, d, ttl).await
    }

    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        self.inner.prune_expired().await
    }
}

fn router(store: CountingStore) -> Router {
    let csrf = CsrfLayer::new(CsrfConfig::new([42u8; 32]));
    Router::new()
        .route("/plain", get(|| async { "plain" }))
        .route("/id", get(|s: AuthSession| async move { format!("{:?}", s.session_id().await.as_bytes().len()) }))
        .route(
            "/set",
            get(|s: AuthSession| async move {
                s.set_custom("k", serde_json::json!(1)).await;
                "set"
            }),
        )
        .merge(
            Router::new()
                .route("/csrf", get(|| async { "csrf" }))
                .layer(csrf),
        )
        .layer(
            SessionLayer::new(store, [42u8; 32])
                .with_ttl(Duration::from_secs(3600))
                .with_secure(false),
        )
}

async fn get_path(store: &CountingStore, path: &str) -> (usize, bool) {
    let resp = router(store.clone())
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let has_cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap().starts_with("axess.sid="));
    (store.writes.load(Ordering::SeqCst), has_cookie)
}

#[tokio::test]
async fn cookieless_get_on_a_plain_route_writes_nothing_and_sets_no_cookie() {
    let store = CountingStore::default();
    assert_eq!(get_path(&store, "/plain").await, (0, false));
}

#[tokio::test]
async fn cookieless_get_that_modifies_the_session_persists_and_sets_cookie() {
    let store = CountingStore::default();
    assert_eq!(get_path(&store, "/set").await, (1, true));
}

#[tokio::test]
async fn cookieless_get_that_reads_the_session_id_persists_and_sets_cookie() {
    let store = CountingStore::default();
    assert_eq!(get_path(&store, "/id").await, (1, true));
}

#[tokio::test]
async fn cookieless_get_on_a_csrf_route_persists_and_sets_cookie() {
    let store = CountingStore::default();
    assert_eq!(get_path(&store, "/csrf").await, (1, true));
}
