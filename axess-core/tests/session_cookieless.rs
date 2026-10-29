//! A request without a session cookie persists a session and sets a cookie
//! only when something needs the session.

#![cfg(feature = "memory")]

use axess_core::middleware::csrf::{CsrfConfig, CsrfLayer, CsrfToken};
use axess_core::session::{
    data::SessionData,
    extractor::AuthSession,
    id::SessionId,
    layer::SessionLayer,
    store::{CycleOutcome, MemorySessionStore, SessionStore},
};
use axum::{
    Extension, Router,
    body::Body,
    http::{Request, header},
    routing::{get, post},
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
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.cycle(old, new, d, ttl, require_old).await
    }

    async fn update(
        &self,
        id: &SessionId,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.update(id, d, ttl).await
    }

    async fn update_if_revision(
        &self,
        id: &SessionId,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<axess_core::session::store::ConditionalUpdate, Self::Error> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .update_if_revision(id, expected_revision, data, ttl)
            .await
    }
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        self.inner.prune_expired().await
    }
}

fn router(store: CountingStore) -> Router {
    router_with(store, CsrfConfig::new([42u8; 32]))
}

fn router_with(store: CountingStore, csrf: CsrfConfig) -> Router {
    let csrf = CsrfLayer::new(csrf);
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
                .route(
                    "/csrf-read",
                    get(|Extension(t): Extension<CsrfToken>| async move { t.as_str().to_owned() }),
                )
                .route("/csrf-post", post(|| async { "posted" }))
                .layer(csrf),
        )
        .layer(
            SessionLayer::new(store, [42u8; 32])
                .with_ttl(Duration::from_secs(3600))
                .with_secure(false),
        )
}

async fn get_path(store: &CountingStore, path: &str) -> (usize, bool) {
    let (writes, has_cookie, _) = get_with(router(store.clone()), store, path).await;
    (writes, has_cookie)
}

/// Writes seen by the store, whether a session cookie was set, and every
/// `Set-Cookie` header of the response.
async fn get_with(app: Router, store: &CountingStore, path: &str) -> (usize, bool, Vec<String>) {
    let resp = app
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let has_cookie = cookies.iter().any(|c| c.starts_with("axess.sid="));
    (store.writes.load(Ordering::SeqCst), has_cookie, cookies)
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

/// A CSRF route whose handler never touches the token must not turn every
/// cookieless request (bots, health checks) into a stored session.
#[tokio::test]
async fn cookieless_get_on_a_csrf_route_that_ignores_the_token_stores_nothing() {
    let store = CountingStore::default();
    let (writes, session_cookie, cookies) = get_with(router(store.clone()), &store, "/csrf").await;
    assert_eq!(writes, 0, "no session row may be written");
    assert!(!session_cookie);
    assert!(cookies.is_empty(), "no Set-Cookie at all, got {cookies:?}");
}

#[tokio::test]
async fn cookieless_get_that_reads_the_csrf_token_persists_and_sets_both_cookies() {
    let store = CountingStore::default();
    let (writes, session_cookie, cookies) =
        get_with(router(store.clone()), &store, "/csrf-read").await;
    assert_eq!(writes, 1);
    assert!(session_cookie);
    assert!(
        cookies.iter().any(|c| c.starts_with("axess.csrf=")),
        "the CSRF cookie accompanies the stored session: {cookies:?}"
    );
}

#[tokio::test]
async fn mint_on_every_request_restores_the_old_behaviour() {
    let store = CountingStore::default();
    let app = router_with(
        store.clone(),
        CsrfConfig::new([42u8; 32]).mint_on_every_request(true),
    );
    let (writes, session_cookie, cookies) = get_with(app, &store, "/csrf").await;
    assert_eq!(writes, 1);
    assert!(session_cookie);
    assert!(cookies.iter().any(|c| c.starts_with("axess.csrf=")));
}

/// A token minted by a handler that read it validates on the next POST.
#[tokio::test]
async fn a_token_read_by_a_handler_validates_on_post() {
    let store = CountingStore::default();
    let app = router(store.clone());
    let resp = app
        .clone()
        .oneshot(Request::get("/csrf-read").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let mut sid = String::new();
    let mut csrf = String::new();
    for v in resp.headers().get_all(header::SET_COOKIE) {
        let pair = v.to_str().unwrap().split(';').next().unwrap().to_owned();
        if pair.starts_with("axess.sid=") {
            sid = pair;
        } else if pair.starts_with("axess.csrf=") {
            csrf = pair;
        }
    }
    assert!(!sid.is_empty() && !csrf.is_empty());
    let token = csrf.trim_start_matches("axess.csrf=").to_owned();
    let post = Request::post("/csrf-post")
        .header(header::COOKIE, format!("{sid}; {csrf}"))
        .header("x-csrf-token", token)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(post).await.unwrap();
    assert_eq!(resp.status(), 200);
}

/// A response that sets the session cookie keeps out of shared caches.
#[tokio::test]
async fn a_response_that_sets_the_session_cookie_is_not_cacheable() {
    let store = CountingStore::default();
    let resp = router(store.clone())
        .oneshot(Request::get("/set").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(resp.headers()[header::VARY], "Cookie");
}

/// A response with no cookie is left alone.
#[tokio::test]
async fn a_response_without_cookies_gets_no_cache_headers() {
    let store = CountingStore::default();
    let resp = router(store.clone())
        .oneshot(Request::get("/plain").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(resp.headers().get(header::CACHE_CONTROL).is_none());
}
