//! `require_authn!` with a validator consults the session registry and ends a
//! revoked session; the bare form reads only the session record.

#![cfg(feature = "testing")]

use axess::authn::AuthnService;
use axess::testing::{MockFactorStore, MockIdentityStore};
use axess::{
    AuthSession, MemorySessionRegistry, MemorySessionStore, SessionLayer, SessionRegistry,
    require_authn,
};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use std::time::Duration;
use tower::ServiceExt;

struct App {
    app: Router,
    registry: MemorySessionRegistry,
}

fn app() -> App {
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_registry(registry.clone())
        .build();
    let reg = registry.clone();
    let session_layer = SessionLayer::new(MemorySessionStore::new(), [42u8; 32])
        .with_ttl(Duration::from_secs(3600))
        .with_secure(false);
    let plain = Router::new()
        .route("/plain", get(|| async { "ok" }))
        .route_layer(require_authn!());
    let guarded = Router::new()
        .route("/guarded", get(|| async { "ok" }))
        .route_layer(require_authn!(validator = svc.session_validator()));
    let redirecting = Router::new()
        .route("/redirecting", get(|| async { "ok" }))
        .route_layer(require_authn!(
            url = "/login",
            validator = svc.session_validator()
        ));
    let app = Router::new()
        .route(
            "/login",
            get(move |s: AuthSession| {
                let reg = reg.clone();
                async move {
                    let user = axess::testing::user("u1");
                    s.set_authenticated(user, axess::testing::tenant("t1"), chrono::Utc::now())
                        .await;
                    reg.register(&user, &s.session_id().await).await.unwrap();
                    "in"
                }
            }),
        )
        .merge(plain)
        .merge(guarded)
        .merge(redirecting)
        .layer(session_layer);
    App { app, registry }
}

async fn status(app: &Router, cookie: &str, path: &str) -> (StatusCode, Option<String>) {
    let resp = app
        .clone()
        .oneshot(
            Request::get(path)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let set = resp
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    (resp.status(), set)
}

async fn login(app: &Router) -> String {
    let resp = app
        .clone()
        .oneshot(Request::get("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    resp.headers()
        .get(header::SET_COOKIE)
        .expect("login sets the cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn a_revoked_session_passes_the_bare_guard_and_fails_the_validator_guard() {
    let a = app();
    let cookie = login(&a.app).await;
    assert_eq!(status(&a.app, &cookie, "/plain").await.0, StatusCode::OK);
    assert_eq!(status(&a.app, &cookie, "/guarded").await.0, StatusCode::OK);

    a.registry
        .invalidate_user(&axess::testing::user("u1"))
        .await
        .unwrap();

    assert_eq!(
        status(&a.app, &cookie, "/plain").await.0,
        StatusCode::OK,
        "the bare guard reads only the session record"
    );
    assert_eq!(
        status(&a.app, &cookie, "/guarded").await.0,
        StatusCode::UNAUTHORIZED
    );
    // The validator ended the session: the bare guard now refuses it too.
    assert_eq!(
        status(&a.app, &cookie, "/plain").await.0,
        StatusCode::UNAUTHORIZED,
        "the stored session was cleared, not merely refused once"
    );
}

#[tokio::test]
async fn the_validator_guard_can_redirect() {
    let a = app();
    let cookie = login(&a.app).await;
    a.registry
        .invalidate_user(&axess::testing::user("u1"))
        .await
        .unwrap();
    assert_eq!(
        status(&a.app, &cookie, "/redirecting").await.0,
        StatusCode::TEMPORARY_REDIRECT
    );
}
