//! An adopter whose tenant lives in the session, not in a `TenantId` request
//! extension, still gets a device cookie with the default resolver.

#![cfg(all(feature = "memory", feature = "device"))]

use std::sync::Arc;

use axess_clock::SystemClock;
use axess_core::authn::ids::{TenantId, testing};
use axess_core::session::{extractor::AuthSession, layer::SessionLayer, store::MemorySessionStore};
use axess_core::{
    DefaultFingerprintExtractor, DeviceLifecycleService, DeviceStore, LifecycleDeviceResolver,
    MemoryDeviceStore,
};
use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{Request, header},
    middleware::{self, Next},
    routing::get,
};
use chrono::Utc;
use tower::ServiceExt;

const UA: &str = "Mozilla/5.0 (session tenant browser)";

fn session_tenant() -> TenantId {
    testing::tenant("from-the-session")
}

fn extension_tenant() -> TenantId {
    testing::tenant("from-the-extension")
}

fn resolver(
    store: &MemoryDeviceStore,
) -> LifecycleDeviceResolver<DefaultFingerprintExtractor, MemoryDeviceStore, SystemClock> {
    // No `with_tenant_fn`: the default must find the tenant itself.
    LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(Arc::new(|_: &TenantId| [9u8; 32])),
        DeviceLifecycleService::new(store.clone()),
        SystemClock,
    )
}

async fn login(session: AuthSession, Path(user): Path<String>) -> &'static str {
    session
        .set_authenticated(testing::user(&user), session_tenant(), Utc::now())
        .await;
    "ok"
}

async fn whoami(session: AuthSession) -> &'static str {
    let _ = session.data().await;
    "ok"
}

fn session_layer(store: &MemoryDeviceStore) -> SessionLayer<MemorySessionStore> {
    SessionLayer::new(MemorySessionStore::new(), [42u8; 32])
        .with_secure(false)
        .with_device_resolver(resolver(store))
}

/// No `TenantId` extension anywhere: the tenant is only in the session.
fn session_only_app(store: &MemoryDeviceStore) -> Router {
    Router::new()
        .route("/login/{user}", get(login))
        .route("/me", get(whoami))
        .layer(session_layer(store))
}

/// An outer layer sets a `TenantId` extension, as 0.13.0 adopters do.
fn extension_app(store: &MemoryDeviceStore) -> Router {
    Router::new()
        .route("/login/{user}", get(login))
        .route("/me", get(whoami))
        .layer(session_layer(store))
        .layer(middleware::from_fn(
            |mut req: Request<Body>, next: Next| async move {
                req.extensions_mut().insert(extension_tenant());
                next.run(req).await
            },
        ))
}

fn get_req(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(uri).header(header::USER_AGENT, UA);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::empty()).unwrap()
}

fn session_cookie(resp: &axum::response::Response) -> String {
    let set = resp.headers().get(header::SET_COOKIE).expect("cookie");
    set.to_str().unwrap().split(';').next().unwrap().to_string()
}

fn device_set_cookie(resp: &axum::response::Response) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("__Host-axess_device="))
        .map(str::to_string)
}

#[tokio::test]
async fn a_session_tenant_gets_a_device_cookie_on_the_first_authenticated_request() {
    let store = MemoryDeviceStore::new();
    let app = session_only_app(&store);

    let resp = app
        .clone()
        .oneshot(get_req("/login/alice", None))
        .await
        .unwrap();
    assert!(
        device_set_cookie(&resp).is_none(),
        "login is a guest request"
    );
    let session = session_cookie(&resp);

    let resp = app
        .clone()
        .oneshot(get_req("/me", Some(&session)))
        .await
        .unwrap();
    assert!(
        device_set_cookie(&resp).is_some(),
        "the first authenticated request must set the device cookie"
    );
    assert_eq!(store.len(), 1);
    let owned = store
        .find_for_user(&session_tenant(), &testing::user("alice"), 10)
        .await
        .unwrap();
    assert_eq!(
        owned.len(),
        1,
        "the device is scoped to the session's tenant"
    );
}

#[tokio::test]
async fn a_guest_still_gets_no_device() {
    let store = MemoryDeviceStore::new();
    let app = session_only_app(&store);

    let resp = app.oneshot(get_req("/me", None)).await.unwrap();

    assert!(device_set_cookie(&resp).is_none());
    assert!(store.is_empty());
}

#[tokio::test]
async fn a_tenant_extension_is_still_the_first_choice() {
    let store = MemoryDeviceStore::new();
    let app = extension_app(&store);

    let resp = app
        .clone()
        .oneshot(get_req("/login/alice", None))
        .await
        .unwrap();
    let session = session_cookie(&resp);
    let resp = app
        .clone()
        .oneshot(get_req("/me", Some(&session)))
        .await
        .unwrap();

    assert!(device_set_cookie(&resp).is_some());
    let by_extension = store
        .find_for_user(&extension_tenant(), &testing::user("alice"), 10)
        .await
        .unwrap();
    let by_session = store
        .find_for_user(&session_tenant(), &testing::user("alice"), 10)
        .await
        .unwrap();
    assert_eq!(
        by_extension.len(),
        1,
        "the extension tenant owns the device"
    );
    assert!(by_session.is_empty());
}
