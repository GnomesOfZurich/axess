//! The default device resolver is given the authenticated user by the
//! session layer, so one user never reuses another user's device.

#![cfg(all(feature = "memory", feature = "device"))]

use std::sync::Arc;

use axess_clock::SystemClock;
use axess_core::authn::ids::{DeviceId, TenantId, testing};
use axess_core::session::{extractor::AuthSession, layer::SessionLayer, store::MemorySessionStore};
use axess_core::{
    DefaultFingerprintExtractor, DeviceLifecycleService, DeviceStore, DeviceTrustLevel,
    LifecycleDeviceResolver, MemoryDeviceStore,
};
use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{Request, header},
    routing::get,
};
use chrono::Utc;
use tower::ServiceExt;

fn tenant() -> TenantId {
    testing::tenant("tenant-1")
}

const UA: &str = "Mozilla/5.0 (shared office browser)";

fn extractor() -> DefaultFingerprintExtractor {
    DefaultFingerprintExtractor::new(Arc::new(|_: &TenantId| [9u8; 32]))
}

async fn login(session: AuthSession, Path(user): Path<String>) -> &'static str {
    session
        .set_authenticated(testing::user(&user), tenant(), Utc::now())
        .await;
    "ok"
}

async fn device(session: AuthSession) -> String {
    match session.data().await.device_id {
        Some(id) => id.to_string(),
        None => "none".into(),
    }
}

fn app(store: &MemoryDeviceStore) -> Router {
    // The default `user_fn`: whatever the session layer supplies.
    let resolver = LifecycleDeviceResolver::new(
        extractor(),
        DeviceLifecycleService::new(store.clone()),
        SystemClock,
    )
    .with_tenant_fn(|_| Some(tenant()));
    Router::new()
        .route("/login/{user}", get(login))
        .route("/device", get(device))
        .layer(
            SessionLayer::new(MemorySessionStore::new(), [42u8; 32])
                .with_secure(false)
                .with_device_resolver(resolver),
        )
}

fn get_req(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(uri).header(header::USER_AGENT, UA);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::empty()).unwrap()
}

fn cookie_of(resp: &axum::response::Response) -> String {
    let set = resp.headers().get(header::SET_COOKIE).expect("cookie");
    set.to_str().unwrap().split(';').next().unwrap().to_string()
}

async fn body(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 256).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn an_authenticated_user_does_not_get_another_users_trusted_device() {
    let store = MemoryDeviceStore::new();

    // The victim's device for this browser fingerprint, Trusted. Created
    // through a resolver that names the victim as owner.
    let owner_resolver = LifecycleDeviceResolver::new(
        extractor(),
        DeviceLifecycleService::new(store.clone()),
        SystemClock,
    )
    .with_tenant_fn(|_| Some(tenant()))
    .with_user_fn(|_| Some(testing::user("victim")));
    let owner_app = Router::new().route("/device", get(device)).layer(
        SessionLayer::new(MemorySessionStore::new(), [42u8; 32])
            .with_secure(false)
            .with_device_resolver(owner_resolver),
    );
    let victim_device: String =
        body(owner_app.oneshot(get_req("/device", None)).await.unwrap()).await;
    let victim_id = DeviceId::try_new(&victim_device).unwrap();
    store
        .set_trust_level(&tenant(), &victim_id, DeviceTrustLevel::Trusted, Utc::now())
        .await
        .unwrap();

    // The attacker, same office, same browser, logs in and asks again.
    let app = app(&store);
    let resp = app
        .clone()
        .oneshot(get_req("/login/attacker", None))
        .await
        .unwrap();
    let cookie = cookie_of(&resp);
    let resp = app
        .clone()
        .oneshot(get_req("/device", Some(&cookie)))
        .await
        .unwrap();
    let attacker_device = body(resp).await;

    assert_ne!(
        attacker_device, victim_device,
        "the attacker must not be handed the victim's device"
    );
    let row = store
        .load(&tenant(), &DeviceId::try_new(&attacker_device).unwrap())
        .await
        .unwrap()
        .expect("a device was created for the attacker");
    assert_eq!(row.user_id, Some(testing::user("attacker")));
    assert_eq!(row.trust_level, DeviceTrustLevel::Unknown);
    let victim_row = store.load(&tenant(), &victim_id).await.unwrap().unwrap();
    assert_eq!(victim_row.trust_level, DeviceTrustLevel::Trusted);
}
