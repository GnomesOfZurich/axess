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

#[tokio::test]
async fn a_cookieless_guest_request_stores_no_device_and_no_session() {
    let store = MemoryDeviceStore::new();
    let app = app(&store);

    let resp = app.oneshot(get_req("/device", None)).await.unwrap();

    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "a guest request that changes nothing must not issue a session cookie"
    );
    assert_eq!(body(resp).await, "none");
    assert!(
        store.is_empty(),
        "a guest request must create no device row"
    );
}

#[tokio::test]
async fn the_device_row_is_created_at_the_first_authenticated_request() {
    let store = MemoryDeviceStore::new();
    let app = app(&store);

    let resp = app
        .clone()
        .oneshot(get_req("/login/alice", None))
        .await
        .unwrap();
    let cookie = cookie_of(&resp);
    assert!(
        store.is_empty(),
        "the login request itself is still a guest request"
    );

    let resp = app
        .clone()
        .oneshot(get_req("/device", Some(&cookie)))
        .await
        .unwrap();
    let id = DeviceId::try_new(body(resp).await).unwrap();

    assert_eq!(store.len(), 1);
    let row = store.load(&tenant(), &id).await.unwrap().unwrap();
    assert_eq!(row.user_id, Some(testing::user("alice")));
}

fn device_cookie_of(resp: &axum::response::Response) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("__Host-axess_device="))
        .map(|v| v.split(';').next().unwrap().to_string())
}

#[tokio::test]
async fn a_guest_presenting_the_device_cookie_reads_the_device_without_writing() {
    let store = MemoryDeviceStore::new();
    let app = app(&store);

    // Alice logs in and gets her device and its cookie.
    let resp = app
        .clone()
        .oneshot(get_req("/login/alice", None))
        .await
        .unwrap();
    let session = cookie_of(&resp);
    let resp = app
        .clone()
        .oneshot(get_req("/device", Some(&session)))
        .await
        .unwrap();
    let device_cookie =
        device_cookie_of(&resp).expect("the first authenticated request issues the cookie");
    let alice_device = body(resp).await;
    let rows = store.len();

    // The same browser, signed out: the cookie proves the device in memory.
    let resp = app
        .oneshot(get_req("/device", Some(&device_cookie)))
        .await
        .unwrap();
    assert!(resp.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(body(resp).await, alice_device);
    assert_eq!(store.len(), rows);
}

/// Another site linking to this one sends the session cookie and, being
/// `SameSite=Strict`, not the device cookie: the session keeps its device.
#[tokio::test]
async fn a_visit_without_the_device_cookie_keeps_the_sessions_device() {
    let store = MemoryDeviceStore::new();
    let app = app(&store);
    let resp = app
        .clone()
        .oneshot(get_req("/login/alice", None))
        .await
        .unwrap();
    let session = cookie_of(&resp);
    let resp = app
        .clone()
        .oneshot(get_req("/device", Some(&session)))
        .await
        .unwrap();
    let first = body(resp).await;

    let resp = app
        .clone()
        .oneshot(get_req("/device", Some(&session)))
        .await
        .unwrap();
    assert!(device_cookie_of(&resp).is_none(), "no second device cookie");
    assert_eq!(body(resp).await, first);
    assert_eq!(store.len(), 1);
}

/// A device row left by a guest request (or by an earlier release) has the
/// fingerprint a visitor can copy. Signing in with the same headers must not
/// hand it over.
#[tokio::test]
async fn an_unowned_trusted_device_with_the_same_fingerprint_is_not_handed_over() {
    use axess_core::DeviceFingerprintExtractor;
    let store = MemoryDeviceStore::new();
    let probe = get_req("/device", None).into_parts().0;
    let fingerprint = extractor()
        .extract(&tenant(), &probe, None)
        .expect("a fingerprint");
    let legacy = DeviceId::try_new("11111111-1111-4111-8111-111111111111").unwrap();
    store
        .save(
            &axess_core::Device {
                id: legacy,
                tenant_id: tenant(),
                user_id: None,
                trust_level: DeviceTrustLevel::Trusted,
                fingerprint_hash: fingerprint,
                first_seen_at: Utc::now(),
                last_seen_at: Utc::now(),
                revoked_at: None,
                demoted_at: None,
                bindings: Vec::new(),
            },
            Utc::now(),
        )
        .await
        .unwrap();
    let app = app(&store);

    let resp = app
        .clone()
        .oneshot(get_req("/login/mallory", None))
        .await
        .unwrap();
    let session = cookie_of(&resp);
    let resp = app
        .clone()
        .oneshot(get_req("/device", Some(&session)))
        .await
        .unwrap();
    let mallory_device = body(resp).await;

    assert_ne!(mallory_device, legacy.to_string());
    let kept = store.load(&tenant(), &legacy).await.unwrap().unwrap();
    assert_eq!(kept.user_id, None, "the legacy device is not claimed");
    assert_eq!(kept.trust_level, DeviceTrustLevel::Trusted);
}
