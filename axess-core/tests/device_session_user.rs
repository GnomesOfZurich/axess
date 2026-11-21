//! The default device resolver is given the authenticated user by the
//! session layer, so one user never reuses another user's device.

#![cfg(all(feature = "memory", feature = "device", feature = "testing"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::testing::AuthSessionTestExt;
use std::sync::Arc;

use axess_core::authn::ids::{DeviceId, TenantId, testing};
use axess_core::device::{BoundDevice, DeviceResolver};
use axess_core::session::{extractor::AuthSession, layer::SessionLayer, store::MemorySessionStore};
use axess_core::{
    DefaultFingerprintExtractor, DeviceLifecycleService, DeviceStore, DeviceTrustLevel,
    LifecycleDeviceResolver, MemoryDeviceStore,
};
use axum::http::request::Parts;
use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{Request, header},
    routing::get,
};
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
        .set_authenticated(testing::user(&user), tenant(), common::start())
        .await;
    "ok"
}

async fn device(session: AuthSession) -> String {
    match session.data().await.device_id {
        Some(id) => id.to_string(),
        None => "none".into(),
    }
}

async fn proven(session: AuthSession) -> &'static str {
    if session.proven_device().await.is_some() {
        "proven"
    } else {
        "unproven"
    }
}

fn lifecycle_resolver(clock: &MockClock, store: &MemoryDeviceStore) -> impl DeviceResolver {
    // The default `user_fn`: whatever the session layer supplies.
    LifecycleDeviceResolver::new(
        extractor(),
        DeviceLifecycleService::new(store.clone()),
        clock.clone(),
    )
    .with_tenant_fn(|_| Some(tenant()))
}

fn app(clock: &MockClock, store: &MemoryDeviceStore) -> Router {
    app_with(lifecycle_resolver(clock, store), clock)
}

fn app_with(resolver: impl DeviceResolver, clock: &MockClock) -> Router {
    Router::new()
        .route("/login/{user}", get(login))
        .route("/device", get(device))
        .route("/proven", get(proven))
        .layer(
            SessionLayer::without_registry_insecure(
                MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone())),
                axess_core::testing::test_key(42),
                std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
            )
            .with_clock(clock.clone())
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

/// A request that names no `User-Agent`, so the default extractor computes no
/// fingerprint for it.
fn get_req_without_user_agent(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(uri);
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
    let clock = common::test_clock();
    let store = MemoryDeviceStore::new();

    // The victim's device for this browser fingerprint, Trusted. Created
    // through a resolver that names the victim as owner.
    let owner_resolver = LifecycleDeviceResolver::new(
        extractor(),
        DeviceLifecycleService::new(store.clone()),
        clock.clone(),
    )
    .with_tenant_fn(|_| Some(tenant()))
    .with_user_fn(|_| Some(testing::user("victim")));
    let owner_app = Router::new().route("/device", get(device)).layer(
        SessionLayer::without_registry_insecure(
            MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone())),
            axess_core::testing::test_key(42),
            std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
        )
        .with_clock(clock.clone())
        .with_secure(false)
        .with_device_resolver(owner_resolver),
    );
    let victim_device: String =
        body(owner_app.oneshot(get_req("/device", None)).await.unwrap()).await;
    let victim_id = DeviceId::try_new(&victim_device).unwrap();
    store
        .set_trust_level(
            &tenant(),
            &victim_id,
            DeviceTrustLevel::Trusted,
            common::start(),
        )
        .await
        .unwrap();

    // The attacker, same office, same browser, logs in and asks again.
    let app = app(&clock, &store);
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
    let clock = common::test_clock();
    let store = MemoryDeviceStore::new();
    let app = app(&clock, &store);

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
    let clock = common::test_clock();
    let store = MemoryDeviceStore::new();
    let app = app(&clock, &store);

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
    let clock = common::test_clock();
    let store = MemoryDeviceStore::new();
    let app = app(&clock, &store);

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
    let clock = common::test_clock();
    let store = MemoryDeviceStore::new();
    let app = app(&clock, &store);
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

/// A resolver that proves the device on its first answer, as the lifecycle
/// resolver does, and from then on only recognises that device, as a
/// resolver does that found it by other means than its token.
struct ProvesOnce<R> {
    inner: R,
    seen: std::sync::Mutex<Option<DeviceId>>,
}

impl<R: DeviceResolver> DeviceResolver for ProvesOnce<R> {
    type Error = R::Error;

    async fn resolve(&self, parts: &Parts) -> Result<Option<BoundDevice>, Self::Error> {
        let seen = *self.seen.lock().unwrap();
        if let Some(id) = seen {
            return Ok(Some(BoundDevice::Unproven(id)));
        }
        let resolved = self.inner.resolve(parts).await?;
        *self.seen.lock().unwrap() = resolved.map(|bound| bound.id());
        Ok(resolved)
    }
}

/// A session reads as proven for the request whose resolver proved its
/// device. When a later request only recognises the same device, the session
/// keeps the device and no longer reads as proven.
#[tokio::test]
async fn a_request_that_only_recognises_the_sessions_device_leaves_it_unproven() {
    let clock = common::test_clock();
    let store = MemoryDeviceStore::new();
    let app = app_with(
        ProvesOnce {
            inner: lifecycle_resolver(&clock, &store),
            seen: std::sync::Mutex::new(None),
        },
        &clock,
    );
    let resp = app
        .clone()
        .oneshot(get_req("/login/alice", None))
        .await
        .unwrap();
    let session = cookie_of(&resp);
    let ask = |uri: &'static str| {
        let (app, request) = (app.clone(), get_req(uri, Some(&session)));
        async move { body(app.oneshot(request).await.unwrap()).await }
    };

    assert_eq!(ask("/proven").await, "proven");
    let device_id = ask("/device").await;
    assert_ne!(device_id, "none");
    assert_eq!(ask("/proven").await, "unproven");
    assert_eq!(ask("/device").await, device_id, "the device is kept");
}

#[derive(Debug, thiserror::Error)]
#[error("device store unavailable")]
struct StoreDown;

/// A resolver that proves the device on its first answer, as the lifecycle
/// resolver does, and fails from then on, as a device store does during an
/// outage.
struct ProvesThenFails<R> {
    inner: R,
    proved: std::sync::atomic::AtomicBool,
}

impl<R: DeviceResolver> DeviceResolver for ProvesThenFails<R> {
    type Error = StoreDown;

    async fn resolve(&self, parts: &Parts) -> Result<Option<BoundDevice>, Self::Error> {
        use std::sync::atomic::Ordering;
        if self.proved.load(Ordering::SeqCst) {
            return Err(StoreDown);
        }
        let resolved = self.inner.resolve(parts).await.map_err(|_| StoreDown)?;
        self.proved.store(resolved.is_some(), Ordering::SeqCst);
        Ok(resolved)
    }
}

/// A request whose resolver failed proved nothing: the session keeps the
/// device it was bound to, and the proof of an earlier request does not
/// stand in for this one, whatever the session store kept of it.
#[tokio::test]
async fn a_resolver_failure_keeps_the_device_and_no_proof_of_an_earlier_request() {
    let clock = common::test_clock();
    let store = MemoryDeviceStore::new();
    let app = app_with(
        ProvesThenFails {
            inner: lifecycle_resolver(&clock, &store),
            proved: std::sync::atomic::AtomicBool::new(false),
        },
        &clock,
    );
    let resp = app
        .clone()
        .oneshot(get_req("/login/alice", None))
        .await
        .unwrap();
    let session = cookie_of(&resp);
    let ask = |uri: &'static str| {
        let (app, request) = (app.clone(), get_req(uri, Some(&session)));
        async move { body(app.oneshot(request).await.unwrap()).await }
    };

    assert_eq!(ask("/proven").await, "proven");
    assert_eq!(ask("/proven").await, "unproven");
    let device_id = ask("/device").await;
    assert_ne!(device_id, "none", "the device is kept");
    assert_eq!(store.len(), 1);
}

/// A request of a signed-in session that carries no `User-Agent` cannot be
/// fingerprinted, and the fingerprint has no part in finding a device: the
/// session keeps the device it is bound to and no device is created, so a
/// later request that presents no device cookie finds that device instead of
/// minting another. A guest's request without one has no device, even with
/// the device cookie that proves the device to a guest that sends one.
#[tokio::test]
async fn a_request_without_a_user_agent_keeps_the_sessions_device() {
    let clock = common::test_clock();
    let store = MemoryDeviceStore::new();
    let app = app(&clock, &store);
    let resp = app
        .clone()
        .oneshot(get_req("/login/alice", None))
        .await
        .unwrap();
    let session = cookie_of(&resp);
    // Only the session cookie travels: the device cookie is never sent back.
    let ask = |request: Request<Body>| {
        let app = app.clone();
        async move { body(app.oneshot(request).await.unwrap()).await }
    };

    let resp = app
        .clone()
        .oneshot(get_req("/device", Some(&session)))
        .await
        .unwrap();
    let device_cookie =
        device_cookie_of(&resp).expect("the first authenticated request issues the cookie");
    let device_id = body(resp).await;
    assert_ne!(
        device_id, "none",
        "the first authenticated request has a device"
    );
    assert_eq!(store.len(), 1);

    let bare = ask(get_req_without_user_agent("/device", Some(&session))).await;
    assert_eq!(bare, device_id, "the session keeps its device");
    assert_eq!(store.len(), 1, "no device is created");

    let later = ask(get_req("/device", Some(&session))).await;
    assert_eq!(
        later, device_id,
        "a later request finds the session's device"
    );
    assert_eq!(store.len(), 1, "and creates no other");

    let guest = ask(get_req("/device", Some(&device_cookie))).await;
    assert_eq!(guest, device_id, "the cookie proves the device to a guest");
    let guest = ask(get_req_without_user_agent("/device", Some(&device_cookie))).await;
    assert_eq!(guest, "none", "a guest without a User-Agent has no device");
    assert_eq!(store.len(), 1);
}

/// The fingerprint has no part in finding a device: a request of a signed-in
/// session that sends no `User-Agent` and presents the device cookie proves
/// the device by its token, as any other request does.
#[tokio::test]
async fn a_signed_in_request_without_a_user_agent_is_proven_by_its_device_token() {
    let clock = common::test_clock();
    let store = MemoryDeviceStore::new();
    let app = app(&clock, &store);
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
    let device_id = body(resp).await;
    let both = format!("{session}; {device_cookie}");
    let ask = |uri: &'static str, cookie: &str| {
        let (app, request) = (app.clone(), get_req_without_user_agent(uri, Some(cookie)));
        async move { body(app.oneshot(request).await.unwrap()).await }
    };

    assert_eq!(ask("/proven", &both).await, "proven", "the token proves it");
    assert_eq!(ask("/device", &both).await, device_id);
    assert_eq!(
        ask("/proven", &session).await,
        "unproven",
        "the session cookie alone proves nothing"
    );
    assert_eq!(ask("/device", &session).await, device_id);
    assert_eq!(store.len(), 1, "no device is created");
}

/// A new device row stores the request's fingerprint, so a signed-in
/// session whose request sends no `User-Agent` and that has no device is
/// given none. The next request that sends one creates it.
#[tokio::test]
async fn a_signed_in_request_without_a_user_agent_creates_no_device() {
    let clock = common::test_clock();
    let store = MemoryDeviceStore::new();
    let app = app(&clock, &store);
    let resp = app
        .clone()
        .oneshot(get_req("/login/alice", None))
        .await
        .unwrap();
    let session = cookie_of(&resp);
    let ask = |request: Request<Body>| {
        let app = app.clone();
        async move { body(app.oneshot(request).await.unwrap()).await }
    };

    let bare = ask(get_req_without_user_agent("/device", Some(&session))).await;
    assert_eq!(bare, "none", "no device is created without a fingerprint");
    assert!(store.is_empty());

    let device_id = ask(get_req("/device", Some(&session))).await;
    assert_ne!(device_id, "none", "a request with a User-Agent creates it");
    assert_eq!(store.len(), 1);
}

/// A device row left by a guest request (or by an earlier release) has the
/// fingerprint a visitor can copy. Signing in with the same headers must not
/// hand it over.
#[tokio::test]
async fn an_unowned_trusted_device_with_the_same_fingerprint_is_not_handed_over() {
    use axess_core::DeviceFingerprintExtractor;
    let clock = common::test_clock();
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
                first_seen_at: common::start(),
                last_seen_at: common::start(),
                revoked_at: None,
                demoted_at: None,
                bindings: Vec::new(),
            },
            common::start(),
        )
        .await
        .unwrap();
    let app = app(&clock, &store);

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
