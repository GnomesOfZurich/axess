//! The device a request resolves holds for the person it was resolved for.
//! When another person signs in on a signed-in session within one request,
//! the session names no device for the rest of that request and its row is
//! written without one; the next request resolves a device for the new
//! person. A device resolved for nobody (a guest's request) holds for
//! whoever signs in. A step-up and an impersonation keep the person at the
//! browser, and with them the device. A device a row holds while nobody is
//! signed in holds for nobody on a request that resolves nothing.

#![cfg(all(feature = "testing", feature = "memory", feature = "device"))]

use axess_core::testing::fixtures as common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::ids::{DeviceId, TenantId};
use axess_core::authn::service::AuthnService;
use axess_core::authn::types::Tenant;
use axess_core::session::store::SessionStore;
use axess_core::session::{extractor::AuthSession, layer::SessionLayer, store::MemorySessionStore};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::{
    BoundDevice, DefaultFingerprintExtractor, DeviceLifecycleService, DeviceResolver, DeviceStore,
    LifecycleDeviceResolver, MemoryDeviceStore,
};
use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{Request, header, request::Parts},
    routing::get,
};
use common::{
    password_config, password_method, test_tenant, test_user, test_user_in_tenant, tid, uid,
    user_scope,
};
use tower::ServiceExt;

const UA: &str = "Mozilla/5.0 (a shared browser)";
const PASSWORD: &str = "Sample2+";
const DEVICE: &str = "__Host-axess_device";

fn tenant() -> TenantId {
    test_tenant().id
}

/// What the session answers about its device: the device it names, the
/// device this request proved, and that device as the signed-in user's.
async fn answers(session: &AuthSession) -> String {
    let device = session
        .device_id()
        .await
        .map_or("none".to_string(), |id| id.to_string());
    let proven = session
        .proven_device()
        .await
        .map_or("none".to_string(), |proven| proven.id().to_string());
    let user_device = session
        .user_device()
        .await
        .map_or("none".to_string(), |owned| {
            format!("{}/{}", owned.user(), owned.device().id())
        });
    format!("{device} {proven} {user_device}")
}

struct World {
    app: Router,
    /// The same routes and sessions behind a layer with no resolver.
    unresolved: Router,
    /// While set, the resolver of `app` fails.
    failing: Arc<AtomicBool>,
    sessions: MemorySessionStore,
    devices: MemoryDeviceStore,
}

#[derive(Debug, thiserror::Error)]
#[error("device store unavailable")]
struct StoreDown;

/// A resolver that fails while its flag is set, as one over a device store
/// in an outage does, and otherwise answers as the one it wraps.
struct FailsWhile<R> {
    inner: R,
    failing: Arc<AtomicBool>,
}

impl<R: DeviceResolver> DeviceResolver for FailsWhile<R> {
    type Error = StoreDown;

    async fn resolve(&self, parts: &Parts) -> Result<Option<BoundDevice>, Self::Error> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(StoreDown);
        }
        self.inner.resolve(parts).await.map_err(|_| StoreDown)
    }
}

/// A browser: the cookies it holds.
#[derive(Clone, Default)]
struct Browser(BTreeMap<String, String>);

impl World {
    /// `GET uri` from `browser`, keeping the cookies the answer sets.
    async fn get(&self, browser: &mut Browser, uri: &str) -> String {
        Self::get_on(&self.app, browser, uri).await
    }

    /// `GET uri` from `browser` through `app`, keeping the cookies the
    /// answer sets.
    async fn get_on(app: &Router, browser: &mut Browser, uri: &str) -> String {
        let cookies = browser
            .0
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        let mut request = Request::get(uri).header(header::USER_AGENT, UA);
        if !cookies.is_empty() {
            request = request.header(header::COOKIE, cookies);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        for value in response.headers().get_all(header::SET_COOKIE) {
            let text = value.to_str().unwrap();
            let (pair, attributes) = text.split_once(';').unwrap_or((text, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attributes.contains("Max-Age=0") {
                browser.0.remove(name);
            } else {
                browser.0.insert(name.to_string(), value.to_string());
            }
        }
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// `user` signs in on a fresh browser, whose first signed-in request is
    /// given a device and its cookie. Returns the browser and the device.
    async fn signed_in(&self, user: &str) -> (Browser, DeviceId) {
        let mut browser = Browser::default();
        assert_eq!(
            self.get(&mut browser, &format!("/sign-in/{user}")).await,
            "in"
        );
        let device = self.get(&mut browser, "/device").await;
        assert!(browser.0.contains_key(DEVICE), "the device cookie");
        (browser, device.parse().expect("a device"))
    }

    /// The device the stored row of `user`'s one session names.
    async fn stored_device(&self, user: &str) -> Option<DeviceId> {
        let rows = self
            .sessions
            .find_sessions_for_user(&uid(user), 10)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "one session of {user}");
        rows[0].1.device_id
    }
}

/// Alice (`u1`, who has a password), Bob (`u2`), an administrator, and
/// Carol (`u3`) in another tenant.
fn world() -> World {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_tenant(Tenant {
            id: tid("t2"),
            identifier: "other".into(),
            ..test_tenant()
        })
        .with_user(test_user("u1", "alice"))
        .with_user(test_user("u2", "bob"))
        .with_user(test_user("admin", "ops"))
        .with_user(test_user_in_tenant("u3", "carol", "t2"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config(PASSWORD))
        .with_method(&uid("u1"), password_method());
    let devices = MemoryDeviceStore::new();
    let service = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_device_store(devices.clone())
        .build();
    let sessions = MemorySessionStore::new().with_clock(Arc::new(clock.clone()));
    let resolver = LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(Arc::new(|_: &TenantId| [9u8; 32])),
        DeviceLifecycleService::new(devices.clone()),
        clock.clone(),
    )
    .with_tenant_fn(|_| Some(tenant()));
    let failing = Arc::new(AtomicBool::new(false));
    let layer = SessionLayer::without_registry_insecure(
        sessions.clone(),
        axess_core::testing::test_key(42),
        Arc::new(axess_core::session::UnrecordedSessionEnds),
    )
    .with_clock(clock.clone())
    .with_secure(false);
    let unresolved = routes(&clock, &service).layer(layer.clone());
    let app = routes(&clock, &service).layer(layer.with_device_resolver(FailsWhile {
        inner: resolver,
        failing: failing.clone(),
    }));
    World {
        app,
        unresolved,
        failing,
        sessions,
        devices,
    }
}

type Authn = AuthnService<MockIdentityStore, MockFactorStore>;

fn routes(clock: &MockClock, service: &Authn) -> Router {
    let audited = |service: &Authn| service.with_audit_context(AuditContext::default());
    Router::new()
        .route(
            "/sign-in/{user}",
            get({
                let clock = clock.clone();
                move |session: AuthSession, Path(user): Path<String>| async move {
                    session
                        .set_authenticated(uid(&user), tenant(), clock.now())
                        .await;
                    "in"
                }
            }),
        )
        .route(
            "/sign-out",
            get(|session: AuthSession| async move {
                session.clear().await;
                "out"
            }),
        )
        .route(
            "/device",
            get(|session: AuthSession| async move {
                session
                    .device_id()
                    .await
                    .map_or("none".to_string(), |id| id.to_string())
            }),
        )
        .route(
            "/answers",
            get(|session: AuthSession| async move { answers(&session).await }),
        )
        // A login of `user` begun, with what the session answers after it.
        .route(
            "/begin-log-in/{user}",
            get(
                |session: AuthSession, Path(user): Path<String>| async move {
                    session
                        .begin_authenticating(
                            uid(&user),
                            tenant(),
                            Arc::from("password"),
                            vec![FactorKind::Password],
                        )
                        .await;
                    answers(&session).await
                },
            ),
        )
        // A login of `user` begun and completed in one request, with what
        // the session answered before it and after it.
        .route(
            "/log-in/{user}",
            get({
                let clock = clock.clone();
                move |session: AuthSession, Path(user): Path<String>| async move {
                    let before = answers(&session).await;
                    session
                        .begin_authenticating(
                            uid(&user),
                            tenant(),
                            Arc::from("password"),
                            vec![FactorKind::Password],
                        )
                        .await;
                    session
                        .advance_factor(&FactorKind::Password, clock.now())
                        .await;
                    format!("{before} | {}", answers(&session).await)
                }
            }),
        )
        .route(
            "/begin-step-up",
            get({
                let service = service.clone();
                move |session: AuthSession| async move {
                    let begun = audited(&service)
                        .begin_step_up(&session, vec![FactorKind::Password])
                        .await;
                    format!("{} {}", begun.is_ok(), answers(&session).await)
                }
            }),
        )
        .route(
            "/verify",
            get({
                let service = service.clone();
                move |session: AuthSession| async move {
                    let credential = FactorCredential::Password(ZeroizedString::new(PASSWORD));
                    let verified = audited(&service).verify_factor(&credential, &session).await;
                    format!("{} {}", verified.is_ok(), answers(&session).await)
                }
            }),
        )
        .route(
            "/impersonate",
            get({
                let service = service.clone();
                move |session: AuthSession| async move {
                    let begun = audited(&service)
                        .begin_impersonation(
                            &test_user("admin", "ops"),
                            &test_user("u1", "alice"),
                            &session,
                        )
                        .await;
                    format!("{} {}", begun.is_ok(), answers(&session).await)
                }
            }),
        )
        .route(
            "/impersonate-across",
            get({
                let service = service.clone();
                move |session: AuthSession| async move {
                    let begun = audited(&service)
                        .begin_impersonation_across_tenants(
                            &uid("admin"),
                            &test_user_in_tenant("u3", "carol", "t2"),
                            &session,
                        )
                        .await;
                    format!("{} {}", begun.is_ok(), answers(&session).await)
                }
            }),
        )
        .route(
            "/end-impersonation",
            get({
                let service = service.clone();
                move |session: AuthSession| async move {
                    let ended = audited(&service).end_impersonation(&session).await;
                    format!("{} {}", ended.is_ok(), answers(&session).await)
                }
            }),
        )
}

/// Bob signs in on a session of Alice's, on a request that proved Alice's
/// device by its token: from the sign-in on the session names no device and
/// no proven one, its row is written without the device, and the request
/// after it resolves a device for Bob.
#[tokio::test]
async fn another_persons_sign_in_leaves_the_session_without_the_first_persons_device() {
    let w = world();
    let (mut browser, alices) = w.signed_in("u1").await;
    let alice = format!("{alices} {alices} {}/{alices}", uid("u1"));
    assert_eq!(
        w.get(&mut browser, "/log-in/u2").await,
        format!("{alice} | none none none")
    );
    assert_eq!(w.stored_device("u2").await, None, "the row names no device");

    let next = w.get(&mut browser, "/device").await;
    assert_ne!(next, alices.to_string(), "not Alice's device");
    let bobs = w.stored_device("u2").await.expect("a device for Bob");
    assert_eq!(next, bobs.to_string());
    let owner = w
        .devices
        .load_fresh(&tenant(), &bobs)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.user_id, Some(uid("u2")), "the device is Bob's");
}

/// A login takes the browser's device: a guest's request proves Bob's device
/// by its token (the device was resolved for nobody), and the handler
/// completes Bob's login on it. The session names the device as Bob's, and
/// the row holds it.
#[tokio::test]
async fn a_login_on_a_guests_request_takes_the_browsers_device() {
    let w = world();
    let (mut browser, bobs) = w.signed_in("u2").await;
    assert_eq!(w.get(&mut browser, "/sign-out").await, "out");
    assert!(browser.0.contains_key(DEVICE), "the device cookie stays");
    let answered = w.get(&mut browser, "/log-in/u2").await;
    assert_eq!(
        answered.split(" | ").nth(1),
        Some(format!("{bobs} {bobs} {}/{bobs}", uid("u2")).as_str()),
        "{answered}"
    );
    assert_eq!(w.stored_device("u2").await, Some(bobs));
}

/// The person at the browser stays through a step-up, begun and completed,
/// and the session keeps its device and its row keeps it.
#[tokio::test]
async fn a_step_up_keeps_the_device() {
    let w = world();
    let (mut browser, alices) = w.signed_in("u1").await;
    let begun = w.get(&mut browser, "/begin-step-up").await;
    assert!(
        begun.starts_with(&format!("true {alices} {alices}")),
        "{begun}"
    );
    assert_eq!(w.stored_device("u1").await, Some(alices));
    let verified = w.get(&mut browser, "/verify").await;
    assert!(
        verified.starts_with(&format!("true {alices} {alices}")),
        "{verified}"
    );
    assert_eq!(w.stored_device("u1").await, Some(alices));
}

/// The start of an impersonation, within the administrator's tenant and
/// across tenants, keeps the administrator at the browser and with them the
/// device: the session answers it and the row of the impersonated session
/// keeps it. The end of the impersonation leaves no device.
#[tokio::test]
async fn an_impersonation_keeps_the_administrators_device() {
    for (path, target) in [("/impersonate", "u1"), ("/impersonate-across", "u3")] {
        let w = world();
        let (mut browser, admins) = w.signed_in("admin").await;
        let begun = w.get(&mut browser, path).await;
        assert!(
            begun.starts_with(&format!("true {admins} {admins}")),
            "{path}: {begun}"
        );
        assert_eq!(w.stored_device(target).await, Some(admins), "{path}");
        let device = w.get(&mut browser, "/device").await;
        assert_eq!(device, admins.to_string(), "{path}");
        assert_eq!(
            w.get(&mut browser, "/end-impersonation").await,
            "true none none none",
            "{path}"
        );
    }
}

/// A device a row holds while a login is in progress was resolved on an
/// earlier request, for the user that login names. On a request that
/// resolves nothing (the resolver fails, or none is installed) it holds for
/// nobody: another person's login completed on that request leaves their
/// session and its row without it.
#[tokio::test]
async fn a_device_stored_during_a_login_does_not_pass_to_another_person_on_an_unresolved_request() {
    for resolver_fails in [true, false] {
        let w = world();
        let (mut browser, alices) = w.signed_in("u1").await;
        assert_eq!(w.get(&mut browser, "/sign-out").await, "out");
        let begun = w.get(&mut browser, "/begin-log-in/u1").await;
        assert!(
            begun.starts_with(&format!("{alices} {alices}")),
            "the login in progress holds the browser's device: {begun}"
        );
        let answered = if resolver_fails {
            w.failing.store(true, Ordering::SeqCst);
            w.get(&mut browser, "/log-in/u2").await
        } else {
            World::get_on(&w.unresolved, &mut browser, "/log-in/u2").await
        };
        assert_eq!(
            answered, "none none none | none none none",
            "resolver fails: {resolver_fails}"
        );
        assert_eq!(
            w.stored_device("u2").await,
            None,
            "resolver fails: {resolver_fails}"
        );
    }
}
