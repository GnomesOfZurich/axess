#![cfg(all(feature = "testing", feature = "memory", feature = "device"))]
//! A device is proven by the request that presents its token, or the request
//! it is created on, and by no other. A request that carries the session
//! cookie and not the device cookie keeps the session's device, as a label:
//! it does not read as proven, and the per-account lockout does not exempt
//! it.

use axess_core::session::SessionKey;
use axess_core::testing::fixtures as common;

use std::sync::Arc;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::AuthnService;
use axess_core::authn::types::LockoutPolicy;
use axess_core::session::refresh::{
    IssueRequest, Refresh, RefreshTokenConfig, issue_refresh_token,
};
use axess_core::session::store::SessionStore;
use axess_core::session::{extractor::AuthSession, layer::SessionLayer, store::MemorySessionStore};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::testing::{AuthSessionTestExt, MemoryRefreshTokenStore, MockRng, test_session};
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
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use tower::ServiceExt;

const UA: &str = "Mozilla/5.0 (the owner's browser)";
const PASSWORD: &str = "Sample2+";

type Service = AuthnService<MockIdentityStore, MockFactorStore>;

struct World {
    app: Router,
    clock: MockClock,
    sessions: MemorySessionStore,
    devices: MemoryDeviceStore,
    identity: MockIdentityStore,
    service: Service,
}

fn tenant() -> TenantId {
    test_tenant().id
}

async fn device(session: AuthSession) -> String {
    match session.device_id().await {
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

fn world() -> World {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(LockoutPolicy {
            max_attempts: 3,
            duration: Some(std::time::Duration::from_secs(900)),
            ..LockoutPolicy::default()
        });
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config(PASSWORD))
        .with_method(&uid("u1"), password_method());
    let devices = MemoryDeviceStore::new();
    let service = AuthnService::builder(identity.clone(), factors)
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

    let (sign_in_clock, entry, step_up) = (clock.clone(), service.clone(), service.clone());
    let app = Router::new()
        .route(
            "/sign-in",
            get(move |session: AuthSession| {
                let now = sign_in_clock.now();
                async move {
                    session.set_authenticated(uid("u1"), tenant(), now).await;
                    "in"
                }
            }),
        )
        .route("/device", get(device))
        .route("/proven", get(proven))
        .route(
            "/sid",
            get(|session: AuthSession| async move { session.session_key().await.to_string() }),
        )
        // A password entry in one request, on whatever session the request
        // carries.
        .route(
            "/password/{password}",
            get(
                move |session: AuthSession, Path(password): Path<String>| async move {
                    let outcome = entry
                        .with_audit_context(AuditContext::default())
                        .login_with_password("alice", "default", &password, &session)
                        .await;
                    format!("{outcome:?}")
                },
            ),
        )
        // A step-up begun and answered in one request.
        .route(
            "/step-up/{password}",
            get(
                move |session: AuthSession, Path(password): Path<String>| async move {
                    let service = step_up.with_audit_context(AuditContext::default());
                    if let Err(refused) = service
                        .begin_step_up(&session, vec![FactorKind::Password])
                        .await
                    {
                        return format!("not begun: {refused:?}");
                    }
                    let credential = FactorCredential::Password(ZeroizedString::new(&password));
                    format!("{:?}", service.verify_factor(&credential, &session).await)
                },
            ),
        )
        .layer(
            SessionLayer::without_registry_insecure(
                sessions.clone(),
                axess_core::testing::test_key(42),
                std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
            )
            .with_clock(clock.clone())
            .with_secure(false)
            .with_device_resolver(resolver),
        );
    World {
        app,
        clock,
        sessions,
        devices,
        identity,
        service,
    }
}

/// What a browser holds: the session cookie and, once a device was created
/// for it, the device cookie.
#[derive(Clone)]
struct Browser {
    session: String,
    device: String,
    device_id: String,
}

impl Browser {
    /// Both cookies, as a request from the browser itself sends them.
    fn both(&self) -> String {
        format!("{}; {}", self.session, self.device)
    }
}

impl World {
    async fn get(&self, uri: &str, cookies: Option<&str>) -> axum::response::Response {
        let mut request = Request::get(uri).header(header::USER_AGENT, UA);
        if let Some(cookies) = cookies {
            request = request.header(header::COOKIE, cookies);
        }
        self.app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// The body of the answer to `uri` sent with `cookies`.
    async fn ask(&self, uri: &str, cookies: &str) -> String {
        let response = self.get(uri, Some(cookies)).await;
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// A new signed-in session, as a cookie.
    async fn sign_in(&self) -> String {
        let response = self.get("/sign-in", None).await;
        cookie_named(&response, "").expect("the session cookie")
    }

    /// Alice signs in from her browser: the first request of the signed-in
    /// session creates her device and issues its cookie, and the device has
    /// since become one the account has used.
    async fn owners_browser(&self) -> Browser {
        let session = self.sign_in().await;
        let response = self.get("/device", Some(&session)).await;
        let device = cookie_named(&response, "__Host-axess_device=")
            .expect("the first signed-in request issues the device cookie");
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let device_id = String::from_utf8(bytes.to_vec()).unwrap();
        self.devices
            .set_trust_level(
                &tenant(),
                &device_id.parse().expect("a device id"),
                DeviceTrustLevel::Seen,
                self.clock.now(),
            )
            .await
            .unwrap();
        Browser {
            session,
            device,
            device_id,
        }
    }

    /// Three wrong passwords from unknown browsers, each from its own
    /// address so the throttle refuses none before the lock does.
    async fn lock_the_account(&self) {
        for n in 1..=3 {
            let from_elsewhere = self.service.with_audit_context(AuditContext {
                ip_address: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    203, 0, 113, n,
                ))),
                ip_source: axess_core::client_ip::Source::Peer,
                ..AuditContext::default()
            });
            let stranger = test_session();
            from_elsewhere
                .begin_login("alice", "default", &stranger)
                .await
                .unwrap();
            let wrong = FactorCredential::Password(ZeroizedString::new("wrong"));
            from_elsewhere
                .verify_factor(&wrong, &stranger)
                .await
                .unwrap();
        }
        assert_eq!(
            self.identity.failed_attempts_for("u1"),
            3,
            "the account is locked"
        );
    }
}

/// The `name=value` of the response's cookie whose name starts with
/// `prefix`; with an empty prefix, the one that is not the device cookie.
fn cookie_named(response: &axum::response::Response, prefix: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| {
            if prefix.is_empty() {
                !value.starts_with("__Host-axess_device=")
            } else {
                value.starts_with(prefix)
            }
        })
        .map(|value| value.split(';').next().unwrap().to_string())
}

/// A request of the session that sends no device cookie (a visit arriving
/// from another site, or whoever holds a copy of the session cookie alone)
/// keeps the session's device and does not read as proven; the browser's own
/// next request, with the cookie, does again. No second device is created.
#[tokio::test]
async fn a_request_without_the_device_cookie_keeps_the_device_and_reads_unproven() {
    let w = world();
    let browser = w.owners_browser().await;

    assert_eq!(w.ask("/proven", &browser.both()).await, "proven");
    assert_eq!(w.ask("/proven", &browser.session).await, "unproven");
    assert_eq!(w.ask("/device", &browser.session).await, browser.device_id);
    assert_eq!(w.ask("/proven", &browser.both()).await, "proven");
    assert_eq!(w.devices.len(), 1, "no second device");
}

/// Whether the device was proven is each request's own answer: a session
/// that is proven on one request and only recognised on the next is not
/// written to the store for it.
#[tokio::test]
async fn proving_and_keeping_the_device_by_turns_does_not_rewrite_the_session() {
    let w = world();
    let browser = w.owners_browser().await;
    let id: SessionKey = w.ask("/sid", &browser.both()).await.parse().unwrap();
    let revision = |w: &World| {
        let (sessions, id) = (w.sessions.clone(), id);
        async move { sessions.load(&id).await.unwrap().expect("the row").revision }
    };
    let stored = revision(&w).await;

    for cookies in [&browser.session, &browser.both(), &browser.session] {
        w.ask("/proven", cookies).await;
        assert_eq!(revision(&w).await, stored, "sent with {cookies}");
    }
    let row = w.sessions.load(&id).await.unwrap().expect("the row");
    assert_eq!(
        row.device_id.map(|device| device.to_string()),
        Some(browser.device_id),
        "the row holds the device"
    );
    let serialised = serde_json::to_value(&row).unwrap();
    assert!(
        serialised.get("device_proven").is_none(),
        "and its stored form never says whether a request proved it: {serialised}"
    );
}

/// A refresh token says which device it was issued to, not that anyone
/// proved it. The session it yields carries that device, and its next
/// request without the device cookie keeps the device and reads unproven.
#[tokio::test]
async fn a_session_issued_from_a_refresh_token_is_unproven_until_the_device_token_is_presented() {
    let w = world();
    let browser = w.owners_browser().await;
    let id: SessionKey = w.ask("/sid", &browser.both()).await.parse().unwrap();
    let (tokens, config, rng) = (
        MemoryRefreshTokenStore::new().with_clock(Arc::new(w.clock.clone())),
        RefreshTokenConfig::default(),
        MockRng::new(5),
    );
    let (plaintext, _) = issue_refresh_token(
        IssueRequest {
            user_id: &uid("u1"),
            tenant_id: &tenant(),
            device_info: None,
            family_id: None,
            device_id: Some(browser.device_id.parse().unwrap()),
        },
        &config,
        &tokens,
        &rng,
        w.clock.now(),
    )
    .await
    .unwrap();
    let (refreshed, _) = Refresh::new(&plaintext, &tenant(), |_| async { true })
        .without_device_check()
        .run(&tokens, &config, &rng, w.clock.now())
        .await
        .expect("the token redeems");
    assert_eq!(
        refreshed.device_id.map(|device| device.to_string()),
        Some(browser.device_id.clone())
    );
    assert!(!refreshed.device_proven);
    // The application stores what the refresh yields as the session; here
    // under the key of the session the cookie in hand names.
    w.sessions
        .save(&id, &refreshed, std::time::Duration::from_secs(3600))
        .await
        .unwrap();

    assert_eq!(w.ask("/proven", &browser.session).await, "unproven");
    assert_eq!(w.ask("/device", &browser.session).await, browser.device_id);
    assert_eq!(w.ask("/proven", &browser.both()).await, "proven");
    assert_eq!(w.devices.len(), 1, "no second device");
}

/// The lockout lets the account's own device through only on a request that
/// proves it. A password entry on a signed-in session that sends no device
/// cookie is locked out like any unknown browser, the right password
/// included; the same entry from the browser itself, cookie and all, goes
/// through.
#[tokio::test]
async fn a_signed_in_password_entry_is_exempt_from_the_lock_only_with_the_device_token() {
    let w = world();
    let browser = w.owners_browser().await;
    w.lock_the_account().await;
    let entry = format!("/password/{PASSWORD}");

    assert_eq!(
        w.ask(&entry, &browser.session).await,
        "Ok(InvalidCredential)",
        "the session cookie alone is past the lock"
    );
    assert_eq!(w.identity.failed_attempts_for("u1"), 3, "still locked");

    assert_eq!(w.ask(&entry, &browser.both()).await, "Ok(Authenticated)");
    assert_eq!(w.identity.failed_attempts_for("u1"), 0);
}

/// The same for a step-up begun and answered in one request.
#[tokio::test]
async fn a_one_request_step_up_is_exempt_from_the_lock_only_with_the_device_token() {
    let w = world();
    let browser = w.owners_browser().await;
    w.lock_the_account().await;
    let step_up = format!("/step-up/{PASSWORD}");

    let without = w.ask(&step_up, &browser.session).await;
    assert!(
        without.contains("Locked"),
        "the session cookie alone is past the lock: {without}"
    );
    assert_eq!(w.identity.failed_attempts_for("u1"), 3, "still locked");

    // The refused step-up left the session part-way; the browser signs in
    // again and presents the cookie of the device it already has.
    let again = Browser {
        session: w.sign_in().await,
        ..browser
    };
    assert_eq!(w.ask(&step_up, &again.both()).await, "Ok(Authenticated)");
    assert_eq!(w.devices.len(), 1, "no second device");
}
