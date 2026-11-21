//! The browser of an impersonated session is the administrator's. Nothing
//! an impersonation does creates, claims, promotes or trusts a device for
//! the user the session runs as: the request's device is the
//! administrator's own, the user's devices stay as they were, and no
//! lockout exemption or refresh token of the user's comes to rest on it.

#![cfg(all(feature = "testing", feature = "memory", feature = "device"))]

use axess_core::testing::fixtures as common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::ids::{DeviceId, TenantId, UserId};
use axess_core::authn::service::AuthnService;
use axess_core::authn::types::LockoutPolicy;
use axess_core::session::refresh::RefreshTokenConfig;
use axess_core::session::{extractor::AuthSession, layer::SessionLayer, store::MemorySessionStore};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::testing::{AuthSessionTestExt, MemoryRefreshTokenStore, MockRng, test_session};
use axess_core::{
    DefaultFingerprintExtractor, Device, DeviceLifecycleService, DeviceStore, DeviceTrustLevel,
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

const UA: &str = "Mozilla/5.0 (the administrator's browser)";
const PASSWORD: &str = "Sample2+";
const ADMIN: &str = "admin";
/// The user the shared fixtures give a password to.
const TARGET: &str = "u1";

type Authn = AuthnService<MockIdentityStore, MockFactorStore>;

fn tenant() -> TenantId {
    test_tenant().id
}

struct World {
    app: Router,
    clock: MockClock,
    devices: MemoryDeviceStore,
    identity: MockIdentityStore,
    service: Authn,
}

/// A browser: the cookies it holds.
#[derive(Clone, Default)]
struct Browser(BTreeMap<String, String>);

impl World {
    /// `GET uri` from `browser`, keeping the cookies the answer sets.
    async fn get(&self, browser: &mut Browser, uri: &str) -> String {
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
        let response = self
            .app
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

    /// The devices the store holds for `user`, in a fixed order.
    async fn devices_of(&self, user: &str) -> Vec<Device> {
        let mut devices = self
            .devices
            .find_for_user(&tenant(), &uid(user), 100)
            .await
            .unwrap();
        devices.sort_by_key(|device| device.id.to_string());
        devices
    }

    /// The device `browser`'s session is on.
    async fn device(&self, browser: &mut Browser) -> DeviceId {
        self.get(browser, "/device")
            .await
            .parse()
            .expect("the session has a device")
    }

    /// Three wrong passwords for the target's account from unknown
    /// browsers, each from its own address so the throttle refuses none
    /// before the lock does.
    async fn lock_the_targets_account(&self) {
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
            self.identity.failed_attempts_for(TARGET),
            3,
            "the account is locked"
        );
    }
}

/// An application whose administrator can impersonate the target, step up
/// and sign in by password as the target, and be issued a refresh token; it
/// promotes the session's device after a step-up, as the device chapter
/// tells an application to. A user holds at most one `Unknown` device, so a
/// device created for a user would also displace the one they have.
fn world() -> World {
    let clock = common::test_clock();
    let devices = MemoryDeviceStore::new();
    let admin = test_user(ADMIN, "ops");
    let target = test_user(TARGET, "alice");
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(admin.clone())
        .with_user(target.clone())
        .with_lockout_policy(LockoutPolicy {
            max_attempts: 3,
            duration: Some(std::time::Duration::from_secs(900)),
            ..LockoutPolicy::default()
        });
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config(PASSWORD))
        .with_method(&uid(TARGET), password_method());
    let service = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock.clone())
        .with_device_store(devices.clone())
        .with_impersonated_credential_changes_allowed()
        .build();
    let lifecycle =
        DeviceLifecycleService::new(devices.clone()).with_max_unknown_devices_per_user(1);
    let resolver = LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(Arc::new(|_: &TenantId| [9u8; 32])),
        lifecycle.clone(),
        clock.clone(),
    )
    .with_tenant_fn(|_| Some(tenant()))
    .with_rng(MockRng::new(78));
    let tokens = MemoryRefreshTokenStore::new().with_clock(Arc::new(clock.clone()));

    let impersonate = {
        let (service, admin, target) = (service.clone(), admin.clone(), target.clone());
        move |session: AuthSession| async move {
            let begun = service
                .with_audit_context(AuditContext::default())
                .begin_impersonation(&admin, &target, &session)
                .await;
            format!("{begun:?}")
        }
    };
    let app = Router::new()
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
        .route("/impersonate", get(impersonate.clone()))
        .route(
            "/sign-in-and-impersonate",
            get({
                let clock = clock.clone();
                move |session: AuthSession| async move {
                    session
                        .set_authenticated(uid(ADMIN), tenant(), clock.now())
                        .await;
                    impersonate(session).await
                }
            }),
        )
        .route(
            "/end",
            get({
                let service = service.clone();
                move |session: AuthSession| async move {
                    let ended = service
                        .with_audit_context(AuditContext::default())
                        .end_impersonation(&session)
                        .await;
                    format!("{ended:?}")
                }
            }),
        )
        .route(
            "/step-up/{password}",
            get({
                let (service, lifecycle, clock) =
                    (service.clone(), lifecycle.clone(), clock.clone());
                move |session: AuthSession, Path(password): Path<String>| async move {
                    let service = service.with_audit_context(AuditContext::default());
                    if let Err(refused) = service
                        .begin_step_up(&session, vec![FactorKind::Password])
                        .await
                    {
                        return format!("not begun: {refused:?}");
                    }
                    let credential = FactorCredential::Password(ZeroizedString::new(&password));
                    let outcome = service.verify_factor(&credential, &session).await;
                    let said = format!("{outcome:?}");
                    let device = session.user_device().await;
                    if let (Ok(outcome), Some(device)) = (outcome, device) {
                        lifecycle
                            .promote_if_authenticated(&outcome, &device, clock.now())
                            .await
                            .unwrap();
                    }
                    said
                }
            }),
        )
        .route(
            "/password/{password}",
            get({
                let service = service.clone();
                move |session: AuthSession, Path(password): Path<String>| async move {
                    let outcome = service
                        .with_audit_context(AuditContext::default())
                        .login_with_password("alice", "default", &password, &session)
                        .await;
                    format!("{outcome:?}")
                }
            }),
        )
        .route(
            "/issue-token",
            get({
                let service = service.clone();
                move |session: AuthSession| async move {
                    let device = session.device_id().await;
                    let config = RefreshTokenConfig::default();
                    let issued = service
                        .with_audit_context(AuditContext::default())
                        .issue_refresh_token(&session, &tokens, &config, None, device)
                        .await;
                    match issued {
                        Ok((_, token)) => match token.device_id {
                            Some(device) => device.to_string(),
                            None => "no device".to_string(),
                        },
                        Err(refused) => format!("refused: {refused:?}"),
                    }
                }
            }),
        )
        .route(
            "/device",
            get(|session: AuthSession| async move {
                match session.device_id().await {
                    Some(id) => id.to_string(),
                    None => "none".to_string(),
                }
            }),
        )
        .route(
            "/user-device",
            get(|session: AuthSession| async move {
                match session.user_device().await {
                    Some(device) => format!("{} on {}", device.user(), device.device().id()),
                    None => "none".to_string(),
                }
            }),
        )
        .route(
            "/who",
            get(|session: AuthSession| async move {
                let name = |id: Option<UserId>| match id {
                    Some(id) => id.to_string(),
                    None => "nobody".to_string(),
                };
                format!(
                    "{} as {}",
                    name(session.impersonator().await),
                    name(session.user_id().await)
                )
            }),
        )
        .layer(
            SessionLayer::without_registry_insecure(
                MemorySessionStore::new().with_clock(Arc::new(clock.clone())),
                axess_core::testing::test_key(42),
                std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
            )
            .with_clock(clock.clone())
            .with_rng(MockRng::new(79))
            .with_device_resolver(resolver),
        );
    World {
        app,
        clock,
        devices,
        identity,
        service,
    }
}

impl World {
    /// The target signs in on a browser of their own and so holds one
    /// device. Returns their devices as the store holds them.
    async fn target_with_a_device(&self) -> Vec<Device> {
        let mut own = Browser::default();
        assert_eq!(
            self.get(&mut own, &format!("/sign-in/{TARGET}")).await,
            "in"
        );
        self.device(&mut own).await;
        let devices = self.devices_of(TARGET).await;
        assert_eq!(devices.len(), 1, "the target's own device");
        devices
    }

    /// A browser nobody has signed in on, whose first request signs the
    /// administrator in and begins the impersonation, so the impersonated
    /// session's next request is the first that can be given a device.
    async fn impersonating_from_a_fresh_browser(&self) -> Browser {
        let mut browser = Browser::default();
        assert_eq!(
            self.get(&mut browser, "/sign-in-and-impersonate").await,
            "Ok(())"
        );
        assert_eq!(
            self.get(&mut browser, "/who").await,
            format!("{} as {}", uid(ADMIN), uid(TARGET))
        );
        browser
    }
}

/// An impersonation from a browser nobody has signed in on leaves the
/// target's devices as they were, by count and by content: none is created
/// for them, and the one they hold is neither displaced nor sighted. The
/// device of the impersonated session is the administrator's own.
#[tokio::test]
async fn an_impersonation_from_a_fresh_browser_leaves_the_target_users_devices_unchanged() {
    let world = world();
    let before = world.target_with_a_device().await;

    let mut browser = world.impersonating_from_a_fresh_browser().await;
    let device = world.device(&mut browser).await;
    // Past the interval inside which a second sighting is not written.
    world.clock.advance_secs(600);
    assert_eq!(world.device(&mut browser).await, device, "one device");

    assert_eq!(world.devices_of(TARGET).await, before);
    let admins = world.devices_of(ADMIN).await;
    assert_eq!(admins.len(), 1, "the administrator's device, and one only");
    assert_eq!(admins[0].id, device);
    assert_eq!(admins[0].user_id, Some(uid(ADMIN)));
}

/// The administrator's own later sign-in from that browser finds the
/// device the impersonation was recorded on: it is theirs, and no second
/// one is made.
#[tokio::test]
async fn the_administrators_later_sign_in_finds_the_device_of_the_impersonation() {
    let world = world();
    let mut browser = world.impersonating_from_a_fresh_browser().await;
    let device = world.device(&mut browser).await;

    assert_eq!(world.get(&mut browser, "/end").await, "Ok(())");
    assert_eq!(
        world.get(&mut browser, &format!("/sign-in/{ADMIN}")).await,
        "in"
    );
    assert_eq!(world.device(&mut browser).await, device);
    assert_eq!(world.devices_of(ADMIN).await.len(), 1);
    assert!(world.devices_of(TARGET).await.is_empty());
}

/// An impersonation begun on the device the administrator signed in on
/// stays on that device, and the target gains none.
#[tokio::test]
async fn an_impersonation_stays_on_the_administrators_device() {
    let world = world();
    let before = world.target_with_a_device().await;
    let mut browser = Browser::default();
    assert_eq!(
        world.get(&mut browser, &format!("/sign-in/{ADMIN}")).await,
        "in"
    );
    let device = world.device(&mut browser).await;

    assert_eq!(world.get(&mut browser, "/impersonate").await, "Ok(())");
    assert_eq!(world.device(&mut browser).await, device);
    assert_eq!(world.devices_of(TARGET).await, before);
    assert_eq!(world.devices_of(ADMIN).await.len(), 1);
}

/// A step-up under impersonation promotes nothing: the session answers no
/// device for a trust write, the administrator's device keeps its level,
/// and the target's devices stay as they were.
#[tokio::test]
async fn a_step_up_under_impersonation_promotes_no_device() {
    let world = world();
    let before = world.target_with_a_device().await;
    let mut browser = world.impersonating_from_a_fresh_browser().await;
    let device = world.device(&mut browser).await;

    let stepped = world
        .get(&mut browser, &format!("/step-up/{PASSWORD}"))
        .await;
    assert_eq!(stepped, "Ok(Authenticated)");
    assert_eq!(world.get(&mut browser, "/user-device").await, "none");

    assert_eq!(world.devices_of(TARGET).await, before);
    let admins = world.devices_of(ADMIN).await;
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0].id, device);
    assert_eq!(admins[0].trust_level, DeviceTrustLevel::Unknown);
}

/// A session that is no impersonation answers its user's device, so the
/// absence under impersonation is the impersonation's doing.
#[tokio::test]
async fn a_users_own_session_answers_its_device_for_a_trust_write() {
    let world = world();
    let mut browser = Browser::default();
    assert_eq!(
        world.get(&mut browser, &format!("/sign-in/{TARGET}")).await,
        "in"
    );
    let device = world.device(&mut browser).await;
    assert_eq!(
        world.get(&mut browser, "/user-device").await,
        format!("{} on {device}", uid(TARGET))
    );
}

/// No lockout exemption of the target's comes from the administrator's
/// browser. The administrator impersonates and steps up there, the account
/// is then locked from elsewhere, and a sign-in with the right password
/// from the administrator's browser is locked out like any stranger's.
#[tokio::test]
async fn a_locked_account_stays_locked_on_the_browser_it_was_impersonated_from() {
    let world = world();
    let mut browser = world.impersonating_from_a_fresh_browser().await;
    let device = world.device(&mut browser).await;
    let stepped = world
        .get(&mut browser, &format!("/step-up/{PASSWORD}"))
        .await;
    assert_eq!(stepped, "Ok(Authenticated)");
    // The administrator's device at a level a known device has: it is still
    // not one the target's account has used.
    world
        .devices
        .set_trust_level(
            &tenant(),
            &device,
            DeviceTrustLevel::Seen,
            world.clock.now(),
        )
        .await
        .unwrap();
    world.lock_the_targets_account().await;

    let entry = world
        .get(&mut browser, &format!("/password/{PASSWORD}"))
        .await;
    assert!(!entry.contains("Authenticated"), "{entry}");
    assert!(
        world.identity.failed_attempts_for(TARGET) >= 3,
        "still locked"
    );
}

/// A refresh token issued under impersonation, where a deployment allows
/// one, names no device: the session's device is the administrator's. The
/// administrator's own token names it.
#[tokio::test]
async fn a_refresh_token_issued_under_impersonation_names_no_device() {
    let world = world();
    let mut browser = Browser::default();
    assert_eq!(
        world.get(&mut browser, &format!("/sign-in/{ADMIN}")).await,
        "in"
    );
    let device = world.device(&mut browser).await;
    assert_eq!(
        world.get(&mut browser, "/issue-token").await,
        device.to_string()
    );

    assert_eq!(world.get(&mut browser, "/impersonate").await, "Ok(())");
    assert_eq!(world.device(&mut browser).await, device);
    assert_eq!(world.get(&mut browser, "/issue-token").await, "no device");
}
