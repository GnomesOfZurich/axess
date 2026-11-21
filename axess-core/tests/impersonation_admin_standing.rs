#![cfg(all(feature = "memory", feature = "testing"))]
//! An impersonation lasts only as long as the administrator who began it:
//! suspending them, deleting them or ending their sessions ends the
//! impersonation on its next request.

use axess_core::testing::fixtures as common;

use axess_core::Clock;
use axess_core::authn::{Actor, AuditContext, RequestAuthnService};
use axess_core::authn::{service::AuthnService, types::StatusDetail};
use axess_core::session::{
    extractor::AuthSession,
    layer::SessionLayer,
    store::{
        MemorySessionRegistry, MemorySessionStore, SessionRegistryAdapter, SessionRegistryHandle,
    },
};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::MockClock;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    routing::get,
};
use common::{test_clock, test_tenant, test_user};
use std::sync::Arc;
use tower::ServiceExt;

const KEY: [u8; 32] = [
    7, 1, 9, 4, 8, 2, 6, 3, 5, 0, 11, 14, 13, 12, 10, 15, 21, 24, 23, 22, 20, 25, 27, 26, 29, 28,
    31, 30, 17, 16, 19, 18,
];

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

struct Rig {
    app: Router,
    clock: MockClock,
    svc: Svc,
    reg: MemorySessionRegistry,
    admin: axess_core::authn::types::User,
}

fn rig() -> Rig {
    let clock = test_clock();
    let admin = test_user("admin", "ops");
    let target = test_user("u2", "bob");
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(admin.clone())
        .with_user(target.clone());
    let reg = MemorySessionRegistry::new().with_clock(Arc::new(clock.clone()));
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_registry(reg.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let handle: Arc<dyn SessionRegistryHandle> = Arc::new(SessionRegistryAdapter(reg.clone()));
    let store = MemorySessionStore::new().with_clock(Arc::new(clock.clone()));
    let layer = SessionLayer::new(
        store,
        KEY,
        handle.clone(),
        std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
    )
    .with_clock(clock.clone())
    .with_secure(false);
    let (login_admin, login_reg, login_clock) = (admin.clone(), handle, clock.clone());
    let (imp_svc, imp_admin, imp_target) = (svc.clone(), admin.clone(), target);
    let app = Router::new()
        .route(
            "/login",
            get(move |s: AuthSession| {
                let (u, reg, at) = (login_admin.clone(), login_reg.clone(), login_clock.now());
                async move {
                    s.set_authenticated(u.id, u.tenant_id, at).await;
                    reg.register(&u.id, &s.session_key().await).await;
                    "in"
                }
            }),
        )
        .route(
            "/impersonate",
            get(move |s: AuthSession| {
                let (svc, a, t) = (imp_svc.clone(), imp_admin.clone(), imp_target.clone());
                async move {
                    svc.begin_impersonation(&a, &t, &s)
                        .await
                        .map_or("refused", |()| "impersonating")
                }
            }),
        )
        .route(
            "/whoami",
            get(|s: AuthSession| async move {
                match (s.user_id().await, s.impersonator().await) {
                    (Some(_), Some(_)) => "impersonated",
                    (Some(_), None) => "user",
                    _ => "guest",
                }
            }),
        )
        .layer(layer);
    Rig {
        app,
        clock,
        svc,
        reg,
        admin,
    }
}

async fn call(app: &Router, jar: &mut Option<String>, path: &str) -> String {
    let mut req = Request::get(path);
    if let Some(c) = jar.as_deref() {
        req = req.header(header::COOKIE, c);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    if let Some(v) = resp.headers().get(header::SET_COOKIE) {
        *jar = Some(v.to_str().unwrap().split(';').next().unwrap().to_owned());
    }
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn impersonating(r: &Rig) -> Option<String> {
    let mut jar = None;
    assert_eq!(call(&r.app, &mut jar, "/login").await, "in");
    assert_eq!(
        call(&r.app, &mut jar, "/impersonate").await,
        "impersonating"
    );
    assert_eq!(call(&r.app, &mut jar, "/whoami").await, "impersonated");
    jar
}

#[tokio::test]
async fn an_impersonation_stands_while_the_administrator_does() {
    let r = rig();
    let mut jar = impersonating(&r).await;
    assert_eq!(call(&r.app, &mut jar, "/whoami").await, "impersonated");
}

#[tokio::test]
async fn suspending_the_administrator_ends_the_impersonation() {
    let r = rig();
    let mut jar = impersonating(&r).await;
    let detail = StatusDetail::administrative("compromised", r.clock.now());
    r.svc
        .suspend_user(Actor::System, &r.admin.id, &r.admin.tenant_id, detail)
        .await
        .unwrap();
    assert_eq!(
        call(&r.app, &mut jar, "/whoami").await,
        "guest",
        "impersonation session survived the administrator's suspension"
    );
}

#[tokio::test]
async fn deleting_the_administrator_ends_the_impersonation() {
    let r = rig();
    let mut jar = impersonating(&r).await;
    r.svc
        .delete_user(Actor::System, &r.admin.id, &r.admin.tenant_id)
        .await
        .unwrap();
    assert_eq!(
        call(&r.app, &mut jar, "/whoami").await,
        "guest",
        "impersonation session survived the administrator's deletion"
    );
}

#[tokio::test]
async fn ending_the_administrators_sessions_ends_the_impersonation() {
    let r = rig();
    let mut jar = impersonating(&r).await;
    axess_core::session::store::SessionRegistry::invalidate_user(&r.reg, &r.admin.id)
        .await
        .unwrap();
    assert_eq!(
        call(&r.app, &mut jar, "/whoami").await,
        "guest",
        "impersonation session survived the end of the administrator's sessions"
    );
}
