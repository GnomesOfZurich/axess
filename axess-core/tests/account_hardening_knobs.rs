#![cfg(all(feature = "memory", feature = "testing"))]
//! The account-level knobs the strict profile sets: the password hashing
//! cost, the password reset lifetime and its cap, and how recently an
//! administrator must have authenticated to impersonate. Each starts at the
//! behaviour the library has always had.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axess_core::authn::error::AuthnError;
use axess_core::authn::factor::PasswordRules;
use axess_core::authn::service::AuthnService;
use axess_core::authn::{AuditContext, RequestAuthnService};
use axess_core::session::{
    extractor::AuthSession,
    layer::SessionLayer,
    store::{
        MemorySessionRegistry, MemorySessionStore, SessionRegistryAdapter, SessionRegistryHandle,
    },
};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_factors::{Argon2Cost, password_needs_rehash_for};
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    routing::get,
};
use chrono::Utc;
use common::{test_tenant, test_user};
use tower::ServiceExt;

const KEY: [u8; 32] = [
    7, 1, 9, 4, 8, 2, 6, 3, 5, 0, 11, 14, 13, 12, 10, 15, 21, 24, 23, 22, 20, 25, 27, 26, 29, 28,
    31, 30, 17, 16, 19, 18,
];

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn identity() -> MockIdentityStore {
    MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("admin", "ops"))
        .with_user(test_user("u2", "bob"))
}

// ── Password reset lifetime and cap ─────────────────────────────────────────

fn reset_service(
    configure: impl FnOnce(
        axess_core::authn::service::AuthnServiceBuilder<MockIdentityStore, MockFactorStore>,
    ) -> axess_core::authn::service::AuthnServiceBuilder<
        MockIdentityStore,
        MockFactorStore,
    >,
) -> Svc {
    configure(AuthnService::builder(identity(), MockFactorStore::new()))
        .build()
        .with_audit_context(AuditContext::default())
}

#[tokio::test]
async fn the_reset_cap_is_seven_days_unless_set() {
    let svc = reset_service(|b| b);
    let week = Duration::from_secs(7 * 24 * 3600);
    assert!(
        svc.begin_password_reset("ops", "default", week)
            .await
            .unwrap()
            .is_some()
    );
    let refused = svc
        .begin_password_reset("ops", "default", week + Duration::from_secs(1))
        .await;
    assert!(matches!(refused, Err(AuthnError::Internal(_))));
}

#[tokio::test]
async fn a_lower_reset_cap_refuses_a_longer_lifetime() {
    let svc = reset_service(|b| b.with_max_password_reset_ttl(Duration::from_secs(3600)));
    assert!(
        svc.begin_password_reset("ops", "default", Duration::from_secs(3600))
            .await
            .unwrap()
            .is_some()
    );
    let refused = svc
        .begin_password_reset("ops", "default", Duration::from_secs(3601))
        .await;
    assert!(matches!(refused, Err(AuthnError::Internal(_))));
}

#[tokio::test]
async fn the_default_reset_ttl_refuses_until_configured() {
    let svc = reset_service(|b| b);
    let refused = svc
        .begin_password_reset_with_default_ttl("ops", "default")
        .await;
    assert!(matches!(refused, Err(AuthnError::Internal(_))));
}

#[tokio::test]
async fn the_default_reset_ttl_issues_a_token_and_obeys_the_cap() {
    let svc = reset_service(|b| b.with_password_reset_ttl(Duration::from_secs(1800)));
    assert!(
        svc.begin_password_reset_with_default_ttl("ops", "default")
            .await
            .unwrap()
            .is_some()
    );
    let over = reset_service(|b| {
        b.with_password_reset_ttl(Duration::from_secs(7200))
            .with_max_password_reset_ttl(Duration::from_secs(3600))
    });
    let refused = over
        .begin_password_reset_with_default_ttl("ops", "default")
        .await;
    assert!(matches!(refused, Err(AuthnError::Internal(_))));
}

// ── Password hashing cost ───────────────────────────────────────────────────

#[tokio::test]
async fn a_chosen_password_is_hashed_under_the_configured_cost() {
    let cost = Argon2Cost::new(24 * 1024, 3, 1).unwrap();
    let service = AuthnService::builder(identity(), MockFactorStore::new())
        .with_argon2_cost(cost)
        .build();
    let hash = service
        .hash_chosen_password("Gnomes-of-Zurich-7", &PasswordRules::default())
        .await
        .unwrap();
    assert!(
        hash.contains("m=24576,t=3,p=1"),
        "the hash carries the configured cost: {hash}"
    );
    assert!(!password_needs_rehash_for(&hash, cost));
    assert!(password_needs_rehash_for(&hash, Argon2Cost::default()));
}

#[tokio::test]
async fn a_chosen_password_is_hashed_under_the_pinned_cost_by_default() {
    let service = AuthnService::new(identity(), MockFactorStore::new());
    let hash = service
        .hash_chosen_password("Gnomes-of-Zurich-7", &PasswordRules::default())
        .await
        .unwrap();
    assert!(hash.contains("m=19456,t=2,p=1"), "{hash}");
}

#[test]
fn a_cost_below_the_floor_is_refused() {
    assert!(Argon2Cost::new(8 * 1024, 2, 1).is_err());
    assert!(Argon2Cost::new(24 * 1024, 0, 1).is_err());
}

// ── Impersonation recency ───────────────────────────────────────────────────

fn impersonation_app(max_age: Option<Duration>) -> Router {
    let admin = test_user("admin", "ops");
    let target = test_user("u2", "bob");
    let reg = MemorySessionRegistry::new();
    let mut builder =
        AuthnService::builder(identity(), MockFactorStore::new()).with_registry(reg.clone());
    if let Some(age) = max_age {
        builder = builder.with_impersonation_max_authn_age(age);
    }
    let svc = builder.build().with_audit_context(AuditContext::default());
    let handle: Arc<dyn SessionRegistryHandle> = Arc::new(SessionRegistryAdapter(reg));
    let layer =
        SessionLayer::new(MemorySessionStore::new(), KEY, handle.clone()).with_secure(false);
    let login = |age_minutes: i64,
                 admin: axess_core::authn::types::User,
                 h: Arc<dyn SessionRegistryHandle>| {
        get(move |s: AuthSession| {
            let (u, reg) = (admin.clone(), Arc::clone(&h));
            async move {
                let at = Utc::now() - chrono::Duration::minutes(age_minutes);
                s.set_authenticated(u.id, u.tenant_id, at).await;
                reg.register(&u.id, &s.session_id().await).await;
                "in"
            }
        })
    };
    let (imp_svc, imp_admin, imp_target) = (svc, admin.clone(), target);
    Router::new()
        .route("/login", login(0, admin.clone(), handle.clone()))
        .route("/login_stale", login(60, admin, handle))
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
        .layer(layer)
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

async fn impersonation_after(app: &Router, login: &str) -> String {
    let mut jar = None;
    assert_eq!(call(app, &mut jar, login).await, "in");
    call(app, &mut jar, "/impersonate").await
}

#[tokio::test]
async fn impersonation_asks_for_no_recency_by_default() {
    let app = impersonation_app(None);
    assert_eq!(
        impersonation_after(&app, "/login_stale").await,
        "impersonating"
    );
}

#[tokio::test]
async fn a_stale_administrator_is_refused_when_recency_is_required() {
    let app = impersonation_app(Some(Duration::from_secs(15 * 60)));
    assert_eq!(impersonation_after(&app, "/login_stale").await, "refused");
}

#[tokio::test]
async fn a_fresh_administrator_may_impersonate_when_recency_is_required() {
    let app = impersonation_app(Some(Duration::from_secs(15 * 60)));
    assert_eq!(impersonation_after(&app, "/login").await, "impersonating");
}
