//! `require_authz!` with a validator consults the session registry and ends a
//! revoked session; the bare form reads only the session record.

#![cfg(all(feature = "testing", feature = "authz"))]

use axess::authn::AuthnService;
use axess::authz::{PolicyStore, RequestEntityProvider};
use axess::testing::AuthSessionTestExt;
use axess::testing::{MockFactorStore, MockIdentityStore};
use axess::{
    AuthSession, MemorySessionRegistry, MemorySessionStore, SessionLayer, SessionRegistry,
    require_authn, require_authz,
};
use axess_core::authz::AuthzError;
use axum::{
    Extension, Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use cedar_policy::{Entities, Entity, EntityUid, RestrictedExpression};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const SCHEMA: &str = r#"{
    "App": {
        "entityTypes": {
            "User":     { "shape": { "type": "Record", "attributes": {} } },
            "Platform": { "shape": { "type": "Record", "attributes": {} } }
        },
        "actions": {
            "Manage": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes":  ["Platform"]
                }
            }
        }
    }
}"#;

struct Provider;

impl RequestEntityProvider for Provider {
    fn entities_for<'a>(
        &'a self,
        _session: &'a AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        _action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        let principal = principal.clone();
        let resource = resource.clone();
        Box::pin(async move {
            let build = |uid| {
                Entity::new(
                    uid,
                    HashMap::<String, RestrictedExpression>::new(),
                    HashSet::new(),
                )
                .map_err(|e| AuthzError::EntityBuild(format!("{e:?}")))
            };
            Entities::from_entities(vec![build(principal)?, build(resource)?], None)
                .map_err(|e| AuthzError::EntityBuild(format!("{e:?}")))
        })
    }
}

struct App {
    app: Router,
    registry: MemorySessionRegistry,
}

fn app() -> App {
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_registry(registry.clone())
        .build();
    let alice = axess::testing::user("alice").to_string();
    let policy = format!(
        r#"permit (principal == App::User::"{alice}", action == App::Action::"Manage", resource == App::Platform::"global");"#
    );
    let store = Arc::new(PolicyStore::from_text(&policy, SCHEMA).expect("policy"));
    let provider: Arc<dyn RequestEntityProvider> = Arc::new(Provider);
    let reg = registry.clone();
    let session_layer = SessionLayer::without_registry_insecure(
        MemorySessionStore::new(),
        axess::testing::test_key(42),
    )
    .with_ttl(Duration::from_secs(3600))
    .with_secure(false);
    let app = Router::new()
        .route("/plain", get(|| async { "ok" }).layer(require_authn!()))
        .route(
            "/guarded",
            get(|| async { "ok" }).layer(require_authz!(
                "App",
                "Manage",
                "Platform:global",
                validator = svc.session_validator()
            )),
        )
        .route(
            "/login",
            get(move |s: AuthSession| {
                let reg = reg.clone();
                async move {
                    let user = axess::testing::user("alice");
                    s.set_authenticated(user, axess::testing::tenant("t1"), chrono::Utc::now())
                        .await;
                    reg.register(&user, &s.session_id().await).await.unwrap();
                    "in"
                }
            }),
        )
        .layer(Extension(store))
        .layer(Extension(provider))
        .layer(session_layer);
    App { app, registry }
}

async fn status(app: &Router, cookie: &str, path: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::get(path)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
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
async fn a_revoked_session_passes_the_bare_authn_guard_and_fails_the_validator_gate() {
    let a = app();
    let cookie = login(&a.app).await;
    assert_eq!(status(&a.app, &cookie, "/plain").await, StatusCode::OK);
    assert_eq!(status(&a.app, &cookie, "/guarded").await, StatusCode::OK);

    a.registry
        .invalidate_user(&axess::testing::user("alice"))
        .await
        .unwrap();

    assert_eq!(
        status(&a.app, &cookie, "/plain").await,
        StatusCode::OK,
        "the bare authn guard reads only the session record"
    );
    assert_eq!(
        status(&a.app, &cookie, "/guarded").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&a.app, &cookie, "/plain").await,
        StatusCode::UNAUTHORIZED,
        "the validator ended the stored session, not merely refused it once"
    );
}
