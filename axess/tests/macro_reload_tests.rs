//! `require_authz!` and live policy reload: the gate must decide on the
//! policy set a reload put in force, with the wiring the examples show (one
//! `Arc<PolicyStore>` handed to both the request extensions and the store).

#![cfg(all(feature = "memory", feature = "authz"))]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axess::authz::{PolicyStore, RequestEntityProvider};
use axess::testing::AuthSessionTestExt;
use axess::{MemorySessionStore, SessionLayer, require_authz};
use axess_core::authz::{AuthzEntityProvider, AuthzError, AuthzStore, make_entity_uid};
use axum::{
    Extension, Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    routing::get,
};
use cedar_policy::{Entities, Entity, EntityUid, Schema};
use tower::ServiceExt;

const SCHEMA: &str = r#"{
    "App": {
        "entityTypes": {
            "User": { "shape": { "type": "Record", "attributes": {} } },
            "Doc":  { "shape": { "type": "Record", "attributes": {} } }
        },
        "actions": {
            "View": {
                "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Doc"] }
            }
        }
    }
}"#;

const PERMIT_ALL: &str = "permit (principal, action, resource);";
const FORBID_VIEW: &str = r#"
    permit (principal, action, resource);
    forbid (principal, action == App::Action::"View", resource);
"#;

fn session_validator() -> axess::authn::SessionValidator {
    axess::authn::AuthnService::builder(
        axess::testing::MockIdentityStore::new(),
        axess::testing::MockFactorStore::new(),
    )
    .build()
    .session_validator()
}

struct Provider;

impl RequestEntityProvider for Provider {
    fn entities_for<'a>(
        &'a self,
        _session: &'a axess::AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        _action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        let principal = principal.clone();
        let resource = resource.clone();
        Box::pin(async move {
            let build =
                |e: Result<Entity, _>| e.map_err(|e| AuthzError::EntityBuild(format!("{e:?}")));
            Entities::from_entities(
                [
                    build(Entity::new(principal, HashMap::new(), HashSet::new()))?,
                    build(Entity::new(resource, HashMap::new(), HashSet::new()))?,
                ],
                None,
            )
            .map_err(|e| AuthzError::EntityBuild(format!("{e:?}")))
        })
    }
}

impl AuthzEntityProvider for Provider {
    type ResourceId = String;
    type Error = std::convert::Infallible;

    async fn entities_for(
        &self,
        _: &EntityUid,
        _: &String,
        _: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        Ok(Entities::empty())
    }

    async fn entities_for_tenant(
        &self,
        _: &EntityUid,
        _: Option<&str>,
        _: &String,
        _: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        Ok(Entities::empty())
    }

    fn resource_uid(&self, id: &String) -> Result<EntityUid, AuthzError> {
        make_entity_uid("App", "Doc", id)
    }

    fn validate_schema(&self, _schema: &Schema) -> Result<(), AuthzError> {
        Ok(())
    }
}

fn router(ps: Arc<PolicyStore>) -> Router {
    let provider: Arc<dyn RequestEntityProvider> = Arc::new(Provider);
    Router::new()
        .route(
            "/doc/{id}",
            get(|| async { "ok" }).layer(require_authz!(
                "App",
                "View",
                "Doc:{id}",
                validator = session_validator()
            )),
        )
        .route(
            "/login",
            axum::routing::post(|session: axess::AuthSession| async move {
                session
                    .set_authenticated(
                        axess::testing::user("alice"),
                        axess::testing::tenant("t1"),
                        chrono::Utc::now(),
                    )
                    .await;
                StatusCode::NO_CONTENT
            }),
        )
        .layer(Extension(ps))
        .layer(Extension(provider))
        .layer(
            SessionLayer::without_registry_insecure(
                MemorySessionStore::new(),
                axess::testing::test_key(42),
            )
            .with_ttl(std::time::Duration::from_secs(3600))
            .with_secure(false),
        )
}

async fn login_cookie(app: &Router) -> String {
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::NO_CONTENT, "login fixture");
    login
        .headers()
        .get(header::SET_COOKIE)
        .expect("cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
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

#[tokio::test]
async fn a_reload_to_a_forbid_reaches_the_gate_with_the_shared_policy_store() {
    let ps = Arc::new(PolicyStore::from_text(PERMIT_ALL, SCHEMA).unwrap());
    let authz = AuthzStore::try_new(ps.clone(), Arc::new(Provider), "App").unwrap();
    let app = router(ps);
    let cookie = login_cookie(&app).await;
    assert_eq!(status(&app, &cookie, "/doc/1").await, StatusCode::OK);

    authz.reload_policies(FORBID_VIEW, SCHEMA).await.unwrap();

    assert_eq!(status(&app, &cookie, "/doc/1").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_second_reload_back_to_a_permit_reaches_the_gate() {
    let ps = Arc::new(PolicyStore::from_text(PERMIT_ALL, SCHEMA).unwrap());
    let authz = AuthzStore::try_new(ps.clone(), Arc::new(Provider), "App").unwrap();
    let app = router(ps.clone());
    let cookie = login_cookie(&app).await;

    authz.reload_policies(FORBID_VIEW, SCHEMA).await.unwrap();
    assert_eq!(status(&app, &cookie, "/doc/1").await, StatusCode::FORBIDDEN);
    let back = authz.reload_policies(PERMIT_ALL, SCHEMA).await.unwrap();

    assert_eq!(status(&app, &cookie, "/doc/1").await, StatusCode::OK);
    assert_eq!(authz.policy_digest().as_deref(), Some(back.digest.as_str()));
    assert_eq!(ps.digest(), back.digest);
}

#[tokio::test]
async fn the_shared_policy_store_reports_the_reloaded_digest_and_schema() {
    let ps = Arc::new(PolicyStore::from_text(PERMIT_ALL, SCHEMA).unwrap());
    let original = ps.original_digest().to_string();
    let authz = AuthzStore::try_new(ps.clone(), Arc::new(Provider), "App").unwrap();

    let reloaded = authz.reload_policies(FORBID_VIEW, SCHEMA).await.unwrap();

    assert_eq!(ps.digest(), reloaded.digest);
    assert_ne!(ps.digest(), original);
    assert_eq!(ps.original_digest(), original);
    assert_eq!(
        ps.schema().action_entities().unwrap().iter().count(),
        PolicyStore::from_text(FORBID_VIEW, SCHEMA)
            .unwrap()
            .original_schema()
            .action_entities()
            .unwrap()
            .iter()
            .count()
    );
}

#[tokio::test]
async fn a_policy_store_behind_the_trait_reports_the_reloaded_schema() {
    use axess::authz::PolicyEvaluator;
    const WIDER: &str = r#"{
        "App": {
            "entityTypes": {
                "User": { "shape": { "type": "Record", "attributes": {} } },
                "Doc":  { "shape": { "type": "Record", "attributes": {} } }
            },
            "actions": {
                "View": { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Doc"] } },
                "Edit": { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Doc"] } }
            }
        }
    }"#;
    let ps = Arc::new(PolicyStore::from_text(PERMIT_ALL, SCHEMA).unwrap());
    let evaluator: Arc<dyn PolicyEvaluator> = ps.clone();
    let authz = AuthzStore::try_new(ps, Arc::new(Provider), "App").unwrap();
    let before = evaluator
        .schema()
        .unwrap()
        .action_entities()
        .unwrap()
        .iter()
        .count();

    authz.reload_policies(PERMIT_ALL, WIDER).await.unwrap();

    let after = evaluator
        .schema()
        .unwrap()
        .action_entities()
        .unwrap()
        .iter()
        .count();
    assert_eq!((before, after), (1, 2));
}
