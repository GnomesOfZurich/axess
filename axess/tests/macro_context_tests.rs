//! `require_authz!` and the request context: a `forbid` on `context.*` must
//! decide on the context a `RequestContextProvider` supplies, and must never
//! turn into an allow because the context is missing.
//!
//! The first group runs the policy and schema shipped in `examples/authz`
//! through the macro, so the example's MFA rule is covered as written.

#![cfg(all(feature = "memory", feature = "authz"))]

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use axess::authz::{PolicyStore, RequestContextProvider, RequestEntityProvider};
use axess::{MemorySessionStore, SessionLayer, require_authz};
use axess_core::authz::AuthzError;
use axum::{
    Extension, Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    routing::get,
};
use cedar_policy::{Context, Entities, Entity, EntityUid, RestrictedExpression};
use tower::ServiceExt;

const EXAMPLE_POLICY: &str = include_str!("../../examples/authz/policies/app.cedar");
const EXAMPLE_SCHEMA: &str = include_str!("../../examples/authz/policies/app.cedarschema.json");

/// An unconditional permit and a forbid on the MFA attribute, with the
/// attribute optional in the schema (the shape that errors when absent).
const GUARDED_POLICY: &str = r#"
    permit (principal, action, resource);
    forbid (principal, action, resource) when { !context.mfa_verified };
"#;
const GUARDED_SCHEMA: &str = r#"{
    "App": {
        "entityTypes": {
            "User": { "shape": { "type": "Record", "attributes": {} } },
            "Doc":  { "shape": { "type": "Record", "attributes": {} } }
        },
        "actions": {
            "View": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Doc"],
                    "context": {
                        "type": "Record",
                        "attributes": { "mfa_verified": { "type": "Boolean" } }
                    }
                }
            }
        }
    }
}"#;

fn session_layer() -> SessionLayer<MemorySessionStore> {
    SessionLayer::new(MemorySessionStore::new(), [42u8; 32])
        .with_ttl(std::time::Duration::from_secs(3600))
        .with_secure(false)
}

/// Principal in the `admin` role (when `role` is set) plus the resource.
struct Entities4Test {
    role: Option<&'static str>,
    namespace: &'static str,
}

impl RequestEntityProvider for Entities4Test {
    fn entities_for<'a>(
        &'a self,
        session: &'a axess::AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        let _ = (session, action);
        let principal = principal.clone();
        let resource = resource.clone();
        let role_uid = self
            .role
            .map(|r| EntityUid::from_str(&format!(r#"{}::Role::"{r}""#, self.namespace)).unwrap());
        let owner_attr = self.namespace == "DocApp";
        Box::pin(async move {
            let build =
                |e: Result<Entity, _>| e.map_err(|e| AuthzError::EntityBuild(format!("{e:?}")));
            let mut all = Vec::new();
            let mut parents = HashSet::new();
            if let Some(role) = role_uid {
                parents.insert(role.clone());
                all.push(build(Entity::new(role, HashMap::new(), HashSet::new()))?);
            }
            let mut doc_attrs = HashMap::new();
            if owner_attr {
                let owner = RestrictedExpression::from_str(
                    r#"{ "__entity": { "type": "DocApp::User", "id": "someone-else" } }"#,
                )
                .unwrap();
                doc_attrs.insert("owner".to_string(), owner);
                all.push(build(Entity::new(
                    EntityUid::from_str(r#"DocApp::User::"someone-else""#).unwrap(),
                    HashMap::new(),
                    HashSet::new(),
                ))?);
            }
            all.push(build(Entity::new(principal, HashMap::new(), parents))?);
            all.push(build(Entity::new(resource, doc_attrs, HashSet::new()))?);
            Entities::from_entities(all, None)
                .map_err(|e| AuthzError::EntityBuild(format!("{e:?}")))
        })
    }
}

/// Supplies a fixed MFA status, or fails.
struct MfaProvider(Result<bool, &'static str>);

impl RequestContextProvider for MfaProvider {
    fn context_for<'a>(
        &'a self,
        session: &'a axess::AuthSession,
        request: &'a axum::http::request::Parts,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Context, AuthzError>> + Send + 'a>>
    {
        let _ = (session, request);
        let answer = self.0;
        Box::pin(async move {
            let mfa = answer.map_err(|m| AuthzError::Context(m.to_string()))?;
            Context::from_pairs([(
                "mfa_verified".to_string(),
                RestrictedExpression::new_bool(mfa),
            )])
            .map_err(|e| AuthzError::Context(format!("{e:?}")))
        })
    }
}

struct Setup {
    policy: &'static str,
    schema: &'static str,
    entities: Entities4Test,
    context: Option<MfaProvider>,
}

fn app(setup: Setup, namespace: &'static str) -> Router {
    let store = Arc::new(PolicyStore::from_text(setup.policy, setup.schema).expect("policies"));
    let entities: Arc<dyn RequestEntityProvider> = Arc::new(setup.entities);
    let mut router = Router::new()
        .route(
            "/delete/{id}",
            get(|| async { "deleted" }).layer(require_authz!(
                namespace,
                "DeleteDocument",
                "Document:{id}"
            )),
        )
        .route(
            "/view/{id}",
            get(|| async { "viewed" }).layer(require_authz!(
                namespace,
                "ViewDocument",
                "Document:{id}"
            )),
        )
        .route(
            "/app/{id}",
            get(|| async { "viewed" }).layer(require_authz!(namespace, "View", "Doc:{id}")),
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
        );
    if let Some(cp) = setup.context {
        let cp: Arc<dyn RequestContextProvider> = Arc::new(cp);
        router = router.layer(Extension(cp));
    }
    router
        .layer(Extension(store))
        .layer(Extension(entities))
        .layer(session_layer())
}

async fn get_status(app: Router, path: &str) -> StatusCode {
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
    let cookie = login
        .headers()
        .get(header::SET_COOKIE)
        .expect("cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    app.oneshot(
        Request::get(path)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

fn example(context: Option<MfaProvider>) -> Router {
    app(
        Setup {
            policy: EXAMPLE_POLICY,
            schema: EXAMPLE_SCHEMA,
            entities: Entities4Test {
                role: Some("admin"),
                namespace: "DocApp",
            },
            context,
        },
        "DocApp",
    )
}

fn guarded(context: Option<MfaProvider>) -> Router {
    app(
        Setup {
            policy: GUARDED_POLICY,
            schema: GUARDED_SCHEMA,
            entities: Entities4Test {
                role: None,
                namespace: "App",
            },
            context,
        },
        "App",
    )
}

#[tokio::test]
async fn example_delete_is_denied_when_the_provider_reports_no_mfa() {
    let status = get_status(example(Some(MfaProvider(Ok(false)))), "/delete/d1").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn example_delete_is_allowed_when_the_provider_reports_mfa() {
    let status = get_status(example(Some(MfaProvider(Ok(true)))), "/delete/d1").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn example_delete_without_a_provider_is_denied() {
    let status = get_status(example(None), "/delete/d1").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn example_delete_is_denied_when_the_provider_errors() {
    let status = get_status(
        example(Some(MfaProvider(Err("session lookup failed")))),
        "/delete/d1",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn example_view_needs_no_context_and_still_works_without_a_provider() {
    let status = get_status(example(None), "/view/d1").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn guarded_forbid_follows_the_provider_context() {
    assert_eq!(
        get_status(guarded(Some(MfaProvider(Ok(false)))), "/app/d1").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get_status(guarded(Some(MfaProvider(Ok(true)))), "/app/d1").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn guarded_forbid_does_not_become_an_allow_without_a_provider() {
    // The attribute is required, so the empty context is an invalid request
    // and the permit beside the forbid must not decide.
    assert_eq!(
        get_status(guarded(None), "/app/d1").await,
        StatusCode::FORBIDDEN
    );
}
