//! `require_authz!` and the request context: a `forbid` on `context.*` must
//! decide on the context the installation's `RequestContextProvider`
//! supplies, and must never turn into an allow because the context is
//! missing. A policy store that reads `context` cannot be installed without
//! a provider at all: `AuthzInstallation::new` refuses it where the router
//! is built, so no gated request is ever served by such a router.
//!
//! The first group runs the policy and schema shipped in `examples/authz`
//! through the macro, so the example's MFA rule is covered as written.

#![cfg(all(feature = "memory", feature = "authz", feature = "testing"))]

use axess::testing::AuthSessionTestExt;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use axess::authz::{AuthzInstallation, PolicyStore, RequestContextProvider, RequestEntityProvider};
use axess::{MemorySessionStore, SessionLayer, require_authz};
use axess_core::authz::AuthzError;
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    routing::get,
};
use cedar_policy::{Context, Entities, Entity, EntityUid, RestrictedExpression};
use tower::ServiceExt;

/// A validator without a registry: the session record decides, which is all
/// these tests exercise.
fn session_validator(clock: &axess::testing::MockClock) -> axess::authn::SessionValidator {
    axess::authn::AuthnService::builder(
        axess::testing::MockIdentityStore::new().with_clock(clock.clone()),
        axess::testing::MockFactorStore::new(),
    )
    .with_clock(clock.clone())
    .build()
    .session_validator()
}

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

const OPTIONAL_SCHEMA: &str = r#"{
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
                        "attributes": {
                            "mfa_verified": { "type": "Boolean", "required": false }
                        }
                    }
                }
            }
        }
    }
}"#;

fn session_layer(clock: &axess::testing::MockClock) -> SessionLayer<MemorySessionStore> {
    SessionLayer::without_registry_insecure(
        MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone())),
        axess::testing::test_key(42),
        std::sync::Arc::new(axess::session::UnrecordedSessionEnds),
    )
    .with_clock(clock.clone())
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

/// The router an application would build: the gates, and outside them the
/// one installation. `Err` when the installation refuses the setup, which
/// is before any route exists to be served.
fn app(
    clock: &axess::testing::MockClock,
    setup: Setup,
    namespace: &'static str,
) -> Result<Router, AuthzError> {
    let store = Arc::new(PolicyStore::from_text(setup.policy, setup.schema).expect("policies"));
    let context = setup
        .context
        .map(|cp| -> Arc<dyn RequestContextProvider> { Arc::new(cp) });
    let installation = AuthzInstallation::new(store, Arc::new(setup.entities), context)?;
    Ok(Router::new()
        .route(
            "/delete/{id}",
            get(|| async { "deleted" }).layer(require_authz!(
                namespace,
                "DeleteDocument",
                "Document:{id}",
                validator = session_validator(clock)
            )),
        )
        .route(
            "/view/{id}",
            get(|| async { "viewed" }).layer(require_authz!(
                namespace,
                "ViewDocument",
                "Document:{id}",
                validator = session_validator(clock)
            )),
        )
        .route(
            "/app/{id}",
            get(|| async { "viewed" }).layer(require_authz!(
                namespace,
                "View",
                "Doc:{id}",
                validator = session_validator(clock)
            )),
        )
        .route(
            "/login",
            axum::routing::post(|session: axess::AuthSession| async move {
                session
                    .set_authenticated(
                        axess::testing::user("alice"),
                        axess::testing::tenant("t1"),
                        axess::testing::MockClock::reference_time(),
                    )
                    .await;
                StatusCode::NO_CONTENT
            }),
        )
        .layer(installation)
        .layer(session_layer(clock)))
}

/// The router of a setup the installation accepts.
fn built(app: Result<Router, AuthzError>) -> Router {
    app.expect("the installation accepts this setup")
}

/// Whether the setup was refused where the installation is built, for the
/// missing context provider.
fn refused_for_the_provider(app: Result<Router, AuthzError>) -> bool {
    matches!(app, Err(AuthzError::ContextProviderRequired))
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

fn example(context: Option<MfaProvider>) -> Result<Router, AuthzError> {
    let clock = axess::testing::MockClock::at_reference();
    app(
        &clock,
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

fn guarded(
    clock: &axess::testing::MockClock,
    context: Option<MfaProvider>,
) -> Result<Router, AuthzError> {
    app(
        clock,
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
    let app = built(example(Some(MfaProvider(Ok(false)))));
    assert_eq!(get_status(app, "/delete/d1").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn example_delete_is_allowed_when_the_provider_reports_mfa() {
    let app = built(example(Some(MfaProvider(Ok(true)))));
    assert_eq!(get_status(app, "/delete/d1").await, StatusCode::OK);
}

/// The example's policies read `context` (the delete rule). Without a
/// provider the installation is refused where it is built, so neither the
/// delete route nor the view route, whose own rule reads nothing, is ever
/// served on an empty context: the check is per store, not per action.
#[test]
fn the_example_cannot_be_installed_without_a_provider() {
    assert!(refused_for_the_provider(example(None)));
}

#[tokio::test]
async fn example_delete_is_denied_when_the_provider_errors() {
    let app = built(example(Some(MfaProvider(Err("session lookup failed")))));
    assert_eq!(get_status(app, "/delete/d1").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn example_view_is_allowed_with_a_provider_installed() {
    // The view rule reads no context; the provider the delete rule needs
    // does not get in its way.
    let app = built(example(Some(MfaProvider(Ok(false)))));
    assert_eq!(get_status(app, "/view/d1").await, StatusCode::OK);
}

/// The gate evaluates with the context of the provider the installation
/// was built with: the same policy, the same session, and the answer
/// follows what the provider reports.
#[tokio::test]
async fn guarded_forbid_follows_the_provider_context() {
    let clock = axess::testing::MockClock::at_reference();
    assert_eq!(
        get_status(
            built(guarded(&clock, Some(MfaProvider(Ok(false))))),
            "/app/d1"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get_status(
            built(guarded(&clock, Some(MfaProvider(Ok(true))))),
            "/app/d1"
        )
        .await,
        StatusCode::OK
    );
}

#[test]
fn guarded_forbid_cannot_be_installed_without_a_provider() {
    let clock = axess::testing::MockClock::at_reference();
    // The policies read `context` and nothing would supply it: the
    // installation refuses by name instead of a gate deciding on an empty
    // context.
    assert!(refused_for_the_provider(guarded(&clock, None)));
}

/// The same forbid with the attribute optional in the schema: on an empty
/// context `context has mfa_verified` is false, the forbid stops applying and
/// the permit allows.
const OPTIONAL_POLICY: &str = r#"
    permit (principal, action, resource);
    forbid (principal, action, resource)
        when { context has mfa_verified && !context.mfa_verified };
"#;

fn optional(
    clock: &axess::testing::MockClock,
    context: Option<MfaProvider>,
) -> Result<Router, AuthzError> {
    app(
        clock,
        Setup {
            policy: OPTIONAL_POLICY,
            schema: OPTIONAL_SCHEMA,
            entities: Entities4Test {
                role: None,
                namespace: "App",
            },
            context,
        },
        "App",
    )
}

#[test]
fn an_optional_context_guard_cannot_be_installed_without_a_provider() {
    let clock = axess::testing::MockClock::at_reference();
    let store = PolicyStore::from_text(OPTIONAL_POLICY, OPTIONAL_SCHEMA).unwrap();
    assert!(store.mentions_context());
    // This is the pair an empty context would ALLOW, so it is the one that
    // must never be served.
    assert!(refused_for_the_provider(optional(&clock, None)));
}

#[tokio::test]
async fn an_optional_context_guard_follows_the_provider_when_there_is_one() {
    let clock = axess::testing::MockClock::at_reference();
    assert_eq!(
        get_status(
            built(optional(&clock, Some(MfaProvider(Ok(false))))),
            "/app/d1"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get_status(
            built(optional(&clock, Some(MfaProvider(Ok(true))))),
            "/app/d1"
        )
        .await,
        StatusCode::OK
    );
}

/// The word `context` in a comment and in a string, with no read of the
/// request context anywhere.
const WORD_ONLY_POLICY: &str = r#"
    permit (principal, action, resource) when {
        // the request context plays no part in this rule
        "context" like "con*"
    };
"#;

/// A permit that reads nothing, beside a template that reads the context.
const TEMPLATE_POLICY: &str = r#"
    permit (principal, action, resource);
    forbid (principal == ?principal, action, resource)
        when { context has mfa_verified && !context.mfa_verified };
"#;

fn optional_schema_app(
    clock: &axess::testing::MockClock,
    policy: &'static str,
    context: Option<MfaProvider>,
) -> Result<Router, AuthzError> {
    app(
        clock,
        Setup {
            policy,
            schema: OPTIONAL_SCHEMA,
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
async fn the_word_in_a_comment_and_a_string_needs_no_provider() {
    let clock = axess::testing::MockClock::at_reference();
    let store = PolicyStore::from_text(WORD_ONLY_POLICY, OPTIONAL_SCHEMA).unwrap();
    assert!(!store.mentions_context());
    // Installed with `None`, and its gate decides on the empty context.
    assert_eq!(
        get_status(
            built(optional_schema_app(&clock, WORD_ONLY_POLICY, None)),
            "/app/d1"
        )
        .await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_template_that_reads_the_context_cannot_be_installed_without_a_provider() {
    let clock = axess::testing::MockClock::at_reference();
    let store = PolicyStore::from_text(TEMPLATE_POLICY, OPTIONAL_SCHEMA).unwrap();
    assert!(store.mentions_context());
    assert!(refused_for_the_provider(optional_schema_app(
        &clock,
        TEMPLATE_POLICY,
        None
    )));
    assert_eq!(
        get_status(
            built(optional_schema_app(
                &clock,
                TEMPLATE_POLICY,
                Some(MfaProvider(Ok(true)))
            )),
            "/app/d1"
        )
        .await,
        StatusCode::OK
    );
}
