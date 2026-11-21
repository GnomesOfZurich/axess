//! `require_authz!` and live policy reload: the gate must decide on the
//! policy set a reload put in force, with the wiring the examples show (one
//! `Arc<PolicyStore>` handed to both the installation and the store).
//!
//! The installation checks its context provider against the policies in
//! force when it is built. A reload can bring a read of `context` in
//! afterwards; the last group holds the gate to refusing such a set when the
//! installation has no provider, and to deciding it with the provider when
//! one was given up front.

#![cfg(all(feature = "memory", feature = "authz", feature = "testing"))]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axess::authz::{AuthzInstallation, PolicyStore, RequestContextProvider, RequestEntityProvider};
use axess::testing::AuthSessionTestExt;
use axess::{MemorySessionStore, SessionLayer, require_authz};
use axess_core::authz::{AuthzEntityProvider, AuthzError, AuthzStore, make_entity_uid};
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    routing::get,
};
use cedar_policy::{Context, Entities, Entity, EntityUid, RestrictedExpression, Schema};
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

fn session_validator(clock: &axess::testing::MockClock) -> axess::authn::SessionValidator {
    axess::authn::AuthnService::builder(
        axess::testing::MockIdentityStore::new().with_clock(clock.clone()),
        axess::testing::MockFactorStore::new(),
    )
    .with_clock(clock.clone())
    .build()
    .session_validator()
}

struct Provider;

impl RequestEntityProvider for Provider {
    fn entities_for<'a>(
        &'a self,
        _: &'a axess::AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        _: &'a EntityUid,
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

    fn validate_schema(&self, _: &Schema) -> Result<(), AuthzError> {
        Ok(())
    }
}

/// The installation of a policy store that reads no `context`: no context
/// provider.
fn installed(ps: Arc<PolicyStore>) -> AuthzInstallation {
    AuthzInstallation::new(ps, Arc::new(Provider), None)
        .expect("the policies in force read no `context`")
}

fn router(installation: AuthzInstallation) -> Router {
    let clock = axess::testing::MockClock::at_reference();
    Router::new()
        .route(
            "/doc/{id}",
            get(|| async { "ok" }).layer(require_authz!(
                "App",
                "View",
                "Doc:{id}",
                validator = session_validator(&clock)
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
        .layer(
            SessionLayer::without_registry_insecure(
                MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone())),
                axess::testing::test_key(42),
                std::sync::Arc::new(axess::session::UnrecordedSessionEnds),
            )
            .with_clock(clock.clone())
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
    let app = router(installed(ps));
    let cookie = login_cookie(&app).await;
    assert_eq!(status(&app, &cookie, "/doc/1").await, StatusCode::OK);

    authz.reload_policies(FORBID_VIEW, SCHEMA).await.unwrap();

    assert_eq!(status(&app, &cookie, "/doc/1").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_second_reload_back_to_a_permit_reaches_the_gate() {
    let ps = Arc::new(PolicyStore::from_text(PERMIT_ALL, SCHEMA).unwrap());
    let authz = AuthzStore::try_new(ps.clone(), Arc::new(Provider), "App").unwrap();
    let app = router(installed(ps.clone()));
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

/// The schema of the group below: `View` takes an optional `mfa_verified`.
const CONTEXT_SCHEMA: &str = r#"{
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

/// A forbid that guards an optional attribute. On an empty context the
/// guard is false, the forbid matches nothing and the permit allows: the
/// set a gate must never decide without its context.
const OPTIONAL_GUARD: &str = r#"
    permit (principal, action, resource);
    forbid (principal, action, resource)
        when { context has mfa_verified && !context.mfa_verified };
"#;

/// Reports a fixed MFA status.
struct Mfa(bool);

impl RequestContextProvider for Mfa {
    fn context_for<'a>(
        &'a self,
        _: &'a axess::AuthSession,
        _: &'a axum::http::request::Parts,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Context, AuthzError>> + Send + 'a>>
    {
        let mfa = self.0;
        Box::pin(async move {
            Context::from_pairs([(
                "mfa_verified".to_string(),
                RestrictedExpression::new_bool(mfa),
            )])
            .map_err(|e| AuthzError::Context(format!("{e:?}")))
        })
    }
}

/// The path a reload takes to the gate: `AuthzStore::reload_policies` builds
/// the new set and the `PolicyStore` the installation also holds adopts it.
/// The installation was built, and accepted without a provider, while the
/// policies read nothing; the reloaded set reads `context`. The gate refuses
/// every request with a 500 and an error line, and serves again when a
/// reload takes the read out.
#[tokio::test]
async fn a_reload_that_begins_to_read_context_is_refused_at_the_gate_without_a_provider() {
    let ps = Arc::new(PolicyStore::from_text(PERMIT_ALL, CONTEXT_SCHEMA).unwrap());
    let authz = AuthzStore::try_new(ps.clone(), Arc::new(Provider), "App").unwrap();
    let app = router(installed(ps.clone()));
    let cookie = login_cookie(&app).await;
    assert_eq!(status(&app, &cookie, "/doc/1").await, StatusCode::OK);

    authz
        .reload_policies(OPTIONAL_GUARD, CONTEXT_SCHEMA)
        .await
        .unwrap();
    assert!(ps.mentions_context(), "the reloaded set reads `context`");

    let capture = axess_testing::mock_tracing::TracingCapture::install();
    assert_eq!(
        status(&app, &cookie, "/doc/1").await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an empty context would allow this request; the gate must refuse it"
    );
    let refusals: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| {
            e.level == axess_core::tracing::Level::ERROR
                && e.message.contains(
                    "the policies in force read `context` and the AuthzInstallation holds no \
                     RequestContextProvider",
                )
        })
        .collect();
    assert_eq!(refusals.len(), 1, "one error line: {:?}", capture.events());
    // The line names the gate and the action, and says what to build.
    for field in [
        "macro_name=require_authz!",
        "action=View",
        "build the AuthzInstallation with a context provider",
    ] {
        assert!(
            refusals[0].message.contains(field),
            "{field} not in {}",
            refusals[0].message
        );
    }
    drop(capture);

    authz
        .reload_policies(PERMIT_ALL, CONTEXT_SCHEMA)
        .await
        .unwrap();
    assert_eq!(status(&app, &cookie, "/doc/1").await, StatusCode::OK);
}

/// An installation given a provider up front decides the reloaded set with
/// it: what an application that reloads policies is told to do.
#[tokio::test]
async fn a_reload_that_begins_to_read_context_is_decided_with_a_provider_given_up_front() {
    for (mfa, expected) in [(false, StatusCode::FORBIDDEN), (true, StatusCode::OK)] {
        let ps = Arc::new(PolicyStore::from_text(PERMIT_ALL, CONTEXT_SCHEMA).unwrap());
        let authz = AuthzStore::try_new(ps.clone(), Arc::new(Provider), "App").unwrap();
        let installation = AuthzInstallation::new(ps, Arc::new(Provider), Some(Arc::new(Mfa(mfa))))
            .expect("a provider is never refused");
        let app = router(installation);
        let cookie = login_cookie(&app).await;
        assert_eq!(status(&app, &cookie, "/doc/1").await, StatusCode::OK);

        authz
            .reload_policies(OPTIONAL_GUARD, CONTEXT_SCHEMA)
            .await
            .unwrap();

        assert_eq!(status(&app, &cookie, "/doc/1").await, expected, "mfa {mfa}");
    }
}
