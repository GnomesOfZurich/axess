//! The installation refuses, where it is built, a policy store it could not
//! decide with, and hands the gate exactly the parts it was given.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cedar_policy::{Context, Entities, Entity, EntityUid, RestrictedExpression};
use tower::{Layer, ServiceExt};

use super::AuthzInstallation;
use crate::authz::{
    AuthzError, AuthzStore, PolicyStore, RequestContextProvider, RequestEntityProvider,
};
use crate::testing::mock_policy::MockEntityProvider;

const SCHEMA: &str = r#"{
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

const NO_CONTEXT: &str = "permit (principal, action, resource);";

/// The guard an empty context turns into nothing: the reason a provider is
/// required.
const READS_CONTEXT: &str = r#"
    permit (principal, action, resource);
    forbid (principal, action, resource)
        when { context has mfa_verified && !context.mfa_verified };
"#;

/// A read that lives in a template only, with no policy linked to it.
const TEMPLATE_READS_CONTEXT: &str = r#"
    permit (principal, action, resource);
    forbid (principal == ?principal, action, resource)
        when { context has mfa_verified && !context.mfa_verified };
"#;

fn store(policy: &str) -> Arc<PolicyStore> {
    Arc::new(PolicyStore::from_text(policy, SCHEMA).expect("the policy is valid"))
}

struct NoEntities;

impl RequestEntityProvider for NoEntities {
    fn entities_for<'a>(
        &'a self,
        _: &'a crate::session::AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        _: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        let (principal, resource) = (principal.clone(), resource.clone());
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

struct Mfa(bool);

impl RequestContextProvider for Mfa {
    fn context_for<'a>(
        &'a self,
        _: &'a crate::session::AuthSession,
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

fn entities() -> Arc<dyn RequestEntityProvider> {
    Arc::new(NoEntities)
}

#[test]
fn a_store_that_reads_context_is_refused_without_a_provider() {
    let refused = AuthzInstallation::new(store(READS_CONTEXT), entities(), None)
        .expect_err("a store that reads `context` needs a provider");
    assert!(
        matches!(refused, AuthzError::ContextProviderRequired),
        "{refused:?}"
    );
}

#[test]
fn the_refusal_says_what_to_pass() {
    let text = AuthzInstallation::new(store(READS_CONTEXT), entities(), None)
        .expect_err("refused")
        .to_string();
    for needle in [
        "the policies read `context`",
        "Some(Arc<dyn RequestContextProvider>)",
        "third argument of AuthzInstallation::new",
    ] {
        assert!(text.contains(needle), "{needle:?} not in {text:?}");
    }
    // One line: the text is read in a startup log.
    assert!(!text.contains('\n'), "{text:?}");
    assert!(!text.contains("  "), "{text:?}");
}

#[test]
fn a_template_that_reads_context_is_refused_without_a_provider() {
    let refused = AuthzInstallation::new(store(TEMPLATE_READS_CONTEXT), entities(), None);
    assert!(matches!(refused, Err(AuthzError::ContextProviderRequired)));
}

#[test]
fn a_store_that_never_reads_context_builds_without_a_provider() {
    let installation = AuthzInstallation::new(store(NO_CONTEXT), entities(), None)
        .expect("a store that never reads `context` needs no provider");
    assert!(installation.context().is_none());
}

#[test]
fn a_store_that_reads_context_builds_with_a_provider() {
    let installation =
        AuthzInstallation::new(store(READS_CONTEXT), entities(), Some(Arc::new(Mfa(true))))
            .expect("the provider is there");
    assert!(installation.context().is_some());
}

#[test]
fn a_provider_is_kept_for_a_store_that_does_not_read_context_yet() {
    // A reload may bring the read in; the provider given up front is then
    // already there.
    let installation =
        AuthzInstallation::new(store(NO_CONTEXT), entities(), Some(Arc::new(Mfa(true))))
            .expect("a provider is never refused");
    assert!(installation.context().is_some());
}

#[test]
fn the_installation_hands_back_the_parts_it_was_given() {
    let policies = store(NO_CONTEXT);
    let provider = entities();
    let context: Arc<dyn RequestContextProvider> = Arc::new(Mfa(true));
    let installation =
        AuthzInstallation::new(policies.clone(), provider.clone(), Some(context.clone()))
            .expect("built");
    assert!(Arc::ptr_eq(installation.store(), &policies));
    assert!(Arc::ptr_eq(installation.entities(), &provider));
    assert!(Arc::ptr_eq(
        installation.context().expect("given"),
        &context
    ));
    // A clone is the same installation, not a copy of its parts.
    let clone = installation.clone();
    assert!(Arc::ptr_eq(clone.store(), installation.store()));
}

/// The build-time check judges the set in force when it runs. A reload that
/// brings a read of `context` in afterwards is visible through the store the
/// installation holds, which is what the gate asks per request.
#[tokio::test]
async fn a_reload_that_begins_to_read_context_shows_through_the_installation() {
    let policies = store(NO_CONTEXT);
    let installation =
        AuthzInstallation::new(policies.clone(), entities(), None).expect("no read yet");
    let authz = AuthzStore::try_new(policies, Arc::new(MockEntityProvider::new("App")), "App")
        .expect("the mock provider fits every schema");
    assert!(!installation.store().mentions_context());

    authz
        .reload_policies(READS_CONTEXT, SCHEMA)
        .await
        .expect("the reload is valid");

    assert!(installation.store().mentions_context());
    assert!(installation.context().is_none());
}

#[test]
fn the_debug_form_names_the_digest_and_whether_a_provider_is_there() {
    let policies = store(NO_CONTEXT);
    let installation = AuthzInstallation::new(policies.clone(), entities(), None).expect("built");
    let text = format!("{installation:?}");
    assert!(text.contains(&policies.digest()), "{text}");
    assert!(text.contains("context_provider: false"), "{text}");
}

/// As a layer the installation puts itself, and nothing else, into the
/// request extensions.
#[tokio::test]
async fn the_layer_adds_the_installation_to_the_request() {
    let policies = store(NO_CONTEXT);
    let installation = AuthzInstallation::new(policies.clone(), entities(), None).expect("built");
    let service = installation.layer(tower::service_fn(
        |request: axum::http::Request<axum::body::Body>| async move {
            let found = request.extensions().get::<AuthzInstallation>().cloned();
            let separate = request.extensions().get::<Arc<PolicyStore>>().is_some();
            Ok::<_, std::convert::Infallible>((found, separate))
        },
    ));
    let (found, separate) = service
        .oneshot(axum::http::Request::new(axum::body::Body::empty()))
        .await
        .expect("infallible");
    let found = found.expect("the installation is in the extensions");
    assert!(Arc::ptr_eq(found.store(), &policies));
    assert!(!separate, "the store is not installed on its own");
}
