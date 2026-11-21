#![cfg(all(feature = "testing", feature = "authz"))]
//! A session without a request context is never decided against policies
//! that read `context`.
//!
//! On an empty context a `forbid` that guards an optional attribute with
//! `context has ..` stops applying, and the `permit` beside it allows. So
//! the builders of `AuthzStore` that take no context answer an error when
//! the policies in force read `context`, the builders that take one are the
//! way through, and a session begun before a reload brought the read in is
//! denied by the reloaded set.

use axess_core::authz::{
    AuthzDenied, AuthzError, AuthzStore, NoContext, PolicyStore, StandardRequestContext,
};
use axess_core::testing::mock_policy::{MockEntityProvider, MockPolicyEvaluator};
use axess_testing::mock_tracing::TracingCapture;
use std::sync::Arc;

const SCHEMA: &str = r#"{
    "App": {
        "entityTypes": {
            "User": { "shape": { "type": "Record", "attributes": {} } },
            "Resource": { "shape": { "type": "Record", "attributes": {} } }
        },
        "actions": {
            "View": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Resource"],
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

/// A permit beside a forbid that guards an optional attribute: the pair an
/// empty context allows.
const GUARDED: &str = r#"
    permit (principal, action, resource);
    forbid (principal, action, resource)
        when { context has mfa_verified && !context.mfa_verified };
"#;

const NO_CONTEXT_READ: &str = "permit (principal, action, resource);";

fn store(policy: &str) -> Arc<AuthzStore<MockEntityProvider>> {
    Arc::new(
        AuthzStore::try_new(
            Arc::new(PolicyStore::from_text(policy, SCHEMA).expect("the policy is valid")),
            Arc::new(MockEntityProvider::new("App")),
            "App",
        )
        .expect("the mock provider fits every schema"),
    )
}

fn doc() -> String {
    "doc-1".to_string()
}

fn mfa(verified: bool) -> StandardRequestContext {
    StandardRequestContext::new(verified, None)
}

#[test]
fn a_session_without_a_context_is_refused_when_the_policies_read_context() {
    let refused = store(GUARDED).for_user_id("alice");
    assert!(
        matches!(refused, Err(AuthzError::ContextRequired)),
        "the guarded pair must not be decided on an empty context: {:?}",
        refused.err()
    );
}

#[test]
fn the_refusal_names_the_forms_that_take_a_context() {
    let text = store(GUARDED)
        .for_user_id("alice")
        .err()
        .expect("refused")
        .to_string();
    for needle in [
        "the policies read `context`",
        "for_user_id_with_context",
        "for_user_in_tenant_with_context",
        "for_session",
    ] {
        assert!(text.contains(needle), "{needle:?} not in {text:?}");
    }
    assert!(!text.contains('\n') && !text.contains("  "), "{text:?}");
}

#[test]
fn a_tenant_session_without_a_context_is_refused_when_the_policies_read_context() {
    let refused = store(GUARDED).for_user_in_tenant("alice", "t1");
    assert!(matches!(refused, Err(AuthzError::ContextRequired)));
}

/// Naming `NoContext` to a builder that takes a context supplies none: it
/// is the same call as the builder without one.
#[test]
fn no_context_handed_to_a_with_context_form_is_refused_as_well() {
    let guarded = store(GUARDED);
    assert!(matches!(
        guarded.for_user_id_with_context("alice", NoContext),
        Err(AuthzError::ContextRequired)
    ));
    assert!(matches!(
        guarded.for_user_id_with_context("alice", Arc::new(NoContext)),
        Err(AuthzError::ContextRequired)
    ));
    assert!(matches!(
        guarded.for_user_in_tenant_with_context("alice", "t1", NoContext),
        Err(AuthzError::ContextRequired)
    ));
}

#[tokio::test]
async fn the_with_context_form_is_decided_on_the_context() {
    let guarded = store(GUARDED);

    let without_mfa = guarded
        .for_user_id_with_context("alice", mfa(false))
        .expect("a context is supplied");
    assert_eq!(without_mfa.require("View", &doc()).await, Err(AuthzDenied));

    let with_mfa = guarded
        .for_user_id_with_context("alice", mfa(true))
        .expect("a context is supplied");
    assert_eq!(with_mfa.require("View", &doc()).await, Ok(()));
}

#[tokio::test]
async fn the_tenant_form_with_a_context_is_decided_on_the_context() {
    let guarded = store(GUARDED);

    let without_mfa = guarded
        .for_user_in_tenant_with_context("alice", "t1", mfa(false))
        .expect("a context is supplied");
    assert_eq!(without_mfa.require("View", &doc()).await, Err(AuthzDenied));

    let with_mfa = guarded
        .for_user_in_tenant_with_context("alice", "t1", mfa(true))
        .expect("a context is supplied");
    assert_eq!(with_mfa.require("View", &doc()).await, Ok(()));
}

#[tokio::test]
async fn a_store_that_never_reads_context_still_takes_the_forms_without_one() {
    let plain = store(NO_CONTEXT_READ);

    let session = plain.for_user_id("alice").expect("nothing reads `context`");
    assert_eq!(session.require("View", &doc()).await, Ok(()));

    let in_tenant = plain
        .for_user_in_tenant("alice", "t1")
        .expect("nothing reads `context`");
    assert_eq!(in_tenant.require("View", &doc()).await, Ok(()));

    let named = plain
        .for_user_id_with_context("alice", NoContext)
        .expect("nothing reads `context`");
    assert!(named.is_permitted("View", &doc()).await);
}

/// The mock evaluator decides on the action and the resource alone, and
/// says so, so tests written against it keep the form without a context.
#[tokio::test]
async fn the_mock_evaluator_reads_no_context() {
    let store = Arc::new(
        AuthzStore::try_new(
            Arc::new(MockPolicyEvaluator::new().permit_ns("App", "View", "Resource", "doc-1")),
            Arc::new(MockEntityProvider::new("App")),
            "App",
        )
        .expect("the mock evaluator has no schema"),
    );
    let session = store
        .for_user_id("alice")
        .expect("the mock reads no context");
    assert_eq!(session.require("View", &doc()).await, Ok(()));
}

/// The reload: a store whose policies read nothing is reloaded to the
/// guarded pair. A session begun before the reload and still held is denied
/// by the reloaded set, with a decision event that says why; a session begun
/// after it is refused where it is begun; and a session with a context is
/// decided. A reload that takes the read out again restores all of it.
#[tokio::test]
async fn a_reload_that_begins_to_read_context_denies_a_session_without_one() {
    let store = store(NO_CONTEXT_READ);
    let held = store.for_user_id("alice").expect("nothing reads `context`");
    assert_eq!(held.require("View", &doc()).await, Ok(()));

    store
        .reload_policies(GUARDED, SCHEMA)
        .await
        .expect("the reload is valid");

    let capture = TracingCapture::install();
    assert_eq!(
        held.require("View", &doc()).await,
        Err(AuthzDenied),
        "an empty context would allow this request; the reloaded set must deny it"
    );
    assert!(!held.is_permitted("View", &doc()).await);
    let events = capture.events();
    assert!(
        events.iter().any(|e| e.target == "axess::authz::decision"
            && e.message.contains("decision=deny")
            && e.message.contains("reason=context_required")),
        "the denial is in the decision trail: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.level == tracing::Level::ERROR
            && e.message.contains(
                "the policies in force read `context` and this session was begun without one"
            )),
        "the denial is logged as an error: {events:?}"
    );
    drop(capture);

    assert!(matches!(
        store.for_user_id("alice"),
        Err(AuthzError::ContextRequired)
    ));
    let with_mfa = store
        .for_user_id_with_context("alice", mfa(true))
        .expect("a context is supplied");
    assert_eq!(with_mfa.require("View", &doc()).await, Ok(()));

    store
        .reload_policies(NO_CONTEXT_READ, SCHEMA)
        .await
        .expect("the reload is valid");
    assert_eq!(held.require("View", &doc()).await, Ok(()));
    assert!(store.for_user_id("alice").is_ok());
}
