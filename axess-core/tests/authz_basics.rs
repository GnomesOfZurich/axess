#![cfg(all(feature = "testing", feature = "authz"))]
//! Authorization smoke tests: `AuthzStore` + `MockPolicyEvaluator`
//! permit/deny semantics, batch checks, and entity caching.

use axess_core::{
    authz::{AuthzDecision, AuthzDenied, AuthzStore},
    testing::mock_policy::{MockEntityProvider, MockPolicyEvaluator},
};
use std::sync::Arc;

fn make_store(evaluator: MockPolicyEvaluator) -> Arc<AuthzStore<MockEntityProvider>> {
    Arc::new(AuthzStore::new(
        Arc::new(evaluator),
        Arc::new(MockEntityProvider::new("Test")),
        "Test",
    ))
}

#[tokio::test]
async fn require_allowed_action_succeeds() {
    let store =
        make_store(MockPolicyEvaluator::new().permit_ns("Test", "ViewDoc", "Resource", "doc-1"));
    let session = store.for_user_id("alice").unwrap();
    let result = session.require("ViewDoc", &"doc-1".to_string()).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn require_denied_action_returns_authz_denied() {
    let store = make_store(MockPolicyEvaluator::new()); // deny by default
    let session = store.for_user_id("alice").unwrap();
    let result = session.require("ViewDoc", &"doc-1".to_string()).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), AuthzDenied);
}

#[tokio::test]
async fn is_permitted_returns_bool() {
    let store =
        make_store(MockPolicyEvaluator::new().permit_ns("Test", "Edit", "Resource", "doc-1"));
    let session = store.for_user_id("alice").unwrap();
    assert!(session.is_permitted("Edit", &"doc-1".to_string()).await);
    assert!(!session.is_permitted("Delete", &"doc-1".to_string()).await);
}

#[tokio::test]
async fn batch_check_returns_decisions_in_order() {
    let store = make_store(
        MockPolicyEvaluator::new()
            .permit_ns("Test", "View", "Resource", "doc-1")
            .deny_ns("Test", "Delete", "Resource", "doc-1"),
    );
    let session = store.for_user_id("alice").unwrap();
    let doc_id = "doc-1".to_string();
    let checks = vec![("View", &doc_id), ("Delete", &doc_id)];
    let results = session.batch_check(&checks).await;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].1, AuthzDecision::Allow);
    assert_eq!(results[1].1, AuthzDecision::Deny);
}

#[tokio::test]
async fn allow_all_evaluator_permits_everything() {
    let store = make_store(MockPolicyEvaluator::allow_all());
    let session = store.for_user_id("anyone").unwrap();
    assert!(
        session
            .is_permitted("Anything", &"whatever".to_string())
            .await
    );
}

#[tokio::test]
async fn entity_cache_deduplicates_repeated_checks() {
    // Two identical checks should hit the cache: this test just verifies
    // it doesn't crash or return different results.
    let store =
        make_store(MockPolicyEvaluator::new().permit_ns("Test", "View", "Resource", "doc-1"));
    let session = store.for_user_id("alice").unwrap();
    let r1 = session.is_permitted("View", &"doc-1".to_string()).await;
    let r2 = session.is_permitted("View", &"doc-1".to_string()).await;
    assert_eq!(r1, r2);
    assert!(r1);
}
