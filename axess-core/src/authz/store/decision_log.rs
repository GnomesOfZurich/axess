//! The decision event is rendered only when something listens for it.

use super::*;
use crate::testing::mock_tracing::TracingCapture;

const SCHEMA: &str = r#"{
    "TestApp": {
        "entityTypes": { "User": { "memberOfTypes": [] }, "Resource": { "memberOfTypes": [] } },
        "actions": { "View": { "appliesTo": {
            "principalTypes": ["User"], "resourceTypes": ["Resource"] } } }
    }
}"#;

const POLICY: &str = r#"permit(principal, action == TestApp::Action::"View", resource);"#;

fn uid(s: &str) -> EntityUid {
    s.parse().unwrap()
}

fn decide(store: &PolicyStore) -> AuthzDecision {
    store.is_authorized(
        &Entities::empty(),
        uid(r#"TestApp::User::"alice""#),
        uid(r#"TestApp::Action::"View""#),
        uid(r#"TestApp::Resource::"doc1""#),
        Context::empty(),
    )
}

#[test]
fn nothing_is_rendered_without_a_listener() {
    let (p, a, r) = (
        uid(r#"TestApp::User::"alice""#),
        uid(r#"TestApp::Action::"View""#),
        uid(r#"TestApp::Resource::"doc1""#),
    );
    assert!(DecisionSubject::capture(&p, &a, &r).is_none());
    let store = PolicyStore::from_text(POLICY, SCHEMA).unwrap();
    assert_eq!(decide(&store), AuthzDecision::Allow);
}

#[test]
fn a_listener_receives_the_subject_of_the_decision() {
    let store = PolicyStore::from_text(POLICY, SCHEMA).unwrap();
    let capture = TracingCapture::install();
    assert_eq!(decide(&store), AuthzDecision::Allow);
    let event = capture
        .events()
        .into_iter()
        .find(|e| e.target == "axess::authz::decision")
        .expect("decision event");
    for needle in [
        r#"TestApp::User::"alice""#,
        r#"TestApp::Action::"View""#,
        r#"TestApp::Resource::"doc1""#,
        "allow",
    ] {
        assert!(
            event.message.contains(needle),
            "{needle}: {}",
            event.message
        );
    }
}
