//! `axess::authz::require` evaluates with the context the caller passes.

#![cfg(feature = "authz")]

use axess::authz::{AuthzRequest, PolicyStore, make_action_uid, make_entity_uid, require};
use cedar_policy::{Context, Entities, RestrictedExpression};

const SCHEMA: &str = r#"{
    "App": {
        "entityTypes": {
            "User": { "shape": { "type": "Record", "attributes": {} } },
            "Doc": { "shape": { "type": "Record", "attributes": {} } }
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

const POLICY: &str = "permit (principal, action, resource) when { context.mfa_verified };";

fn request() -> AuthzRequest {
    AuthzRequest {
        principal: make_entity_uid("App", "User", "alice").unwrap(),
        action: make_action_uid("App", "View").unwrap(),
        resource: make_entity_uid("App", "Doc", "d1").unwrap(),
    }
}

fn mfa(verified: bool) -> Context {
    Context::from_pairs([(
        "mfa_verified".to_string(),
        RestrictedExpression::new_bool(verified),
    )])
    .unwrap()
}

#[test]
fn the_context_the_caller_passes_decides() {
    let store = PolicyStore::from_text(POLICY, SCHEMA).unwrap();
    let req = request();
    assert!(require(&store, Entities::empty(), &req, mfa(true)).is_ok());
    assert!(require(&store, Entities::empty(), &req, mfa(false)).is_err());
    assert!(
        require(&store, Entities::empty(), &req, Context::empty()).is_err(),
        "an empty context must not satisfy a rule that reads it"
    );
}
