use super::*;

/// An id is data: an escape sequence in it names a different entity from
/// the decoded spelling, and a quote or backslash is not an error.
#[test]
fn make_uid_keeps_the_id_as_data() {
    let escaped = make_uid("TestApp", "User", r"\u{61}lice").expect("escaped id is an id");
    let plain = make_uid("TestApp", "User", "alice").expect("plain id");
    assert_ne!(
        escaped, plain,
        "an escape sequence must not decode into another principal"
    );
    assert_eq!(escaped.id().unescaped(), r"\u{61}lice");
    assert!(
        make_uid("TestApp", "User", "a\"b\\c").is_ok(),
        "a quote or backslash in an id is data"
    );
}

const SCHEMA_JSON: &str = r#"{
    "TestApp": {
        "entityTypes": {
            "User": { "memberOfTypes": [] },
            "Resource": { "memberOfTypes": [] }
        },
        "actions": {
            "View": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Resource"]
                }
            }
        }
    }
}"#;

const POLICY_TEXT: &str = r#"permit(
    principal == TestApp::User::"alice",
    action == TestApp::Action::"View",
    resource == TestApp::Resource::"doc1"
);"#;

fn build_store() -> PolicyStore {
    PolicyStore::from_text(POLICY_TEXT, SCHEMA_JSON).unwrap()
}

/// A schema whose `User` carries a number, so a policy can do arithmetic
/// on it that passes strict validation and fails at evaluation.
const COUNTING_SCHEMA_JSON: &str = r#"{
    "TestApp": {
        "entityTypes": {
            "User": {
                "memberOfTypes": [],
                "shape": {
                    "type": "Record",
                    "attributes": { "n": { "type": "Long" } }
                }
            },
            "Resource": { "memberOfTypes": [] }
        },
        "actions": {
            "View": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Resource"]
                }
            }
        }
    }
}"#;

fn alice_with(n: i64, store: &PolicyStore) -> Entities {
    let json = format!(
        r#"[{{"uid": {{"type": "TestApp::User", "id": "alice"}}, "attrs": {{"n": {n}}}, "parents": []}}]"#
    );
    Entities::from_json_str(&json, Some(store.schema())).unwrap()
}

fn view_doc1(store: &PolicyStore, entities: &Entities) -> AuthzDecision {
    store.is_authorized(
        entities,
        r#"TestApp::User::"alice""#.parse().unwrap(),
        r#"TestApp::Action::"View""#.parse().unwrap(),
        r#"TestApp::Resource::"doc1""#.parse().unwrap(),
        Context::empty(),
    )
}

/// A `forbid` that errors does not stop forbidding.
///
/// Cedar skips a policy whose evaluation errors, so a `forbid` that fails
/// (here on an overflow; in practice on an attribute an entity lacks)
/// would stop applying and let the `permit` beside it allow. The decision
/// must fail closed: any evaluation error is a deny.
#[test]
fn an_erroring_forbid_fails_closed() {
    let policies = r#"
        permit(principal, action == TestApp::Action::"View", resource);
        forbid(principal, action, resource)
            when { principal.n + 9223372036854775807 > 0 };
    "#;
    let store = PolicyStore::from_text(policies, COUNTING_SCHEMA_JSON).unwrap();
    // The forbid evaluates without error and applies: denied.
    assert_eq!(
        view_doc1(&store, &alice_with(0, &store)),
        AuthzDecision::Deny
    );
    // The forbid overflows: Cedar would skip it and allow.
    assert_eq!(
        view_doc1(&store, &alice_with(1, &store)),
        AuthzDecision::Deny
    );
}

/// An erroring `permit` was already a deny; it stays one.
#[test]
fn an_erroring_permit_denies() {
    let policies = r#"
        permit(principal, action == TestApp::Action::"View", resource)
            when { principal.n + 9223372036854775807 > 0 };
    "#;
    let store = PolicyStore::from_text(policies, COUNTING_SCHEMA_JSON).unwrap();
    assert_eq!(
        view_doc1(&store, &alice_with(1, &store)),
        AuthzDecision::Deny
    );
    assert_eq!(
        view_doc1(&store, &alice_with(-1, &store)),
        AuthzDecision::Allow
    );
}

/// Cedar would let the working `permit` allow; any evaluation error denies.
#[test]
fn a_working_permit_beside_an_erroring_one_denies() {
    let policies = r#"
        permit(principal, action == TestApp::Action::"View", resource);
        permit(principal, action == TestApp::Action::"View", resource)
            when { principal.n + 9223372036854775807 > 0 };
    "#;
    let store = PolicyStore::from_text(policies, COUNTING_SCHEMA_JSON).unwrap();
    assert_eq!(
        view_doc1(&store, &alice_with(1, &store)),
        AuthzDecision::Deny
    );
    assert_eq!(
        view_doc1(&store, &alice_with(-1, &store)),
        AuthzDecision::Allow
    );
}

const GROUP_SCHEMA_JSON: &str = r#"{
    "TestApp": {
        "entityTypes": {
            "User": { "memberOfTypes": [] },
            "Resource": { "memberOfTypes": [] }
        },
        "actions": {
            "Mutating": {},
            "DeleteDocument": {
                "memberOf": [{ "id": "Mutating" }],
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Resource"],
                    "context": {
                        "type": "Record",
                        "attributes": { "mfa_verified": { "type": "Boolean" } }
                    }
                }
            }
        }
    }
}"#;

const GROUP_POLICIES: &str = r#"
    permit(principal, action, resource);
    forbid(principal, action in TestApp::Action::"Mutating", resource)
        when { !context.mfa_verified };
"#;

fn delete_doc(store: &PolicyStore, entities: &Entities, mfa: bool) -> AuthzDecision {
    let context = Context::from_json_value(
        serde_json::json!({ "mfa_verified": mfa }),
        Some((
            store.schema(),
            &r#"TestApp::Action::"DeleteDocument""#.parse().unwrap(),
        )),
    )
    .unwrap();
    store.is_authorized(
        entities,
        r#"TestApp::User::"alice""#.parse().unwrap(),
        r#"TestApp::Action::"DeleteDocument""#.parse().unwrap(),
        r#"TestApp::Resource::"doc1""#.parse().unwrap(),
        context,
    )
}

/// A `forbid` over an action group holds for entities the provider built
/// without the schema: the store adds the action entities itself.
#[test]
fn a_forbid_over_an_action_group_denies_without_schema_built_entities() {
    let store = PolicyStore::from_text(GROUP_POLICIES, GROUP_SCHEMA_JSON).unwrap();
    let schemaless = Entities::from_entities(
        [Entity::new_no_attrs(
            r#"TestApp::User::"alice""#.parse().unwrap(),
            Default::default(),
        )],
        None,
    )
    .unwrap();
    assert_eq!(
        delete_doc(&store, &schemaless, false),
        AuthzDecision::Deny,
        "the forbid over Mutating must apply"
    );
    assert_eq!(delete_doc(&store, &schemaless, true), AuthzDecision::Allow);

    // Entities built with the schema carry the action entities already
    // and decide the same way.
    let with_schema = Entities::empty()
        .add_entities(
            [Entity::new_no_attrs(
                r#"TestApp::User::"alice""#.parse().unwrap(),
                Default::default(),
            )],
            Some(store.schema()),
        )
        .unwrap();
    assert_eq!(delete_doc(&store, &with_schema, false), AuthzDecision::Deny);
    assert_eq!(delete_doc(&store, &with_schema, true), AuthzDecision::Allow);
}

#[test]
fn policy_evaluator_schema_returns_some_when_loaded() {
    // pins `<impl PolicyEvaluator for PolicyStore>::schema
    // -> None` mutation. The trait default body returns `None`,
    // but `PolicyStore` overrides with `Some(&self.schema)`. The
    // mutation collapses the override back to the default; this
    // would silently disable schema-driven `validate_schema`
    // checks at startup.
    let store = build_store();
    assert!(
        <PolicyStore as PolicyEvaluator>::schema(&store).is_some(),
        "PolicyStore::schema must return Some, not None"
    );
}

#[test]
fn policy_store_schema_accessor_is_borrow_of_inner() {
    // defends the inherent `schema()` accessor against
    // body replacement. Two consecutive calls must return refs
    // to the same Schema instance (verified via pointer equality).
    let store = build_store();
    let s1 = store.schema() as *const _;
    let s2 = store.schema() as *const _;
    assert_eq!(
        s1, s2,
        "schema() must borrow the stored Schema, not produce a new one"
    );
}
