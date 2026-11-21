//! Whether a policy set reads the request context is decided from the parsed
//! policies: the word in a comment, a string, an attribute name, an entity id
//! or an annotation is not a read, and a read is found wherever an expression
//! can hold one, in templates as well as in policies.

use super::PolicyStore;

/// A principal with a `name` and a `context` attribute, and a request context
/// with an optional `mfa` flag and an optional `level`.
const SCHEMA_JSON: &str = r#"{
    "TestApp": {
        "entityTypes": {
            "User": {
                "memberOfTypes": [],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "name": { "type": "String" },
                        "context": { "type": "String" }
                    }
                }
            },
            "Resource": { "memberOfTypes": [] }
        },
        "actions": {
            "View": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Resource"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "mfa": { "type": "Boolean", "required": false },
                            "level": { "type": "Long", "required": false }
                        }
                    }
                }
            }
        }
    }
}"#;

fn reads_context(policy_text: &str) -> bool {
    PolicyStore::from_text(policy_text, SCHEMA_JSON)
        .expect("the policy text is valid against the schema")
        .mentions_context()
}

#[test]
fn the_word_in_a_comment_is_not_a_read() {
    assert!(!reads_context(
        r#"permit(principal, action, resource) when {
            // the request context plays no part in this rule
            principal.name == "alice"
        };"#
    ));
}

#[test]
fn the_word_in_a_string_literal_is_not_a_read() {
    assert!(!reads_context(
        r#"permit(principal, action, resource) when { principal.name == "context" };"#
    ));
}

#[test]
fn an_attribute_an_entity_id_a_record_key_and_an_annotation_of_that_name_are_not_reads() {
    assert!(!reads_context(
        r#"permit(principal, action, resource) when { principal.context == "x" };"#
    ));
    assert!(!reads_context(
        r#"permit(principal == TestApp::User::"context", action, resource);"#
    ));
    assert!(!reads_context(
        r#"permit(principal, action, resource) when { {context: 1}.context == 1 };"#
    ));
    assert!(!reads_context(
        r#"@context("none") permit(principal, action, resource);"#
    ));
}

#[test]
fn a_when_clause_that_reads_a_context_attribute_is_a_read() {
    assert!(reads_context(
        r#"permit(principal, action, resource) when { context has mfa && context.mfa };"#
    ));
}

#[test]
fn an_unless_clause_that_reads_the_context_is_a_read() {
    assert!(reads_context(
        r#"permit(principal, action, resource) unless { context has mfa && context.mfa };"#
    ));
}

#[test]
fn a_has_test_alone_is_a_read() {
    assert!(reads_context(
        r#"forbid(principal, action, resource) when { context has mfa };"#
    ));
}

#[test]
fn a_template_that_reads_the_context_is_a_read() {
    assert!(reads_context(
        r#"permit(principal == ?principal, action, resource)
           when { context has mfa && context.mfa };"#
    ));
}

/// The read sits below the top of the expression: in a record value, a set
/// element and the branches of a conditional.
#[test]
fn a_read_nested_inside_another_expression_is_found() {
    assert!(reads_context(
        r#"permit(principal, action, resource) when {
            context has level && {Value: context.level}.Value == 1
        };"#
    ));
    assert!(reads_context(
        r#"permit(principal, action, resource) when {
            context has level && [1, 2].contains(context.level)
        };"#
    ));
    assert!(reads_context(
        r#"permit(principal, action, resource) when {
            if principal.name == "alice" then true else (context has mfa)
        };"#
    ));
}

/// One reading policy among others is enough, and a set with none reads
/// nothing.
#[test]
fn one_reading_policy_among_others_is_a_read() {
    assert!(reads_context(
        r#"permit(principal, action, resource);
           forbid(principal, action, resource) when { context has mfa && !context.mfa };"#
    ));
    assert!(!reads_context(
        r#"permit(principal, action, resource);
           forbid(principal, action, resource) when { principal.name == "mallory" };"#
    ));
}
