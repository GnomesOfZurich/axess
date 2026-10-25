//! Cedar policy store and the `PolicyEvaluator` trait.
//!
//! [`PolicyStore`] compiles and holds a Cedar policy set + schema at startup.
//! It implements [`PolicyEvaluator`], which is the injectable trait used by
//! [`AuthzSession`][super::session::AuthzSession]: swap it for
//! [`MockPolicyEvaluator`][crate::testing::mock_policy::MockPolicyEvaluator]
//! in tests to evaluate authz flows without any Cedar policy files.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    Validator,
};
use std::str::FromStr;

use super::error::AuthzError;

// ── validate_policies ────────────────────────────────────────────────────────

/// Cross-check a Cedar policy set against a schema using Cedar's strict
/// validator.
///
/// Runs [`cedar_policy::Validator`] in [`ValidationMode::Strict`]: rejects
/// policies that reference undeclared entity types, undeclared actions,
/// wrong attribute types, or scope-variable misuse. Separate from
/// parse-time syntax checking ([`AuthzError::PolicyParse`],
/// [`AuthzError::SchemaParse`]); both are required.
///
/// Extracted as a free function so it is callable both at startup (from
/// [`PolicyStore::from_text`]) **and** at future policy hot-swap time,
/// where the invariant is **validate-before-swap**: never leave the
/// authorizer holding a policy set that fails validation.
///
/// All validation errors are collected and joined into a single
/// [`AuthzError::PolicyValidation`] payload so operators see every
/// mismatch, not just the first.
pub fn validate_policies(policies: &PolicySet, schema: &Schema) -> Result<(), AuthzError> {
    let validator = Validator::new(schema.clone());
    let result = validator.validate(policies, ValidationMode::Strict);
    if result.validation_passed() {
        return Ok(());
    }
    let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
    Err(AuthzError::PolicyValidation(errors.join("; ")))
}

// ── AuthzDecision ─────────────────────────────────────────────────────────────

/// The outcome of a Cedar policy evaluation.
///
/// Cedar uses three-valued logic internally: `Allow`, `Deny`, and no applicable
/// policy. When no policy applies, Axess maps the result to `Deny` (deny by
/// default). This enum exposes only the two externally meaningful outcomes.
///
/// If Cedar adds richer decision metadata in the future, extend this enum
/// with new variants and update consumers; exhaustive matches will catch
/// the missing arms at compile time. (Project policy bars the
/// future-proofing attribute that erases exhaustiveness.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDecision {
    /// At least one Cedar `permit` policy matched and no `forbid` policy applied.
    Allow,
    /// No `permit` policy matched, a `forbid` policy applied, or the request
    /// could not be evaluated: it failed schema validation, or any policy
    /// errored. Fail-closed default.
    Deny,
}

// ── PolicyEvaluator ───────────────────────────────────────────────────────────

/// Abstraction over Cedar policy evaluation.
///
/// The production implementation is [`PolicyStore`].
/// Tests use [`MockPolicyEvaluator`][crate::testing::mock_policy::MockPolicyEvaluator]
/// to control decisions without loading policy files.
pub trait PolicyEvaluator: Send + Sync {
    /// Evaluate whether `principal` may perform `action` on `resource`.
    ///
    /// `entities` must contain all entities referenced by the policy (principal,
    /// resource, roles, tenant, etc.). Always returns [`AuthzDecision::Deny`] on
    /// any evaluation error: fail-closed is the only correct default.
    fn is_authorized(
        &self,
        entities: &Entities,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
    ) -> AuthzDecision;

    /// Return the Cedar schema if available. Used to validate entity providers
    /// at startup via [`AuthzEntityProvider::validate_schema`][super::provider::AuthzEntityProvider::validate_schema].
    fn schema(&self) -> Option<&Schema> {
        None
    }
}

// ── PolicyStore ───────────────────────────────────────────────────────────────

/// Compiled, immutable Cedar policy set + schema + authorizer.
///
/// Construct once at startup and wrap in `Arc` for sharing across requests.
/// The namespace is intentionally NOT stored here; it lives on
/// [`AuthzStore`][super::session::AuthzStore] so that entity UID construction
/// and policy evaluation use the same configured namespace.
pub struct PolicyStore {
    policy_set: PolicySet,
    schema: Schema,
    authorizer: Authorizer,
}

impl PolicyStore {
    /// Compile a policy store from Cedar policy text and a JSON schema string.
    ///
    /// Both strings are validated at construction time: any parse or schema
    /// error is returned immediately so misconfiguration fails at startup.
    pub fn from_text(policy_text: &str, schema_json: &str) -> Result<Self, AuthzError> {
        let policy_set = PolicySet::from_str(policy_text)
            .map_err(|e| AuthzError::PolicyParse(format!("{e:?}")))?;

        let schema = Schema::from_json_str(schema_json)
            .map_err(|e| AuthzError::SchemaParse(format!("{e:?}")))?;

        validate_policies(&policy_set, &schema)?;

        Ok(Self {
            policy_set,
            schema,
            authorizer: Authorizer::new(),
        })
    }

    /// Access the Cedar schema (e.g. for entity provider validation).
    pub fn schema(&self) -> &Schema {
        &self.schema
    }
}

/// The rendered principal, action and resource of a decision, kept only
/// while the decision event is enabled.
struct DecisionSubject {
    principal: String,
    action: String,
    resource: String,
}

impl DecisionSubject {
    /// Render the three UIDs, or `None` when no subscriber is interested in
    /// the decision event.
    fn capture(principal: &EntityUid, action: &EntityUid, resource: &EntityUid) -> Option<Self> {
        tracing::enabled!(target: "axess::authz::decision", tracing::Level::INFO).then(|| Self {
            principal: principal.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
        })
    }
}

impl PolicyEvaluator for PolicyStore {
    fn is_authorized(
        &self,
        entities: &Entities,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
    ) -> AuthzDecision {
        // Captured before move into Request for the audit event, and only when
        // a subscriber listens to the decision target: rendering three UIDs
        // per decision is wasted work otherwise.
        let subject = DecisionSubject::capture(&principal, &action, &resource);
        let started = std::time::Instant::now();

        let cedar_req = match Request::new(principal, action, resource, context, Some(&self.schema))
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Cedar request validation failed: {e:?}");
                if let Some(subject) = &subject {
                    tracing::info!(
                        target: "axess::authz::decision",
                        principal = %subject.principal,
                        action = %subject.action,
                        resource = %subject.resource,
                        decision = "deny",
                        reason = "request_validation_failed",
                        latency_us = started.elapsed().as_micros() as u64,
                    );
                }
                return AuthzDecision::Deny;
            }
        };

        let response = self
            .authorizer
            .is_authorized(&cedar_req, &self.policy_set, entities);

        // Log diagnostics server-side for debugging (never in API response)
        let diagnostics = response.diagnostics();
        let reasons: Vec<String> = diagnostics.reason().map(|p| p.to_string()).collect();
        let errors: Vec<String> = diagnostics.errors().map(|e| e.to_string()).collect();

        let latency_us = started.elapsed().as_micros() as u64;

        // Fail closed on any evaluation error. Cedar skips a policy whose
        // evaluation errors, so a `forbid` that fails (an attribute of the
        // wrong type, an overflow) stops forbidding and the `permit` beside it
        // allows. Whatever the decision, a request any policy could not
        // evaluate is denied, and said so at error level.
        if !errors.is_empty() {
            tracing::error!(
                errors = ?errors,
                "Cedar policy evaluation errors: denied"
            );
            if let Some(subject) = &subject {
                tracing::info!(
                    target: "axess::authz::decision",
                    principal = %subject.principal,
                    action = %subject.action,
                    resource = %subject.resource,
                    decision = "deny",
                    reason = "policy_evaluation_error",
                    latency_us = latency_us,
                );
            }
            return AuthzDecision::Deny;
        }

        match response.decision() {
            Decision::Allow => {
                tracing::trace!(reasons = ?reasons, "Cedar: allowed");
                // Structured audit event; see `axess::authz::audit` module
                // docs for the documented schema and target.
                if let Some(subject) = &subject {
                    tracing::info!(
                        target: "axess::authz::decision",
                        principal = %subject.principal,
                        action = %subject.action,
                        resource = %subject.resource,
                        decision = "allow",
                        reasons = ?reasons,
                        latency_us = latency_us,
                    );
                }
                AuthzDecision::Allow
            }
            Decision::Deny => {
                tracing::debug!(reasons = ?reasons, "Cedar: denied");
                if let Some(subject) = &subject {
                    tracing::info!(
                        target: "axess::authz::decision",
                        principal = %subject.principal,
                        action = %subject.action,
                        resource = %subject.resource,
                        decision = "deny",
                        reasons = ?reasons,
                        latency_us = latency_us,
                    );
                }
                AuthzDecision::Deny
            }
        }
    }

    fn schema(&self) -> Option<&Schema> {
        Some(&self.schema)
    }
}

// ── UID builder helpers ───────────────────────────────────────────────────────

/// Build a Cedar `EntityUid` from a type name, id, and namespace.
///
/// Produces `{namespace}::{type_name}::"id"`.
pub(super) fn make_uid(
    namespace: &str,
    type_name: &str,
    id: &str,
) -> Result<EntityUid, AuthzError> {
    // Built from the type name and the id as DATA, never by formatting Cedar
    // source and parsing it back: a parsed id decodes `\u{61}lice` to
    // `alice` and chokes on `"` or `\`, so two ids could name one entity.
    super::provider::make_entity_uid(namespace, type_name, id)
}

#[cfg(test)]
mod decision_log;

#[cfg(test)]
mod authz_store_tests {
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
}
