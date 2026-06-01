//! Cedar policy store and the `PolicyEvaluator` trait.
//!
//! [`PolicyStore`] compiles and holds a Cedar policy set + schema at startup.
//! It implements [`PolicyEvaluator`], which is the injectable trait used by
//! [`AuthzSession`][super::session::AuthzSession]: swap it for
//! [`MockPolicyEvaluator`][crate::testing::mock_policy::MockPolicyEvaluator]
//! in tests to evaluate authz flows without any Cedar policy files.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema,
};
use std::str::FromStr;
use tracing::warn;

use super::error::AuthzError;

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
    /// No `permit` policy matched, or a `forbid` policy applied. Fail-closed default.
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
    /// at startup via [`AuthzEntityProvider::validate_against_schema`][super::provider::AuthzEntityProvider::validate_against_schema].
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

impl PolicyEvaluator for PolicyStore {
    fn is_authorized(
        &self,
        entities: &Entities,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
    ) -> AuthzDecision {
        // Captured before move into Request for the audit event.
        let principal_str = principal.to_string();
        let action_str = action.to_string();
        let resource_str = resource.to_string();
        let started = std::time::Instant::now();

        let cedar_req = match Request::new(principal, action, resource, context, Some(&self.schema))
        {
            Ok(r) => r,
            Err(e) => {
                warn!("Cedar request validation failed: {e:?}");
                tracing::info!(
                    target: "axess::authz::decision",
                    principal = %principal_str,
                    action = %action_str,
                    resource = %resource_str,
                    decision = "deny",
                    reason = "request_validation_failed",
                    latency_us = started.elapsed().as_micros() as u64,
                );
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

        if !errors.is_empty() {
            tracing::warn!(
                errors = ?errors,
                "Cedar policy evaluation errors"
            );
        }

        let latency_us = started.elapsed().as_micros() as u64;
        match response.decision() {
            Decision::Allow => {
                tracing::trace!(reasons = ?reasons, "Cedar: allowed");
                // Structured audit event; see `axess::authz::audit` module
                // docs for the documented schema and target.
                tracing::info!(
                    target: "axess::authz::decision",
                    principal = %principal_str,
                    action = %action_str,
                    resource = %resource_str,
                    decision = "allow",
                    reasons = ?reasons,
                    latency_us = latency_us,
                );
                AuthzDecision::Allow
            }
            Decision::Deny => {
                tracing::debug!(reasons = ?reasons, "Cedar: denied");
                tracing::info!(
                    target: "axess::authz::decision",
                    principal = %principal_str,
                    action = %action_str,
                    resource = %resource_str,
                    decision = "deny",
                    reasons = ?reasons,
                    latency_us = latency_us,
                );
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
    EntityUid::from_str(&format!(r#"{namespace}::{type_name}::"{id}""#))
        .map_err(|e| AuthzError::InvalidEntityUid(format!("{type_name}/{id}: {e:?}")))
}

#[cfg(test)]
mod authz_store_tests {
    use super::*;

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

    #[test]
    fn policy_evaluator_schema_returns_some_when_loaded() {
        // pins `<impl PolicyEvaluator for PolicyStore>::schema
        // -> None` mutation. The trait default body returns `None`,
        // but `PolicyStore` overrides with `Some(&self.schema)`. The
        // mutation collapses the override back to the default; this
        // would silently disable schema-driven `validate_against_schema`
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
