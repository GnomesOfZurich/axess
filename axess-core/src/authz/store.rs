//! Cedar policy store and the `PolicyEvaluator` trait.
//!
//! [`PolicyStore`] compiles and holds a Cedar policy set + schema at startup.
//! It implements [`PolicyEvaluator`], which is the injectable trait used by
//! [`AuthzSession`][super::session::AuthzSession] — swap it for
//! [`MockPolicyEvaluator`][crate::utils::testing::mock_policy::MockPolicyEvaluator]
//! in tests to evaluate authz flows without any Cedar policy files.

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema};
use std::str::FromStr;
use tracing::warn;

use super::error::AuthzError;

// ── AuthzDecision ─────────────────────────────────────────────────────────────

/// The outcome of a Cedar policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    Deny,
}

// ── PolicyEvaluator ───────────────────────────────────────────────────────────

/// Abstraction over Cedar policy evaluation.
///
/// The production implementation is [`PolicyStore`].
/// Tests use [`MockPolicyEvaluator`][crate::utils::testing::mock_policy::MockPolicyEvaluator]
/// to control decisions without loading policy files.
pub trait PolicyEvaluator: Send + Sync {
    /// Evaluate whether `principal` may perform `action` on `resource`.
    ///
    /// `entities` must contain all entities referenced by the policy (principal,
    /// resource, roles, tenant, etc.). Always returns [`AuthzDecision::Deny`] on
    /// any evaluation error — fail-closed is the only correct default.
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
/// The namespace is intentionally NOT stored here — it lives on
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
    /// Both strings are validated at construction time — any parse or schema
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
        let cedar_req = match Request::new(
            principal,
            action,
            resource,
            context,
            Some(&self.schema),
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!("Cedar request validation failed: {e:?}");
                return AuthzDecision::Deny;
            }
        };

        match self
            .authorizer
            .is_authorized(&cedar_req, &self.policy_set, entities)
            .decision()
        {
            Decision::Allow => AuthzDecision::Allow,
            Decision::Deny => AuthzDecision::Deny,
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
