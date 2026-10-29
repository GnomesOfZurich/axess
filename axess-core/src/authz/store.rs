//! Cedar policy store and the `PolicyEvaluator` trait.
//!
//! [`PolicyStore`] compiles and holds a Cedar policy set + schema at startup.
//! It implements [`PolicyEvaluator`], which is the injectable trait used by
//! [`AuthzSession`][super::session::AuthzSession]: swap it for
//! [`MockPolicyEvaluator`][crate::testing::mock_policy::MockPolicyEvaluator]
//! in tests to evaluate authz flows without any Cedar policy files.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityUid, PolicySet, Request, Schema,
    ValidationMode, Validator,
};
use std::borrow::Cow;
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
///
/// The store owns the schema's action entities (the actions and the action
/// groups they belong to) and adds them to every evaluation, so a policy
/// such as `action in Action::"Mutating"` holds whether or not the entity
/// provider built its entities with the schema.
pub struct PolicyStore {
    policy_set: PolicySet,
    schema: Schema,
    authorizer: Authorizer,
    action_entities: Vec<Entity>,
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

        let action_entities = schema
            .action_entities()
            .map_err(|e| AuthzError::SchemaParse(format!("{e:?}")))?
            .iter()
            .cloned()
            .collect();

        Ok(Self {
            policy_set,
            schema,
            authorizer: Authorizer::new(),
            action_entities,
        })
    }

    /// The provider's entities plus the schema's action entities.
    ///
    /// Cedar adds the action entities (with their `memberOf` groups) only
    /// when entities are built against the schema; a provider that passes no
    /// schema leaves them out, and `action in Action::"Group"` is then false
    /// without any error, which would silently disable a `forbid` written
    /// over an action group. Only the missing actions are added, so entities
    /// that already carry them are used as they are.
    fn with_action_entities<'a>(
        &self,
        entities: &'a Entities,
    ) -> Result<Cow<'a, Entities>, Box<cedar_policy::entities_errors::EntitiesError>> {
        let missing: Vec<Entity> = self
            .action_entities
            .iter()
            .filter(|action| entities.get(&action.uid()).is_none())
            .cloned()
            .collect();
        if missing.is_empty() {
            return Ok(Cow::Borrowed(entities));
        }
        entities
            .clone()
            .add_entities(missing, None)
            .map(Cow::Owned)
            .map_err(Box::new)
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

        let entities = match self.with_action_entities(entities) {
            Ok(entities) => entities,
            Err(e) => {
                tracing::error!("Cedar action entities could not be merged: denied: {e:?}");
                if let Some(subject) = &subject {
                    tracing::info!(
                        target: "axess::authz::decision",
                        principal = %subject.principal,
                        action = %subject.action,
                        resource = %subject.resource,
                        decision = "deny",
                        reason = "action_entities_merge_failed",
                        latency_us = started.elapsed().as_micros() as u64,
                    );
                }
                return AuthzDecision::Deny;
            }
        };

        let response = self
            .authorizer
            .is_authorized(&cedar_req, &self.policy_set, &entities);

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
mod authz_store_tests;
