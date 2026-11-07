//! Which step-up would turn a denied request into an allow: the policies'
//! `@step_up` annotations, parsed when the set is built, and the silent
//! re-evaluation a gate runs after a deny.

use cedar_policy::{Context, Decision, Entities, EntityUid, PolicySet, Request};
use std::collections::BTreeSet;

use super::PolicyStore;
use crate::authn::assurance::StepUp;
use crate::authz::assurance::{AssuranceContext, STEP_UP_ANNOTATION, replace_assurance};
use crate::authz::error::AuthzError;

/// The step-ups the policies' `@step_up` annotations name, weakest first and
/// without repeats.
///
/// # Errors
///
/// [`AuthzError::PolicyValidation`] naming the policy and the value when an
/// annotation names no step-up, so a misspelt name refuses the set at build
/// and at reload instead of never prompting.
pub(super) fn annotated_step_ups(policies: &PolicySet) -> Result<Vec<StepUp>, AuthzError> {
    let mut step_ups = BTreeSet::new();
    for policy in policies.policies() {
        let Some(value) = policy.annotation(STEP_UP_ANNOTATION) else {
            continue;
        };
        let step_up = value.parse::<StepUp>().map_err(|e| {
            AuthzError::PolicyValidation(format!(
                "policy {}: @{STEP_UP_ANNOTATION}: {e}",
                policy.id()
            ))
        })?;
        step_ups.insert(step_up);
    }
    Ok(step_ups.into_iter().collect())
}

/// A request the policies denied, as the gate asked it.
pub(super) struct DeniedRequest<'a> {
    pub(super) entities: &'a Entities,
    pub(super) principal: EntityUid,
    pub(super) action: EntityUid,
    pub(super) resource: EntityUid,
    pub(super) context: Context,
}

impl PolicyStore {
    /// The weakest annotated step-up under which `request` is permitted,
    /// with the context's `assurance` replaced by its own plus that
    /// step-up's best proof, aged zero, and nothing else changed. `None`
    /// when the set names no step-up, the context carries no `assurance`
    /// record, or no step-up would permit.
    pub(super) fn step_up_for_denied(&self, request: DeniedRequest<'_>) -> Option<StepUp> {
        if self.step_ups.is_empty() {
            return None;
        }
        let held = AssuranceContext::from_context(&request.context)?;
        // The proofs are aged against a fixed instant: only their age
        // reaches the policy, and the best proof's is zero.
        let now = chrono::DateTime::<chrono::Utc>::UNIX_EPOCH;
        self.step_ups.iter().find_map(|step_up| {
            let assurance = held.clone().with_proof(&step_up.best_proof(now), now);
            let context = replace_assurance(request.context.clone(), &assurance).ok()?;
            self.permits(&request, context).then(|| step_up.clone())
        })
    }

    /// Whether the set permits `request` under `context`, failing closed as
    /// a decision does, and emitting no decision event.
    fn permits(&self, request: &DeniedRequest<'_>, context: Context) -> bool {
        let Ok(cedar_request) = Request::new(
            request.principal.clone(),
            request.action.clone(),
            request.resource.clone(),
            context,
            Some(&self.schema),
        ) else {
            return false;
        };
        let Ok(entities) = self.with_action_entities(request.entities) else {
            return false;
        };
        let response = self
            .authorizer
            .is_authorized(&cedar_request, &self.policy_set, &entities);
        response.diagnostics().errors().next().is_none() && response.decision() == Decision::Allow
    }
}
