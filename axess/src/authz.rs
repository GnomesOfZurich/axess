//! Cedar Policy authorization: public API surface.
//!
//! This module re-exports the authorization layer from `axess-core` and provides
//! a convenience [`require()`] function for direct Cedar policy evaluation with
//! manually-built entity sets.
//!
//! # Two usage patterns
//!
//! ## Pattern 1: `AuthzStore` + `AuthzSession` (recommended)
//!
//! Best when entity construction is consistent across actions; implement
//! [`AuthzEntityProvider`] once, then call `require(action, resource_id)`.
//!
//! ```rust,ignore
//! let authz = Arc::new(AuthzStore::try_new(policy_store, Arc::new(provider), "MyApp")?);
//! let session = authz.for_user_id(&user_id)?;
//! session.require("ViewLedger", &ledger_id).await?;
//! ```
//!
//! ## Pattern 2: `require()` with manual entities
//!
//! Best when different actions need different entity graphs (e.g. ledger vs
//! document vs platform checks each build different Cedar entity sets).
//!
//! ```no_run
//! // no_run: it needs a compiled policy store and an entity set.
//! use axess::authz::{AuthzRequest, PolicyStore, make_action_uid, make_entity_uid, require};
//! use cedar_policy::{Context, Entities};
//!
//! fn view_ledger(
//!     policy_store: &PolicyStore,
//!     entities: Entities,
//!     user_id: &str,
//!     ledger_id: &str,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     // Build ids with `make_entity_uid`, never by formatting an id into
//!     // Cedar source for `EntityUid::from_str`: a quote or escape in the id
//!     // then rewrites the uid (and two different ids can collide).
//!     let req = AuthzRequest {
//!         principal: make_entity_uid("MyApp", "User", user_id)?,
//!         action: make_action_uid("MyApp", "ViewLedger")?,
//!         resource: make_entity_uid("MyApp", "Ledger", ledger_id)?,
//!     };
//!     // The context is what policies read as `context.*` (MFA status and the like).
//!     require(policy_store, entities, &req, Context::empty()).map_err(|_| "denied")?;
//!     Ok(())
//! }
//! ```

pub use axess_core::authz::{
    // Authentication assurance in the context, and the step-up refusal
    ASSURANCE_ATTRIBUTE,
    ASSURANCE_SCHEMA_FRAGMENT,
    AssuranceContext,
    AssuranceContextProvider,
    // Core types
    AuthzDecision,
    AuthzDenied,
    // Traits
    AuthzEntityProvider,
    AuthzError,
    AuthzRefusal,
    // Concrete types
    AuthzSession,
    AuthzStore,
    BuildRequestContext,
    FactorEvidence,
    NoContext,
    PolicyEvaluator,
    PolicyStore,
    RequestContextProvider,
    RequestEntityProvider,
    STEP_UP_ANNOTATION,
    StandardRequestContext,
    make_action_uid,
    make_entity_uid,
    merge_assurance_schema,
    // Live policy reload: `Reloaded`, `PolicySource`, `ReloadCoordinator`, ...
    reload,
};

// The trusted-proxy primitives left this module in 0.7.0. They sat behind
// the `authz` feature, which meant the only correct way to work out a
// caller's address required compiling Cedar, and the rate limiter read the
// headers itself rather than pay that. They are `axess::client_ip` now,
// ungated, with the layer that runs the walk once per request.
pub use crate::client_ip;

use cedar_policy::{Context, Entities, EntityUid};

/// A Cedar authorization request with pre-built [`EntityUid`] values.
///
/// Used with [`require()`] for direct policy evaluation when the application
/// builds entity sets manually rather than through [`AuthzEntityProvider`].
pub struct AuthzRequest {
    /// The Cedar principal: the actor whose access is being checked.
    pub principal: EntityUid,
    /// The Cedar action: the operation being attempted.
    pub action: EntityUid,
    /// The Cedar resource: the target of the action.
    pub resource: EntityUid,
}

/// Evaluate an authorization request against the policy store, with the
/// Cedar `context` of the request.
///
/// Returns `Ok(())` when Cedar permits; `Err(AuthzDenied)` when denied.
///
/// This is a convenience wrapper over [`PolicyEvaluator::is_authorized`] for
/// applications that build Cedar entity sets directly rather than through
/// the [`AuthzStore`]/[`AuthzSession`] pattern.
///
/// `context` carries what policies read as `context.*`, such as whether the
/// session passed MFA. Pass `Context::empty()` only when no policy reads it:
/// a policy that guards with `context has mfa_verified` and permits when the
/// attribute is absent allows every request made with an empty context, and a
/// policy that requires `context.mfa_verified` denies every one.
pub fn require(
    store: &PolicyStore,
    entities: Entities,
    req: &AuthzRequest,
    context: Context,
) -> Result<(), AuthzDenied> {
    let decision = store.is_authorized(
        &entities,
        req.principal.clone(),
        req.action.clone(),
        req.resource.clone(),
        context,
    );
    match decision {
        AuthzDecision::Allow => Ok(()),
        AuthzDecision::Deny => Err(AuthzDenied),
    }
}
