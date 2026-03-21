//! Cedar Policy authorization — public API surface.
//!
//! This module re-exports the authorization layer from `axess-core` and provides
//! a convenience [`require()`] function for direct Cedar policy evaluation with
//! manually-built entity sets.
//!
//! # Two usage patterns
//!
//! ## Pattern 1: `AuthzStore` + `AuthzSession` (recommended)
//!
//! Best when entity construction is consistent across actions — implement
//! [`AuthzEntityProvider`] once, then call `require(action, resource_id)`.
//!
//! ```rust,ignore
//! let authz = Arc::new(AuthzStore::new(policy_store, Arc::new(provider), "MyApp"));
//! let session = authz.for_user_id(&user_id)?;
//! session.require("ViewLedger", &ledger_id).await?;
//! ```
//!
//! ## Pattern 2: `require()` with manual entities
//!
//! Best when different actions need different entity graphs (e.g. ledger vs
//! document vs platform checks each build different Cedar entity sets).
//!
//! ```rust,ignore
//! use axess::authorization::{AuthzRequest, PolicyStore, require};
//! use cedar_policy::{Entities, EntityUid};
//!
//! let entities = build_my_entities(db, user_id, resource_id).await?;
//! let req = AuthzRequest {
//!     principal: EntityUid::from_str(r#"MyApp::User::"alice""#)?,
//!     action: EntityUid::from_str(r#"MyApp::Action::"ViewLedger""#)?,
//!     resource: EntityUid::from_str(r#"MyApp::Ledger::"ledger-1""#)?,
//! };
//! require(&policy_store, entities, &req)?; // Ok(()) or Err(AuthzDenied)
//! ```

pub use axess_core::authz::{
    // Core types
    AuthzDecision,
    AuthzDenied,
    // Traits
    AuthzEntityProvider,
    AuthzError,
    // Concrete types
    AuthzSession,
    AuthzStore,
    BuildRequestContext,
    NoContext,
    PolicyEvaluator,
    PolicyStore,
    StandardRequestContext,
    // Helpers
    ip_from_headers,
};

use cedar_policy::{Context, Entities, EntityUid};

/// A Cedar authorization request with pre-built [`EntityUid`] values.
///
/// Used with [`require()`] for direct policy evaluation when the application
/// builds entity sets manually rather than through [`AuthzEntityProvider`].
pub struct AuthzRequest {
    pub principal: EntityUid,
    pub action: EntityUid,
    pub resource: EntityUid,
}

/// Evaluate an authorization request against the policy store.
///
/// Returns `Ok(())` when Cedar permits; `Err(AuthzDenied)` when denied.
///
/// This is a convenience wrapper over [`PolicyEvaluator::is_authorized`] for
/// applications that build Cedar entity sets directly rather than through
/// the [`AuthzStore`]/[`AuthzSession`] pattern.
pub fn require(
    store: &PolicyStore,
    entities: Entities,
    req: &AuthzRequest,
) -> Result<(), AuthzDenied> {
    let decision = store.is_authorized(
        &entities,
        req.principal.clone(),
        req.action.clone(),
        req.resource.clone(),
        Context::empty(),
    );
    match decision {
        AuthzDecision::Allow => Ok(()),
        AuthzDecision::Deny => Err(AuthzDenied),
    }
}
