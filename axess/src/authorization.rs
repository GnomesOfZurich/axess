//! Cedar Policy authorization — public API surface.
//!
//! This module re-exports the authorization layer from `axess-core`. Import
//! from here rather than from `axess-core` directly.
//!
//! # Typical usage
//!
//! ```rust,ignore
//! use axess::authorization::{AuthzStore, PolicyStore, AuthzDenied, StandardRequestContext};
//! use std::sync::Arc;
//!
//! // At startup — load once, share via Arc in Axum state.
//! let policy_store = Arc::new(PolicyStore::from_text(
//!     include_str!("../policies/app.cedar"),
//!     include_str!("../policies/app.cedar.json"),
//! )?);
//!
//! let authz = Arc::new(AuthzStore::new(
//!     policy_store,
//!     Arc::new(MyEntityProvider::new(db.clone())),
//!     "MyApp",   // Cedar namespace — must match your .cedar schema
//! ));
//! authz.validate()?; // catch schema/provider mismatches at startup
//!
//! // In a handler:
//! let user_id = session.get_user_id().ok_or(AuthzDenied)?;
//! let authz_session = state.authz.for_user_id(&user_id.to_string())?;
//! authz_session.require("ViewLedger", &ledger_id).await?;
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
