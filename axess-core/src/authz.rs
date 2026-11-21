//! Cedar Policy authorization for Axum applications.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │  Handler: authz.require("ViewLedger", &id)  │
//! └──────────────────┬──────────────────────────┘
//!                    │ per-request
//! ┌──────────────────▼──────────────────────────┐
//! │  AuthzSession: principal + context + cache  │
//! └────────┬──────────────────┬─────────────────┘
//!          │                  │
//! ┌────────▼────────┐ ┌───────▼───────────────────┐
//! │ PolicyEvaluator │ │ AuthzEntityProvider        │
//! │ (Cedar / Mock)  │ │ (application-supplied)     │
//! └─────────────────┘ └───────────────────────────┘
//! ```
//!
//! The application implements [`AuthzEntityProvider`] to teach Axess how to
//! load the Cedar entity graph for each request. [`AuthzStore`] holds the
//! configured evaluator, provider, and namespace, and is stored in Axum state.
//! [`AuthzSession`] is created per-request from the store.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use axess::authz::{AuthzStore, PolicyStore, StandardRequestContext};
//! use std::sync::Arc;
//!
//! // At startup, load Cedar policies and configure the store:
//! let policy_store = Arc::new(PolicyStore::from_text(
//!     include_str!("../policies/app.cedar"),
//!     include_str!("../policies/app.cedarschema.json"),
//! )?);
//! // try_new catches provider <-> schema mismatches at startup.
//! let authz = Arc::new(AuthzStore::try_new(
//!     policy_store,
//!     Arc::new(MyEntityProvider::new(db)),
//!     "MyApp",
//! )?);
//!
//! // In a handler, RBAC/ReBAC check. For policies that read no `context`:
//! // when they read it, this form answers `AuthzError::ContextRequired`.
//! let authz_session = state.authz.for_user_id(&user_id)?;
//! authz_session.require("ViewLedger", &ledger_id).await?;
//!
//! // With ABAC context (MFA status, IP address):
//! let ctx = StandardRequestContext::new(mfa_complete, ip_address);
//! let authz_session = state.authz.for_user_id_with_context(&user_id, ctx)?;
//! authz_session.require("PostJournalEntry", &ledger_id).await?;
//! ```
//!
//! # Route gates
//!
//! The `require_authz!` macro gates a route before its handler runs. What
//! its gates decide with is one [`AuthzInstallation`], built from the policy
//! store, a [`RequestEntityProvider`] and, when the policies read `context`,
//! a [`RequestContextProvider`], and added as a layer outside the gates:
//!
//! ```rust,ignore
//! let installation = AuthzInstallation::new(
//!     policy_store.clone(),
//!     Arc::new(MyRequestEntities::new(db)),
//!     Some(Arc::new(MyRequestContext::new(clock))),
//! )?;
//! let app = Router::new()
//!     .route("/ledgers/{id}", get(view_ledger).layer(require_authz!(
//!         "MyApp", "ViewLedger", "Ledger:{id}",
//!         validator = authn.session_validator())))
//!     .layer(installation);
//! ```
//!
//! A policy store that reads `context` is refused there without a context
//! provider, so a router that could not decide is never served.
//!
//! # Testing
//!
//! Use [`MockPolicyEvaluator`](crate::testing::mock_policy::MockPolicyEvaluator)
//! and [`MockEntityProvider`](crate::testing::mock_policy::MockEntityProvider)
//! for deterministic tests without Cedar policy files.
//!
//! # Example
//!
//! See `examples/authz/` for a complete working example with RBAC, ReBAC
//! (ownership), and ABAC (MFA requirement) patterns.

pub mod assurance;
pub mod audit;
pub mod cache;
pub mod context;
pub mod error;
pub mod installation;
pub mod provider;
pub mod reload;
pub mod session;
pub mod store;

// The trusted-proxy primitives live in `crate::client_ip`, outside the
// `authz` feature, though the Cedar request context wants an address: the
// rate limiter reaches the one correct walk without compiling Cedar, so
// nothing reads the forwarded headers itself.
pub use assurance::{
    ASSURANCE_ATTRIBUTE, ASSURANCE_SCHEMA_FRAGMENT, AssuranceContext, AssuranceContextProvider,
    AuthzRefusal, FactorEvidence, STEP_UP_ANNOTATION, merge_assurance_schema,
};
pub use context::{BuildRequestContext, NoContext, RequestContextProvider, StandardRequestContext};
pub use error::{AuthzDenied, AuthzError};
pub use installation::AuthzInstallation;
pub use provider::{
    AuthzEntityProvider, RequestEntityProvider, make_action_uid, make_entity_uid,
    validate_sample_entities,
};
pub use session::{AuthzSession, AuthzStore};
pub use store::{AuthzDecision, PolicyEvaluator, PolicyStore, validate_policies};
