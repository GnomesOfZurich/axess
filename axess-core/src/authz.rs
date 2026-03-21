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
//! │  AuthzSession  — principal + context + cache │
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
//! use axess::authorization::{AuthzStore, PolicyStore, StandardRequestContext};
//! use std::sync::Arc;
//!
//! // At startup — load Cedar policies and configure the store:
//! let policy_store = Arc::new(PolicyStore::from_text(
//!     include_str!("../policies/app.cedar"),
//!     include_str!("../policies/app.cedarschema.json"),
//! )?);
//! let authz = Arc::new(AuthzStore::new(
//!     policy_store,
//!     Arc::new(MyEntityProvider::new(db)),
//!     "MyApp",
//! ));
//! authz.validate()?; // catch provider ↔ schema mismatches at startup
//!
//! // In a handler — RBAC/ReBAC check:
//! let authz_session = state.authz.for_user_id(&user_id)?;
//! authz_session.require("ViewLedger", &ledger_id).await?;
//!
//! // With ABAC context (MFA status, IP address):
//! let ctx = StandardRequestContext::new(session.is_mfa_complete(), ip_address);
//! let authz_session = state.authz.for_user_id_with_context(&user_id, ctx)?;
//! authz_session.require("PostJournalEntry", &ledger_id).await?;
//! ```
//!
//! # Testing
//!
//! Use [`MockPolicyEvaluator`](crate::utils::testing::mock_policy::MockPolicyEvaluator)
//! and [`MockEntityProvider`](crate::utils::testing::mock_policy::MockEntityProvider)
//! for deterministic tests without Cedar policy files.
//!
//! # Example
//!
//! See `examples/authz/` for a complete working example with RBAC, ReBAC
//! (ownership), and ABAC (MFA requirement) patterns.

pub mod context;
pub mod error;
pub mod provider;
pub mod session;
pub mod store;

pub use context::{BuildRequestContext, NoContext, StandardRequestContext, ip_from_headers};
pub use error::{AuthzDenied, AuthzError};
pub use provider::AuthzEntityProvider;
pub use session::{AuthzSession, AuthzStore};
pub use store::{AuthzDecision, PolicyEvaluator, PolicyStore};
