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
//! │  AuthzSession  — principal + context + cache│
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
//! // At startup:
//! let store = Arc::new(PolicyStore::from_text(
//!     include_str!("policies/app.cedar"),
//!     include_str!("policies/app.cedar.json"),
//! )?);
//!
//! let authz = Arc::new(AuthzStore::new(store, Arc::new(MyProvider::new(db)), "MyApp"));
//! authz.validate()?; // assert provider ↔ schema consistency at startup
//!
//! // In a handler:
//! let authz_session = state.authz.for_user_id(&user_id.to_string())?;
//! authz_session.require("ViewLedger", &ledger_id).await?;
//! ```

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
