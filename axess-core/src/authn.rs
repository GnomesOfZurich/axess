//! Authentication layer — identity lookup, factor verification, session management.
//!
//! # Module layout
//!
//! - [`types`] — [`User`], [`Tenant`], [`EntityState`], [`LockoutPolicy`], [`AuthnScope`]
//! - [`factor`] — [`FactorKind`], [`FactorConfig`], [`FactorCredential`], [`ZeroizedString`]
//! - [`event`] — [`AuthEvent`], [`AuthEventBuilder`], [`AuthEventType`], [`AuthEventStatus`]
//! - [`store`] — [`IdentityStore`], [`FactorStore`], [`AuthnBackend`], [`AuthMethod`]
//! - [`service`] — [`AuthnService`], [`LoginOutcome`], [`FactorOutcome`]
//! - [`error`] — [`AuthnError`]

pub mod error;
pub mod event;
pub mod factor;
pub mod service;
pub mod store;
pub mod types;

pub use error::AuthnError;
pub use event::{AuthEvent, AuthEventBuilder, AuthEventStatus, AuthEventType};
pub use factor::{
    EmailOtpConfig, FactorConfig, FactorCredential, FactorKind, FederatedProvider, Fido2Config,
    HotpConfig, OtpAlgorithm, PasswordConfig, PasswordRules, TotpConfig, ZeroizedString,
};
pub use service::{AuthnService, FactorOutcome, LoginOutcome, PrepareOutcome};
pub use store::{AuthMethod, AuthnBackend, FactorStore, IdentityStore};
pub use types::{AuthnScope, EntityState, LockoutPolicy, StatusDetail, Tenant, User};
