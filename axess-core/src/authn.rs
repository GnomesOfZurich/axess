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
//!
//! # Naming conventions
//!
//! **`Authn` prefix** — types specific to the authentication layer: `AuthnService`,
//! `AuthnError`, `AuthnScope`, `AuthnBackend`. These are internal to `authn/`.
//!
//! **`Auth` prefix** — types shared across authentication and authorization:
//! `AuthSession` (wraps session state for both layers), `AuthState` (session
//! state machine), `AuthEvent` (audit log entries from any auth operation),
//! `AuthMethod` (factor chain definition).
//!
//! **`Authz` prefix** — types specific to the authorization layer: `AuthzStore`,
//! `AuthzSession`, `AuthzError`, `AuthzDenied`.
//!
//! **Submodule files** use a `_factor` or `_service` suffix when a same-named
//! file exists at the parent level (e.g. `factor/fido2_factor.rs` alongside
//! `authn/fido2.rs`) to keep IDE tabs distinguishable.

pub mod error;
pub mod event;
pub mod factor;
#[cfg(feature = "fido2")]
pub mod fido2;
#[cfg(feature = "oauth")]
pub mod oauth;
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
