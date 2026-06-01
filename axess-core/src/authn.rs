//! Authentication layer: identity lookup, factor verification, session management.
//!
//! # Module layout
//!
//! - `types`: [`User`], [`Tenant`], [`EntityState`], [`LockoutPolicy`], [`AuthnScope`]
//! - `factor`: [`FactorKind`], [`FactorConfig`], [`FactorCredential`], [`ZeroizedString`]
//! - `event`: [`AuthEvent`], [`AuthEventBuilder`], [`AuthEventType`], [`AuthEventStatus`]
//! - `store`: [`IdentityStore`], [`FactorStore`], [`AuthnBackend`], [`AuthMethod`]
//! - `service`: [`AuthnService`], [`LoginOutcome`], [`SignupOutcome`], [`FactorOutcome`]
//! - `error`: [`AuthnError`]
//!
//! # Naming conventions
//!
//! **`Authn` prefix**: types specific to the authentication layer: `AuthnService`,
//! `AuthnError`, `AuthnScope`, `AuthnBackend`. These are internal to `authn/`.
//!
//! **`Auth` prefix**: types shared across authentication and authorization:
//! `AuthSession` (wraps session state for both layers), `AuthState` (session
//! state machine), `AuthEvent` (audit log entries from any auth operation),
//! `AuthMethod` (factor chain definition).
//!
//! **`Authz` prefix**: types specific to the authorization layer: `AuthzStore`,
//! `AuthzSession`, `AuthzError`, `AuthzDenied`.
//!
//! **Submodule files** use a `_service` suffix when a same-named file exists
//! elsewhere in the crate (e.g. `authn/service/fido2_service.rs` alongside
//! `federation/fido2.rs`) to keep IDE tabs distinguishable.

pub mod audit;
pub mod error;
pub mod event;
pub mod factor;
pub mod ids;
pub mod provisioning;
pub mod service;
pub mod store;
pub mod types;

pub use audit::analytics::{
    AuditLogWithAnalytics, AuthnAnalyticsSink, NoopAuthnAnalyticsSink, RichAuthnEvent,
    UserAgentSummary,
};
pub use audit::archive::{
    AuditArchiver, AuditRetentionLoop, AuditRetentionPolicy, AuditRetentionSource,
    NoopAuditArchiver, RetentionError, RetentionTickReport,
};
#[cfg(feature = "audit-archive-fs")]
pub use audit::archive::{FilesystemArchiveError, FilesystemAuditArchiver};
pub use error::AuthnError;
pub use event::{
    AuditContext, AuthEvent, AuthEventBuilder, AuthEventStatus, AuthEventType,
    extract_audit_context, extract_audit_context_async, ip_from_headers,
};
pub use factor::{
    EmailOtpConfig, FactorConfig, FactorCredential, FactorKind, FactorStep, FactorTemplate,
    FederatedProvider, Fido2Config, HotpConfig, LdapBindFactorConfig, OtpAlgorithm, PasswordConfig,
    PasswordRules, TotpConfig, ZeroizedString, default_catalog,
};
pub use ids::{DeviceId, IdError, TenantId, UserId};
pub use provisioning::{ProvisioningError, TenantBootstrap, create_tenant};
pub use service::{
    AuthnService, FactorOutcome, LoginOutcome, NoSessionRegistryError, PrepareOutcome,
    SessionValidator, SignupOutcome, require_valid_session,
};
pub use store::{
    AuditQuery, AuthMethod, AuthnBackend, EventQueryFilter, FactorStore, IdentityAdmin,
    IdentityAuthnLog, IdentityLookup, IdentityStore, NoopAuthnLog,
};
pub use types::{
    AuthnScope, EntityState, IpPolicy, LockoutPolicy, ScopeColumns, StatusDetail, Tenant, User,
};
