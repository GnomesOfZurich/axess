//! `axess` — re-exports from `axess-core` for convenient access.
//!
//! The core logic lives in `axess-core`. This crate is the public-facing facade.

// Session layer
pub use axess_core::{
    AuthSession, AuthState, MemorySessionRegistry, MemorySessionStore, SessionBinding, SessionData,
    SessionId, SessionLayer, SessionRegistry, SessionStore, UserAgentBinding,
};

// Authentication
pub use axess_core::{
    AuthEvent, AuthEventBuilder, AuthEventStatus, AuthEventType, AuthMethod, AuthnBackend,
    AuthnError, AuthnScope, AuthnService, EmailOtpConfig, EntityState, FactorConfig,
    FactorCredential, FactorKind, FactorOutcome, FactorStore, FederatedProvider, Fido2Config,
    HotpConfig, IdentityStore, LockoutPolicy, LoginOutcome, OtpAlgorithm, PasswordConfig,
    PasswordRules, PrepareOutcome, StatusDetail, Tenant, TotpConfig, User, ZeroizedString,
};

// Authorization — re-exports from axess-core with module-level docs.
#[cfg(feature = "authz")]
pub mod authorization;

// Request ID middleware
#[cfg(feature = "request_id")]
pub mod request_id {
    pub use axess_core::extras::request_id::*;
}

// Trace ID middleware
#[cfg(feature = "trace_id")]
pub mod trace_id {
    pub use axess_core::extras::trace_id::*;
}

// SQLite session store
#[cfg(feature = "sqlite")]
pub use axess_core::SqliteSessionStore;

// Valkey session store + registry
#[cfg(feature = "valkey")]
pub use axess_core::{ValkeySessionRegistry, ValkeySessionStore, ValkeyStoreError};

// DST utilities
pub use axess_core::{
    Clock, MockClock, MockFactorStore, MockIdentityStore, MockRng, SecureRng, SystemClock,
    SystemRng,
};

// OAuth/OIDC
#[cfg(feature = "oauth")]
pub use axess_core::{OAuthClaims, OAuthError, OAuthLoginOptions, OAuthProviderConfig};

// Factor verification functions from axess-factors
pub use axess_factors::{
    HOTP_LENGTH, TOTP_LENGTH, TOTP_PERIOD, build_totp_uri, generate_password_hash,
    generate_totp_secret, verify_hotp, verify_password, verify_totp,
};

// Macros from axess-macros
pub use axess_macros::{login_required, require_partial_authn};
