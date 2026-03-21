#![forbid(unsafe_code)]

// ── Session layer ──────────────────────────────────────────────────────────────

/// Custom tower session layer with HMAC-signed cookies and typed session data.
pub mod session;

pub use session::{
    AuthSession, AuthState, MemorySessionRegistry, MemorySessionStore, SessionData, SessionId,
    SessionLayer, SessionRegistry, SessionStore,
};

// ── Authentication ─────────────────────────────────────────────────────────────

/// Authentication service — identity lookup, factor verification, session management.
pub mod authn;

pub use authn::{
    AuthEvent, AuthEventBuilder, AuthEventStatus, AuthEventType, AuthMethod, AuthnBackend,
    AuthnError, AuthnScope, AuthnService, EmailOtpConfig, EntityState, FactorConfig,
    FactorCredential, FactorKind, FactorOutcome, FactorStore, FederatedProvider, Fido2Config,
    HotpConfig, IdentityStore, LockoutPolicy, LoginOutcome, OtpAlgorithm, PasswordConfig,
    PasswordRules, StatusDetail, Tenant, TotpConfig, User, ZeroizedString,
};

// ── Authorization (unchanged) ──────────────────────────────────────────────────

#[cfg(feature = "authz")]
pub mod authz;

#[cfg(feature = "authz")]
pub use authz::{
    AuthzDecision, AuthzDenied, AuthzEntityProvider, AuthzError, AuthzSession, AuthzStore,
    BuildRequestContext, NoContext, PolicyEvaluator, PolicyStore, StandardRequestContext,
    ip_from_headers,
};

// ── Storage backends ───────────────────────────────────────────────────────────

pub mod storage {
    /// In-memory store (now a redirect notice — see `crate::session::store`).
    pub mod in_memory;

    #[cfg(feature = "sqlite")]
    pub mod sqlite;

    #[cfg(feature = "valkey")]
    pub mod valkey;
}

#[cfg(feature = "sqlite")]
pub use storage::sqlite::SqliteSessionStore;

// ── DST utilities ──────────────────────────────────────────────────────────────

pub mod utils;

pub use utils::random::{SecureRng, SystemRng};
pub use utils::testing::{MockClock, MockFactorStore, MockIdentityStore, MockRng};
pub use utils::time::{Clock, SystemClock};

#[cfg(feature = "authz")]
pub use utils::testing::mock_policy::{MockEntityProvider, MockPolicyEvaluator};

// ── Extras ─────────────────────────────────────────────────────────────────────

pub mod extras {
    #[cfg(feature = "request_id")]
    pub mod request_id;

    #[cfg(feature = "trace_id")]
    pub mod trace_id;
}

#[cfg(feature = "request_id")]
pub use extras::request_id::RequestIdLayer;

#[cfg(feature = "trace_id")]
pub use extras::trace_id::TraceIdLayer;

// ── Re-export axum and tracing for macro hygiene ────────────────────────────────

#[doc(hidden)]
pub use axum;
#[doc(hidden)]
pub use tracing;
