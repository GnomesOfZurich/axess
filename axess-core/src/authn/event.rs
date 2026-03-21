//! Authentication audit events.
//!
//! [`AuthEvent`] is emitted by the authentication service whenever a significant
//! action occurs. [`AuthEventBuilder`] provides ergonomic construction.

use crate::{authn::factor::FactorKind, session::id::SessionId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr, sync::Arc};

// ── AuthEventType ─────────────────────────────────────────────────────────────

/// Enumerates all possible authentication-related events tracked by Axess.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuthEventType {
    /// Successful completion of all required authentication steps.
    Authenticated,
    /// Attempt to log in (may succeed or fail).
    LoginAttempt,
    /// Attempt to log out.
    LogoutAttempt,
    /// Successful verification of an authentication factor (e.g., password, TOTP).
    FactorVerified,
    /// Setup of a new authentication factor.
    FactorSetup,
    /// Enabling an authentication factor.
    FactorEnabled,
    /// Disabling an authentication factor.
    FactorDisabled,
    /// Enabling an authentication method.
    MethodEnabled,
    /// Disabling an authentication method.
    MethodDisabled,
    /// Password reset event.
    PasswordReset,
    /// Session expired due to inactivity or policy.
    SessionExpired,
    /// Session was explicitly invalidated (e.g., admin logout).
    SessionInvalidated,
}

impl AuthEventType {
    /// Stable string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthEventType::Authenticated => "authenticated",
            AuthEventType::LoginAttempt => "login_attempt",
            AuthEventType::LogoutAttempt => "logout_attempt",
            AuthEventType::FactorVerified => "factor_verified",
            AuthEventType::FactorSetup => "factor_setup",
            AuthEventType::FactorEnabled => "factor_enabled",
            AuthEventType::FactorDisabled => "factor_disabled",
            AuthEventType::MethodEnabled => "method_enabled",
            AuthEventType::MethodDisabled => "method_disabled",
            AuthEventType::PasswordReset => "password_reset",
            AuthEventType::SessionExpired => "session_expired",
            AuthEventType::SessionInvalidated => "session_invalidated",
        }
    }
}

impl FromStr for AuthEventType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authenticated" => Ok(AuthEventType::Authenticated),
            "login_attempt" => Ok(AuthEventType::LoginAttempt),
            "logout_attempt" => Ok(AuthEventType::LogoutAttempt),
            "factor_verified" => Ok(AuthEventType::FactorVerified),
            "factor_setup" => Ok(AuthEventType::FactorSetup),
            "factor_enabled" => Ok(AuthEventType::FactorEnabled),
            "factor_disabled" => Ok(AuthEventType::FactorDisabled),
            "method_enabled" => Ok(AuthEventType::MethodEnabled),
            "method_disabled" => Ok(AuthEventType::MethodDisabled),
            "password_reset" => Ok(AuthEventType::PasswordReset),
            "session_expired" => Ok(AuthEventType::SessionExpired),
            "session_invalidated" => Ok(AuthEventType::SessionInvalidated),
            other => Err(format!("Unknown auth event type: {}", other)),
        }
    }
}

impl fmt::Display for AuthEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── AuthEventStatus ───────────────────────────────────────────────────────────

/// Enumerates the possible outcomes for authentication events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuthEventStatus {
    /// The event completed successfully.
    Success,
    /// The event failed (e.g., incorrect credentials).
    Failure,
    /// Blocked due to lockout.
    Locked,
    /// Failed due to expiry.
    Expired,
    /// Flagged as suspicious (e.g., anomaly detected).
    Suspicious,
}

impl AuthEventStatus {
    /// Stable string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthEventStatus::Success => "success",
            AuthEventStatus::Failure => "failure",
            AuthEventStatus::Locked => "locked",
            AuthEventStatus::Expired => "expired",
            AuthEventStatus::Suspicious => "suspicious",
        }
    }
}

impl FromStr for AuthEventStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(AuthEventStatus::Success),
            "failure" => Ok(AuthEventStatus::Failure),
            "locked" => Ok(AuthEventStatus::Locked),
            "expired" => Ok(AuthEventStatus::Expired),
            "suspicious" => Ok(AuthEventStatus::Suspicious),
            other => Err(format!("Unknown auth event status: {}", other)),
        }
    }
}

impl fmt::Display for AuthEventStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── AuthEvent ─────────────────────────────────────────────────────────────────

/// A single authentication-related event for audit and analytics.
///
/// Emitted by the backend whenever a significant authentication action occurs.
/// Persisted via [`IdentityStore::record_event`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    /// User associated with the event.
    pub user_id: Arc<str>,
    /// Tenant associated with the event.
    pub tenant_id: Arc<str>,
    /// Optional session ID for session-related events.
    pub session_id: Option<SessionId>,
    /// What happened.
    pub event_type: AuthEventType,
    /// Outcome of the event.
    pub event_status: AuthEventStatus,
    /// Timestamp when the event occurred.
    pub event_time: DateTime<Utc>,
    /// Optional kind of factor involved.
    pub factor_kind: Option<FactorKind>,
    /// Optional client IP address.
    pub ip_address: Option<Arc<str>>,
    /// Optional user agent string.
    pub user_agent: Option<Arc<str>>,
    /// Optional error detail for failed events.
    pub error: Option<Arc<str>>,
}

// ── AuthEventBuilder ──────────────────────────────────────────────────────────

/// Builder for constructing [`AuthEvent`] records ergonomically.
pub struct AuthEventBuilder {
    user_id: Arc<str>,
    tenant_id: Arc<str>,
    event_type: AuthEventType,
    event_status: AuthEventStatus,
    session_id: Option<SessionId>,
    factor_kind: Option<FactorKind>,
    ip_address: Option<Arc<str>>,
    user_agent: Option<Arc<str>>,
    error: Option<Arc<str>>,
}

impl AuthEventBuilder {
    /// Create a new builder with the required fields.
    pub fn new(
        user_id: Arc<str>,
        tenant_id: Arc<str>,
        event_type: AuthEventType,
        event_status: AuthEventStatus,
    ) -> Self {
        Self {
            user_id,
            tenant_id,
            event_type,
            event_status,
            session_id: None,
            factor_kind: None,
            ip_address: None,
            user_agent: None,
            error: None,
        }
    }

    /// Attach a session ID.
    pub fn with_session(mut self, id: SessionId) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Attach the factor kind involved.
    pub fn with_factor(mut self, kind: FactorKind) -> Self {
        self.factor_kind = Some(kind);
        self
    }

    /// Attach the client IP address.
    pub fn with_ip(mut self, ip: impl Into<Arc<str>>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Attach the user agent string.
    pub fn with_user_agent(mut self, ua: impl Into<Arc<str>>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Attach an error description for failed events.
    pub fn with_error(mut self, err: impl Into<Arc<str>>) -> Self {
        self.error = Some(err.into());
        self
    }

    /// Consume the builder and produce an [`AuthEvent`] timestamped now.
    pub fn build(self) -> AuthEvent {
        AuthEvent {
            user_id: self.user_id,
            tenant_id: self.tenant_id,
            session_id: self.session_id,
            event_type: self.event_type,
            event_status: self.event_status,
            event_time: Utc::now(),
            factor_kind: self.factor_kind,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            error: self.error,
        }
    }

    /// Consume the builder and produce an [`AuthEvent`] with a specific timestamp.
    ///
    /// Use this with an injectable [`Clock`] for DST.
    pub fn build_at(self, event_time: DateTime<Utc>) -> AuthEvent {
        AuthEvent {
            user_id: self.user_id,
            tenant_id: self.tenant_id,
            session_id: self.session_id,
            event_type: self.event_type,
            event_status: self.event_status,
            event_time,
            factor_kind: self.factor_kind,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            error: self.error,
        }
    }
}
