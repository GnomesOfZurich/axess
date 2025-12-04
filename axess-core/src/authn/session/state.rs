//! Authentication session state models and audit event definitions.
//!
//! This module tracks in-flight authentication state (`PartialAuthState` / `AuthState`),
//! stores per-session data payloads, and defines the audit event types emitted by Axess.

use crate::authn::{
    backend::{AuthnBackend, EntityState, FactorId, MethodId, TenantId, UserId},
    methods::{
        MethodInstance,
        factor::{AuthFactorKind, FactorInstance},
    },
    workflows::{WorkflowState, WorkflowStep},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;

/// Tracks the in-flight state of a multi-factor authentication session.
///
/// Used when a user is progressing through a multi-factor authentication flow.
/// Records the current method, remaining factors, attempt count, and last attempt timestamp.
/// Enables replay-safe, stepwise authentication and supports lockout and audit features.
///
/// See [`AuthState::PartialAuthn`] for usage in session flows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "M: Serialize, F: Serialize, U: Serialize",
    deserialize = "M: DeserializeOwned, F: DeserializeOwned, U: DeserializeOwned"
))]
pub struct PartialAuthState<M, F, U>
where
    M: MethodId + serde::de::DeserializeOwned + serde::Serialize,
    F: FactorId + serde::de::DeserializeOwned + serde::Serialize,
    U: UserId + serde::de::DeserializeOwned + serde::Serialize,
{
    pub current_method: MethodInstance<M, F, U>,
    pub remaining_factors: Vec<F>,
    pub attempt_count: u32,
    pub last_attempt: Option<DateTime<Utc>>,
}

impl<M, F, U> PartialAuthState<M, F, U>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
{
    pub fn new(method: MethodInstance<M, F, U>) -> Self {
        Self {
            current_method: method,
            remaining_factors: Vec::new(),
            attempt_count: 0,
            last_attempt: None,
        }
    }

    /// Marks the given factor as applied by removing it from remaining_factors.
    pub fn apply_factor(&mut self, factor_id: &F) -> Self {
        self.remaining_factors.retain(|f| f != factor_id);
        self.clone()
    }

    /// Returns the kind of the next required factor, if any.
    pub fn next_factor_kind(&self) -> Option<AuthFactorKind> {
        self.next_factor().map(|factor| factor.kind.clone())
    }

    /// Returns the id of the next required factor, if any.
    pub fn next_factor_id(&self) -> Option<&F> {
        self.remaining_factors.first()
    }

    /// Returns the next expected factor, if some is required.
    pub fn next_factor(&self) -> Option<&FactorInstance<F, U>> {
        self.next_factor_id().and_then(|factor_id| {
            self.current_method
                .factors
                .iter()
                .find(|factor_instance| &factor_instance.id == factor_id)
        })
    }

    /// Returns whether there are any remaining factors expecting validation or not.
    pub fn is_complete(&self) -> bool {
        self.remaining_factors.is_empty()
    }

    pub fn increment_attempt(&mut self) -> Self {
        self.attempt_count += 1;
        self.last_attempt = Some(Utc::now());
        self.clone()
    }
}

/// Represents the overall authentication state of a session in Axess.
///
/// Tracks progress and status of a user's authentication session, including multi-factor flows,
/// completed authentication, and any pending post-authentication workflows (e.g., KYC, identity verification).
///
/// - `NotAuthenticated`: No authentication started.
/// - `PendingActivation`: Awaiting activation via a workflow (e.g., email verification at user signup).
/// - `PartialAuthn`: In-progress, factors remain.
/// - `Authenticated`: All required factors complete.
/// - `PendingWorkflow`: Authenticated, but blocked by a post-auth workflow.
///
/// Used as part of the session payload to drive authentication and access control logic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(bound(
    serialize = "M: Serialize, F: Serialize, U: Serialize",
    deserialize = "M: DeserializeOwned, F: DeserializeOwned, U: DeserializeOwned",
))]
pub enum AuthState<M, F, U>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
{
    #[default]
    NotAuthenticated,
    PendingActivation(WorkflowState),
    PartialAuthn(PartialAuthState<M, F, U>),
    Authenticated,
    PendingWorkflow(WorkflowState),
}

impl<M, F, U> AuthState<M, F, U>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
{
    /// Creates a new partial authentication state for the given method.
    ///
    /// Initializes the remaining factors from the method's factor list.
    pub fn new_partial(method: MethodInstance<M, F, U>) -> Self {
        let mut partial = PartialAuthState::new(method);
        partial.remaining_factors = partial
            .current_method
            .factors
            .iter()
            .map(|factor| factor.id.clone())
            .collect();
        AuthState::PartialAuthn(partial)
    }

    /// Sets the attempt count for a partial authentication state.
    ///
    /// Returns the updated state, or self if not in partial authentication.
    pub fn with_attempt(self, attempt: u32) -> Self {
        match self {
            AuthState::PartialAuthn(mut partial) => {
                partial.attempt_count = attempt;
                AuthState::PartialAuthn(partial)
            }
            _ => self,
        }
    }

    /// Creates a new pending workflow state with the given workflow payload and blocking status.
    pub fn new_workflow(steps: Vec<WorkflowStep>, blocking: bool) -> Self {
        AuthState::PendingWorkflow(WorkflowState {
            steps,
            current_step: 0,
            started_at: Utc::now(),
            last_updated: Utc::now(),
            blocking,
        })
    }
}

/// Stores all per-session authentication and user state for an active session.
///
/// `Data` is the central payload for session management in Axess. It tracks the current tenant and user,
/// the user's entity state (e.g., Guest, Active, Suspended), the authentication state (including multi-factor progress),
/// a hash of the authentication state for replay protection, and any custom session data needed by the application.
///
/// This struct is designed to be serializable and extensible, supporting DST (Deterministic Simulation Testing)
/// and audit logging. It is used by session extractors, middleware, and backend storage.
///
/// # Fields
/// - `tenant_id`: Optional tenant ID if the session is scoped to a tenant.
/// - `user_id`: Optional user ID if the session is authenticated.
/// - `user_state`: Current state of the user entity (see [`EntityState`](../backend.rs)).
/// - `auth_state`: Current authentication state (see [`AuthState`]).
/// - `auth_hash`: Optional hash of the authentication state for replay protection and audit.
/// - `custom_data`: Arbitrary custom session data as a map of string keys to JSON values.
///
/// # Usage
/// - Used as the session payload in Axess extractors and middleware.
/// - Supports multi-tenant and multi-factor authentication flows.
/// - Extensible for application-specific session data.
///
/// # Example
/// ```rust ignore
/// use axess_core::authn::session::state::{Data, AuthState};
/// use axess_core::authn::backend::{EntityState, Workflow};
/// use std::collections::HashMap;
///
/// // Define a dummy workflow type implementing the Workflow trait.
/// #[derive(Clone, PartialEq, Eq, Debug, Default)]
/// struct DummyWorkflow;
/// impl Workflow for DummyWorkflow {}
///
/// let session_data = Data::<String, String, String, String, DummyWorkflow>::default();
/// assert_eq!(session_data.user_state, EntityState::Guest);
/// assert!(matches!(session_data.auth_state, AuthState::NotAuthenticated));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound(
    serialize = "M: Serialize, F: Serialize, U: Serialize, T: Serialize",
    deserialize = "M: DeserializeOwned, F: DeserializeOwned, U: DeserializeOwned, T: DeserializeOwned"
))]
pub struct Data<M, F, T, U>
where
    M: MethodId,
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    /// Tenant ID if applicable.
    pub tenant_id: Option<T>,
    /// User ID if authenticated.
    pub user_id: Option<U>,
    /// Current user state (see [`EntityState`](../backend.rs)).
    pub user_state: EntityState,
    /// Current authentication state (see [`AuthState`]).
    pub auth_state: AuthState<M, F, U>,
    /// Hash of the authentication state for replay protection and audit.
    pub auth_hash: Option<String>,
    /// Additional custom session data.
    pub custom_data: HashMap<String, JsonValue>,
}

impl<M, F, T, U> Data<M, F, T, U>
where
    M: MethodId,
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    /// Constructs a new `Data` instance with all fields specified.
    pub fn new(
        tenant_id: Option<T>,
        user_id: Option<U>,
        user_state: EntityState,
        auth_state: AuthState<M, F, U>,
        auth_hash: Option<String>,
        custom_data: HashMap<String, JsonValue>,
    ) -> Self {
        Self {
            tenant_id,
            user_id,
            user_state,
            auth_state,
            auth_hash,
            custom_data,
        }
    }

    pub fn get_tenant_id(&self) -> Option<&T> {
        self.tenant_id.as_ref()
    }

    pub fn get_user_id(&self) -> Option<&U> {
        self.user_id.as_ref()
    }

    pub fn get_user_state(&self) -> &EntityState {
        &self.user_state
    }

    pub fn get_auth_state(&self) -> &AuthState<M, F, U> {
        &self.auth_state
    }
    pub fn get_auth_hash(&self) -> Option<&String> {
        self.auth_hash.as_ref()
    }

    pub fn get_custom_data(&self) -> &HashMap<String, JsonValue> {
        &self.custom_data
    }
}

impl<M, F, T, U> Default for Data<M, F, T, U>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
    T: TenantId,
{
    fn default() -> Self {
        Self {
            tenant_id: None,
            user_id: None,
            user_state: EntityState::Guest,
            auth_state: AuthState::<M, F, U>::NotAuthenticated,
            auth_hash: None,
            custom_data: HashMap::new(),
        }
    }
}

/// Enumerates all possible authentication-related events tracked by Axess.
///
/// `AuthEventType` is used for audit logging, session state transitions, and backend queries.
/// Each variant represents a distinct event in the authentication lifecycle, such as login attempts,
/// factor verification, password resets, and session expiry.
///
/// # Variants
/// - `Authenticated`: Successful completion of all required authentication steps.
/// - `LoginAttempt`: Attempt to log in (may succeed or fail).
/// - `LogoutAttempt`: Attempt to log out.
/// - `FactorVerified`: Successful verification of an authentication factor (e.g., password, TOTP).
/// - `FactorSetup`: Setup of a new authentication factor.
/// - `FactorEnabled`: Enabling an authentication factor.
/// - `FactorDisabled`: Disabling an authentication factor.
/// - `MethodEnabled`: Enabling an authentication method.
/// - `MethodDisabled`: Disabling an authentication method.
/// - `PasswordReset`: Password reset event.
/// - `SessionExpired`: Session expired due to inactivity or policy.
/// - `SessionInvalidated`: Session was explicitly invalidated (e.g., admin logout).
///
/// # Usage
/// Use `AuthEventType` for filtering and querying authentication events in the backend,
/// for audit trails, and for driving session state transitions in authentication flows.
///
/// # Example
/// ```rust
/// use axess_core::authn::session::state::AuthEventType;
///
/// let event = AuthEventType::LoginAttempt;
/// assert_eq!(event.as_str(), "login_attempt");
/// ```
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
    /// Stable string representation for database storage
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

impl Display for AuthEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Enumerates the possible outcomes or statuses for authentication events.
///
/// `AuthEventStatus` is used to classify the result of an authentication-related event,
/// such as login attempts, factor verifications, or session changes. This enables
/// audit logging, policy enforcement, and analytics on authentication flows.
///
/// # Variants
/// - `Success`: The event completed successfully (e.g., login succeeded, factor verified).
/// - `Failure`: The event failed (e.g., incorrect credentials, verification failed).
/// - `Locked`: The event was blocked due to lockout (e.g., too many failed attempts).
/// - `Expired`: The event failed due to expiry (e.g., session expired).
/// - `Suspicious`: The event was flagged as suspicious (e.g., anomaly detected).
///
/// # Usage
/// Use `AuthEventStatus` in [`AuthEvent`] and [`AuthEventRecord`] to record the outcome of authentication actions.
/// Filter or query events by status for audit, reporting, or security analysis.
///
/// # Example
/// ```rust
/// use axess_core::authn::session::state::AuthEventStatus;
///
/// let status = AuthEventStatus::Success;
/// assert_eq!(status.as_str(), "success");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuthEventStatus {
    /// The event completed successfully (e.g., login succeeded, factor verified).
    Success,
    /// The event failed (e.g., incorrect credentials, verification failed).
    Failure,
    /// The event was blocked due to lockout (e.g., too many failed attempts).
    Locked,
    /// The event failed due to expiry (e.g., session expired).
    Expired,
    /// The event was flagged as suspicious (e.g., anomaly detected).
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

    /// Parses a string into an `AuthEventStatus`.
    ///
    /// Accepts `"success"`, `"failure"`, `"locked"`, `"expired"`, or `"suspicious"` (case-sensitive).
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

impl Display for AuthEventStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Represents a single authentication-related event for audit and analytics.
///
/// `AuthEvent` is emitted by the backend whenever a significant authentication action occurs,
/// such as login attempts, factor verification, password resets, or session changes.
/// Each event records core identifiers, event type and status, timestamps, and relevant context
/// (method/factor IDs, IP address, user agent, error details).
///
/// This struct is central to audit logging, security analytics, and compliance reporting in Axess.
/// Events are queryable by user, tenant, session, event type, and status.
///
/// # Fields
/// - `id`: Unique event identifier (backend-specific, e.g., UUID or database key).
/// - `user_id`: User associated with the event.
/// - `tenant_id`: Tenant associated with the event.
/// - `session_id`: Optional session ID for session-related events.
/// - `event_type`: What happened (see [`AuthEventType`]).
/// - `event_status`: Outcome of the event (see [`AuthEventStatus`]).
/// - `event_time`: Timestamp when the event occurred.
/// - `method_id`: Optional authentication method involved.
/// - `factor_id`: Optional authentication factor involved.
/// - `factor_kind`: Optional kind of factor (password, OTP, etc.).
/// - `ip_address`: Optional IP address for the request.
/// - `user_agent`: Optional user agent string for the request.
/// - `error_message`: Optional error details for failed events.
///
/// # Usage
/// - Used by [`AuthnBackend::record_auth_event`] to persist audit events.
/// - Queried via [`AuthnBackend::get_auth_history`] for user login history, security analytics, and compliance.
/// - Supports filtering by event type, status, user, tenant, and session.
///
/// # Example
/// ```rust,ignore
/// use axess_core::authn::session::state::{AuthEvent, AuthEventType, AuthEventStatus};
/// use axess_core::authn::methods::factor::AuthFactorKind;
/// use chrono::Utc;
///
/// use crate::models::MyBackend
///
/// let user_id = "user42".to_string();
/// let tenant_id = "tenantA".to_string();
///
/// let event = AuthEvent::<MyBackend> {
///     id: "event123".into(),
///     user_id,
///     tenant_id,
///     session_id: Some("sess456".into()),
///     event_type: AuthEventType::LoginAttempt,
///     event_status: AuthEventStatus::Success,
///     event_time: Utc::now(),
///     method_id: Some("method1".into()),
///     factor_id: Some("factor1".into()),
///     factor_kind: Some(AuthFactorKind::Password),
///     ip_address: Some("192.168.1.1".into()),
///     user_agent: Some("Mozilla/5.0".into()),
///     error_message: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound(
    serialize = "B::DataId: Serialize, B::UserId: Serialize, B::TenantId: Serialize, B::MethodId: Serialize, B::FactorId: Serialize",
    deserialize = "B::DataId: DeserializeOwned, B::UserId: DeserializeOwned, B::TenantId: DeserializeOwned, B::MethodId: DeserializeOwned, B::FactorId: DeserializeOwned"
))]
pub struct AuthEvent<B>
where
    B: AuthnBackend,
{
    /// Unique event identifier (backend-specific, e.g., UUID or database key).
    pub id: B::DataId,
    /// User associated with the event.
    pub user_id: B::UserId,
    /// Tenant associated with the event.
    pub tenant_id: B::TenantId,
    /// Optional session ID for session-related events.
    pub session_id: Option<String>,
    /// What happened (see [`AuthEventType`]).
    pub event_type: AuthEventType,
    /// Outcome of the event (see [`AuthEventStatus`]).
    pub event_status: AuthEventStatus,
    /// Timestamp when the event occurred.
    pub event_time: DateTime<Utc>,
    /// Optional authentication method involved.
    pub method_id: Option<B::MethodId>,
    /// Optional authentication factor involved.
    pub factor_id: Option<B::FactorId>,
    /// Optional kind of factor (password, OTP, etc.).
    pub factor_kind: Option<AuthFactorKind>,
    /// Optional IP address for the request.
    pub ip_address: Option<String>,
    /// Optional user agent string for the request.
    pub user_agent: Option<String>,
    /// Optional error details for failed events.
    pub error_message: Option<String>,
}

/// Builder for constructing authentication event records for audit logging and analytics.
///
/// `AuthEventBuilder` provides an ergonomic way to assemble all relevant fields for an authentication event,
/// such as login attempts, factor verification, password resets, and session changes. It avoids passing
/// many individual parameters to [`AuthnBackend::record_auth_event`] by grouping related event data.
///
/// Use the builder methods to set optional fields (session ID, method/factor IDs, kind, IP, user agent, error message)
/// and then pass the builder to the backend for persistence.
///
/// # Fields
/// - `user_id`: Reference to the user associated with the event.
/// - `tenant_id`: Reference to the tenant associated with the event.
/// - `session_id`: Optional session ID for session-related events.
/// - `event_type`: What happened (see [`AuthEventType`]).
/// - `event_status`: Outcome of the event (see [`AuthEventStatus`]).
/// - `method_id`: Optional authentication method involved.
/// - `factor_id`: Optional authentication factor involved.
/// - `factor_kind`: Optional kind of factor (password, OTP, etc.).
/// - `ip_address`: Optional IP address for the request.
/// - `user_agent`: Optional user agent string for the request.
/// - `error_message`: Optional error details for failed events.
///
/// # Usage
/// - Use in [`AuthnBackend::record_auth_event`] to persist audit events.
/// - Construct with [`AuthEventBuilder::new`] and set optional fields with builder methods.
/// - Supports all event types and statuses for flexible audit logging.
///
/// # Example
/// ```rust
/// use axess_core::authn::session::state::{AuthEventBuilder, AuthEventType, AuthEventStatus};
/// use serde::{Serialize, Deserialize};
/// use std::fmt;
/// use std::hash::Hash;
///
/// #[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
/// struct DummyMethodId(String);
/// impl fmt::Display for DummyMethodId {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         write!(f, "{}", self.0)
///     }
/// }
///
/// #[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
/// struct DummyFactorId(String);
/// impl fmt::Display for DummyFactorId {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         write!(f, "{}", self.0)
///     }
/// }
///
/// type TenantId = String;
/// type UserId = String;
///
/// let user_id = "user42".to_string();
/// let tenant_id = "tenantA".to_string();
///
/// let builder: AuthEventBuilder<'_, DummyMethodId, DummyFactorId, TenantId, UserId> = AuthEventBuilder::new(
///     &user_id,
///     &tenant_id,
///     AuthEventType::LoginAttempt,
///     AuthEventStatus::Success,
/// )
/// .with_session_id("sess123")
/// .with_ip_address("192.168.1.1")
/// .with_user_agent("Mozilla/5.0")
/// .with_error_message("none");
/// ```
#[derive(Debug, Clone)]
pub struct AuthEventBuilder<'a, M, F, T, U>
where
    M: MethodId,
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    /// Reference to the user associated with the event.
    pub user_id: &'a U,
    /// Reference to the tenant associated with the event.
    pub tenant_id: &'a T,
    /// Optional session ID for session-related events.
    pub session_id: Option<&'a str>,
    /// What happened (see [`AuthEventType`]).
    pub event_type: AuthEventType,
    /// Outcome of the event (see [`AuthEventStatus`]).
    pub event_status: AuthEventStatus,
    /// Optional authentication method involved.
    pub method_id: Option<&'a M>,
    /// Optional authentication factor involved.
    pub factor_id: Option<&'a F>,
    /// Optional kind of factor (password, OTP, etc.).
    pub factor_kind: Option<AuthFactorKind>,
    /// Optional IP address for the event.
    pub ip_address: Option<&'a str>,
    /// Optional user agent string for the event.
    pub user_agent: Option<&'a str>,
    /// Optional error details for failed events.
    pub error_message: Option<&'a str>,
}

impl<'a, M, F, T, U> AuthEventBuilder<'a, M, F, T, U>
where
    M: MethodId,
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    /// Creates a new builder for an authentication event.
    ///
    /// Sets required fields: user, tenant, event type, and status.
    pub fn new(
        user_id: &'a U,
        tenant_id: &'a T,
        event_type: AuthEventType,
        event_status: AuthEventStatus,
    ) -> Self {
        Self {
            user_id,
            tenant_id,
            session_id: None,
            event_type,
            event_status,
            method_id: None,
            factor_id: None,
            factor_kind: None,
            ip_address: None,
            user_agent: None,
            error_message: None,
        }
    }

    /// Sets the session ID for the event.
    pub fn with_session_id(mut self, session_id: &'a str) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Sets the authentication method ID for the event.
    pub fn with_method_id(mut self, method_id: &'a M) -> Self {
        self.method_id = Some(method_id);
        self
    }

    /// Sets the authentication factor ID for the event.
    pub fn with_factor_id(mut self, factor_id: &'a F) -> Self {
        self.factor_id = Some(factor_id);
        self
    }

    /// Sets the kind of authentication factor for the event.
    pub fn with_factor_kind(mut self, factor_kind: AuthFactorKind) -> Self {
        self.factor_kind = Some(factor_kind);
        self
    }

    /// Sets the IP address for the event.
    pub fn with_ip_address(mut self, ip_address: &'a str) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    /// Sets the user agent string for the event.
    pub fn with_user_agent(mut self, user_agent: &'a str) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// Sets an error message for the event.
    pub fn with_error_message(mut self, error_message: &'a str) -> Self {
        self.error_message = Some(error_message);
        self
    }
}

pub type AuthEventRecord<'a, B> = AuthEventBuilder<
    'a,
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::TenantId,
    <B as AuthnBackend>::UserId,
>;
