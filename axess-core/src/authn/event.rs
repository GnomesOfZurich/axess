//! Authentication audit events.
//!
//! [`AuthEvent`] is emitted by the authentication service whenever a significant
//! action occurs. [`AuthEventBuilder`] provides ergonomic construction.
//! [`AuditContext`] enriches events with client metadata for compliance
//! (MiFID II record-keeping, GDPR).

use crate::{
    authn::{
        factor::FactorKind,
        ids::{DeviceId, TenantId, UserId},
    },
    session::id::SessionId,
};
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, str::FromStr};

// ── AuditContext ──────────────────────────────────────────────────────────────

/// Enriched context for audit events (compliance: MiFID II record-keeping, GDPR).
///
/// Extracted from HTTP request headers via [`extract_audit_context`]. Passed to
/// [`AuthEventBuilder::with_audit_context`] to stamp every event with client
/// metadata without threading individual header values through every call site.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditContext {
    /// Client IP address (from `X-Real-IP` or `X-Forwarded-For`).
    pub ip_address: Option<IpAddr>,
    /// `User-Agent` header value.
    pub user_agent: Option<String>,
    /// Request ID for log correlation (from `X-Request-Id`).
    pub request_id: Option<String>,
    /// ISO 3166-1 alpha-2 country code derived from IP (if available).
    ///
    /// Requires an external geo-IP lookup; left as `None` when no resolver
    /// is configured.
    pub geo_country: Option<String>,
    /// Session ID for session-scoped audit trail.
    pub session_id: Option<String>,
}

/// Extract an [`AuditContext`] from Axum request headers and an optional session.
///
/// # Example
///
/// ```rust,ignore
/// use axess_core::authn::event::extract_audit_context;
///
/// let ctx = extract_audit_context(request.headers(), Some(&session));
/// let event = AuthEventBuilder::new(user_id, tenant_id, event_type, status)
///     .with_audit_context(&ctx)
///     .build();
/// ```
pub fn extract_audit_context(
    headers: &axum::http::HeaderMap,
    _session: Option<&crate::session::extractor::AuthSession>,
) -> AuditContext {
    AuditContext {
        ip_address: ip_from_headers(headers),
        user_agent: headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        request_id: headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geo_country: None,
        session_id: None, // filled asynchronously below if session is provided
    }
}

/// Extract an [`AuditContext`] from headers and an optional session, including
/// the session ID (requires `.await`).
///
/// Prefer this over [`extract_audit_context`] when you have access to an
/// [`AuthSession`](crate::session::extractor::AuthSession).
pub async fn extract_audit_context_async(
    headers: &axum::http::HeaderMap,
    session: Option<&crate::session::extractor::AuthSession>,
) -> AuditContext {
    let mut ctx = extract_audit_context(headers, session);
    if let Some(s) = session {
        ctx.session_id = Some(s.session_id().await.to_string());
    }
    ctx
}

/// Extract a best-effort client IP address from request headers.
///
/// Checks `X-Real-IP` then `X-Forwarded-For` (first entry). Returns `None`
/// if neither header is present or parseable.
///
/// This is a standalone copy for the `authn` module so it does not depend on
/// the feature-gated `authz` module.
pub fn ip_from_headers(headers: &axum::http::HeaderMap) -> Option<IpAddr> {
    let raw = headers
        .get("X-Real-IP")
        .or_else(|| headers.get("X-Forwarded-For"))
        .and_then(|v| v.to_str().ok())?;

    // X-Forwarded-For may be a comma-separated list; take the first entry.
    raw.split(',').next().and_then(|s| s.trim().parse().ok())
}

// ── AuthEventType ─────────────────────────────────────────────────────────────

/// Enumerates all possible authentication-related events tracked by Axess.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
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
    /// A password reset was requested (token issued).
    PasswordResetRequested,
    /// A password reset was completed (new password set).
    PasswordReset,
    /// Session expired due to inactivity or policy.
    SessionExpired,
    /// Session was explicitly invalidated (e.g., admin logout).
    SessionInvalidated,
    /// A new user account was created (signup started).
    SignupStarted,
    /// A signup workflow was completed (user activated).
    SignupCompleted,
    /// A user account was suspended by an admin or the system.
    AccountSuspended,
    /// A user account was activated (e.g., after suspension or signup verification).
    AccountActivated,
    /// An admin assumed the identity of another user (impersonation).
    Impersonation,
    /// A request's fingerprint+cookie pair did not resolve to
    /// an existing `Device`; a new `Device` row was created at trust
    /// level `Unknown`. See [docs/production/audit-events.md](https://github.com/GnomesOfZurich/axess/blob/main/docs/production/audit-events.md#devicefirstseen-device_first_seen).
    DeviceFirstSeen,
    /// A `Device` transitioned from `Seen` → `Trusted` via a
    /// trust ceremony, user opt-in, or admin-driven assignment.
    DeviceTrustGranted,
    /// A `Device` transitioned to `Revoked`. `error` carries
    /// the reason (`"user_action"`, `"refresh_family_revoked"`,
    /// `"admin"`, `"fingerprint_mismatch"`).
    DeviceRevoked,
    /// A `Device` row was hard-deleted (retention sweep or
    /// Art 17 erasure). `device_id` is a tombstone; the row is gone.
    DevicePurged,
    /// A new `DeviceBinding` (`Cookie` / `WebAuthn`) was
    /// attached to a `Device`. `error` carries the binding kind.
    DeviceBindingAdded,
    /// A request carried a valid `device_id` cookie but the
    /// recomputed `FingerprintHash` did not match. Always
    /// `Suspicious`: canonical cookie-replay signal.
    DeviceFingerprintMismatch,
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
            AuthEventType::PasswordResetRequested => "password_reset_requested",
            AuthEventType::PasswordReset => "password_reset",
            AuthEventType::SessionExpired => "session_expired",
            AuthEventType::SessionInvalidated => "session_invalidated",
            AuthEventType::SignupStarted => "signup_started",
            AuthEventType::SignupCompleted => "signup_completed",
            AuthEventType::AccountSuspended => "account_suspended",
            AuthEventType::AccountActivated => "account_activated",
            AuthEventType::Impersonation => "impersonation",
            AuthEventType::DeviceFirstSeen => "device_first_seen",
            AuthEventType::DeviceTrustGranted => "device_trust_granted",
            AuthEventType::DeviceRevoked => "device_revoked",
            AuthEventType::DevicePurged => "device_purged",
            AuthEventType::DeviceBindingAdded => "device_binding_added",
            AuthEventType::DeviceFingerprintMismatch => "device_fingerprint_mismatch",
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
            "password_reset_requested" => Ok(AuthEventType::PasswordResetRequested),
            "password_reset" => Ok(AuthEventType::PasswordReset),
            "session_expired" => Ok(AuthEventType::SessionExpired),
            "session_invalidated" => Ok(AuthEventType::SessionInvalidated),
            "signup_started" => Ok(AuthEventType::SignupStarted),
            "signup_completed" => Ok(AuthEventType::SignupCompleted),
            "account_suspended" => Ok(AuthEventType::AccountSuspended),
            "account_activated" => Ok(AuthEventType::AccountActivated),
            "impersonation" => Ok(AuthEventType::Impersonation),
            "device_first_seen" => Ok(AuthEventType::DeviceFirstSeen),
            "device_trust_granted" => Ok(AuthEventType::DeviceTrustGranted),
            "device_revoked" => Ok(AuthEventType::DeviceRevoked),
            "device_purged" => Ok(AuthEventType::DevicePurged),
            "device_binding_added" => Ok(AuthEventType::DeviceBindingAdded),
            "device_fingerprint_mismatch" => Ok(AuthEventType::DeviceFingerprintMismatch),
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
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
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
/// Persisted via [`IdentityAuthnLog::record_event`](crate::authn::IdentityAuthnLog::record_event).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct AuthEvent {
    /// User associated with the event, if one has been resolved.
    ///
    /// `None` indicates attribution was not available at the moment the
    /// event fired: e.g. a failed login attempt for a non-existent user,
    /// or an OAuth callback with a malformed subject claim. Downstream
    /// audit schemas should store the `user_id` column as nullable
    /// (`user_id TEXT REFERENCES users(id)`).
    pub user_id: Option<UserId>,
    /// Tenant associated with the event, if one has been resolved.
    ///
    /// `None` when the tenant could not be identified at event time.
    /// Same storage guidance as `user_id`.
    pub tenant_id: Option<TenantId>,
    /// Optional session ID for session-related events.
    pub session_id: Option<SessionId>,
    /// What happened.
    pub event_type: AuthEventType,
    /// Outcome of the event.
    pub event_status: AuthEventStatus,
    /// Timestamp when the event occurred, as `i64` epoch microseconds.
    ///
    /// Stored as `i64` rather than `chrono::DateTime<Utc>` so the event
    /// is rkyv-archivable end-to-end (chrono 0.4 still pins rkyv 0.7
    /// in its `rkyv-*` features, incompatible with the workspace's
    /// rkyv 0.8). Reconstruct as needed via
    /// `DateTime::<Utc>::from_timestamp_micros(event_time)`.
    pub event_time: i64,
    /// Optional kind of factor involved.
    pub factor_kind: Option<FactorKind>,
    /// Optional client IP address.
    pub ip_address: Option<String>,
    /// Optional user agent string.
    pub user_agent: Option<String>,
    /// Optional request ID for log correlation (from `X-Request-Id`).
    pub request_id: Option<String>,
    /// Optional ISO 3166-1 alpha-2 country code derived from client IP.
    pub geo_country: Option<String>,
    /// Optional error detail for failed events.
    pub error: Option<String>,
    /// Optional administrator who initiated the action on the subject's
    /// behalf, distinct from `user_id` (the subject of the event).
    ///
    /// Set on admin actions: impersonation start/stop, suspension,
    /// activation, password reset, factor reset. Without this field the
    /// admin's identity gets buried in `error` strings, making
    /// "show me everything user X did as admin" impossible.
    ///
    /// Recommended audit-table column: `actor_id TEXT REFERENCES users(id)`.
    /// Index it for forensic queries:
    /// `CREATE INDEX idx_auth_events_actor_id ON auth_events(actor_id);`.
    pub actor_id: Option<UserId>,
    /// Optional device that originated the request.
    ///
    /// Populated by the `device` feature for events whose call site
    /// has access to the resolved [`crate::authn::ids::DeviceId`].
    /// Always populated on `Device*` event types; populated on
    /// `Authenticated` / `LoginAttempt` / `LogoutAttempt` /
    /// `FactorVerified` / `SessionInvalidated` when the request was
    /// resolved through the device subsystem; `None` for out-of-band
    /// events with no request context (admin task runners, scheduled
    /// jobs).
    ///
    /// Recommended audit-table column:
    /// `device_id TEXT REFERENCES devices(id)`. Index for forensic
    /// queries that follow a device through its trust transitions:
    /// `CREATE INDEX idx_auth_events_device_id ON auth_events(device_id);`.
    /// `Device*` events with `device_id IS NULL` are an integrity
    /// violation: `DeviceFirstSeen` etc. should never be emitted
    /// without the device that triggered them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    /// Factors actually verified to reach this state, in completion order.
    ///
    /// Set on `Authenticated` events. Distinguishes legitimate
    /// single-factor authentication (the tenant disabled TOTP, so
    /// password alone was always going to be sufficient) from a bypass
    /// attack (the user reached `Authenticated` without verifying TOTP
    /// even though the configured method requires it).
    ///
    /// Detection query: events where `event_type = 'authenticated'`
    /// and `factors_completed` is missing the kinds listed in the
    /// tenant's currently configured `AuthMethod`. Empty for events
    /// from sessions whose state predates the field, and for direct
    /// authenticated transitions (impersonation, refresh-token
    /// rotation) that bypass the per-factor flow by design.
    #[serde(default)]
    pub factors_completed: Vec<FactorKind>,
}

mod builder;
pub use builder::AuthEventBuilder;

#[cfg(test)]
mod tests;
