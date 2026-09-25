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
/// Extracted from HTTP request headers via [`AuditContext`]. Passed to
/// [`AuthEventBuilder::with_audit_context`] to stamp every event with client
/// metadata without threading individual header values through every call site.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditContext {
    /// Client IP address, as resolved by
    /// [`client_ip::layer`](crate::client_ip::layer).
    pub ip_address: Option<IpAddr>,
    /// How [`ip_address`](Self::ip_address) was arrived at.
    ///
    /// An address is not evidence on its own. This says whether it is the
    /// peer the server accepted, an entry walked out of a forwarded chain
    /// against a trusted peer, or a value the application supplied through
    /// [`ClientIp::resolved`](crate::client_ip::ClientIp::resolved), which
    /// axess cannot check. A row that says `supplied` where the rest say
    /// `forwarded` is worth a question.
    pub ip_source: crate::client_ip::Source,
    /// `User-Agent` header value.
    pub user_agent: Option<String>,
    /// Request ID for log correlation.
    ///
    /// Filled from
    /// [`RequestId`](crate::middleware::request_id::RequestId) under the
    /// `request-id` feature, and `None` without it. The `X-Request-Id`
    /// header is not read directly: it is an ordinary request header that
    /// any caller can set, to any length, and this value goes into an
    /// audit row. To honour an id from an upstream proxy, enable
    /// `accept-client-id`, which validates the inbound value in the layer
    /// before it reaches here.
    pub request_id: Option<String>,
    /// W3C trace id, for correlating this event with a distributed trace.
    ///
    /// The request id ties an event to one service's logs; this ties it to
    /// the trace that crosses them, which is the thread an incident
    /// responder actually pulls. Filled from
    /// [`TraceContext`](crate::middleware::trace_id::TraceContext) under
    /// the `trace-id` feature, and `None` without it: the id lives inside
    /// a `traceparent` header that has to be parsed, and guessing at it
    /// would put a malformed value in a column meant for joining.
    pub trace_id: Option<String>,
    /// ISO 3166-1 alpha-2 country code derived from IP (if available).
    ///
    /// Requires an external geo-IP lookup; left as `None` when no resolver
    /// is configured.
    pub geo_country: Option<String>,
    /// Session ID for session-scoped audit trail.
    pub session_id: Option<String>,
}

impl<S> axum::extract::FromRequestParts<S> for AuditContext
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    /// Build the context from the request, rather than from parts the
    /// caller assembles.
    ///
    /// The address is whatever
    /// [`client_ip::layer`](crate::client_ip::layer) resolved,
    /// read from the extensions. No header is consulted for it, and there
    /// is no argument through which a different one could be supplied:
    /// four free functions used to build this value, two of them took the
    /// address straight out of `X-Real-IP`, and a consumer migrated seven
    /// call sites onto one of those because its own documentation
    /// recommended it.
    ///
    /// Everything is optional and nothing here fails. A route mounted
    /// outside the layer yields no address, a request with no session
    /// yields no session id, and a null column is an honest record of
    /// what the request actually carried.
    ///
    /// `geo_country` stays `None`: it needs a lookup axess does not
    /// perform. Fill it in afterwards if you run one.
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };

        let client_ip = parts
            .extensions
            .get::<crate::client_ip::ClientIp>()
            .copied()
            .unwrap_or_default();
        let user_agent = header("user-agent");

        // The typed value the request-id layer left behind, and nothing
        // else. `X-Request-Id` is an ordinary request header: any caller
        // can set it, to any length, and it would land in an audit row
        // unbounded and unchecked. Accepting an upstream id is what the
        // `accept-client-id` feature is for, where the layer validates it
        // and then puts it here.
        #[cfg(feature = "request-id")]
        let request_id = parts
            .extensions
            .get::<crate::middleware::request_id::RequestId>()
            .map(|id| id.0.clone());
        #[cfg(not(feature = "request-id"))]
        let request_id = None;

        #[cfg(feature = "trace-id")]
        let trace_id = parts
            .extensions
            .get::<crate::middleware::trace_id::TraceContext>()
            .map(|ctx| ctx.trace_id.clone());
        #[cfg(not(feature = "trace-id"))]
        let trace_id = None;

        // A request without a session is ordinary on a login route, which
        // is the one place this context matters most, so its absence is a
        // `None` rather than a rejection.
        let session_id =
            match crate::session::extractor::AuthSession::from_request_parts(parts, state).await {
                Ok(session) => Some(session.session_id().await.to_string()),
                Err(_) => None,
            };

        Ok(Self {
            ip_address: client_ip.get(),
            ip_source: client_ip.source(),
            user_agent,
            request_id,
            trace_id,
            geo_country: None,
            session_id,
        })
    }
}

// ── AuthEventType ─────────────────────────────────────────────────────────────

/// Every authentication-related event name axess defines.
///
/// The enum is shared vocabulary, not a list of what axess emits. Axess
/// emits from its service layer, which is the part holding an
/// [`IdentityAuthnLog`](super::store::IdentityAuthnLog) to write through.
/// Seven names are for glue the adopter implements and axess is not on the
/// call path for: `MethodEnabled`, `MethodDisabled`, `SessionExpired`,
/// `SessionInvalidated`, `DeviceTrustGranted`, `DevicePurged` and
/// `DeviceFingerprintMismatch`. They are declared here so every deployment
/// spells them the same way and a shared SIEM rule matches across adopters;
/// each is marked below. See `docs/production/audit-events.md`.
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
    /// Enabling an authentication method. **Adopter-emitted:** axess has
    /// no method enable/disable operation.
    MethodEnabled,
    /// Disabling an authentication method. **Adopter-emitted**, as
    /// [`MethodEnabled`](Self::MethodEnabled).
    MethodDisabled,
    /// A password reset was requested (token issued).
    PasswordResetRequested,
    /// A password reset was completed (new password set).
    PasswordReset,
    /// Session expired due to inactivity or policy. **Adopter-emitted:**
    /// expiry is decided by the session store, and `refresh_session` takes
    /// no audit sink.
    SessionExpired,
    /// Session was explicitly invalidated (e.g., admin logout).
    /// **Adopter-emitted**, as [`SessionExpired`](Self::SessionExpired).
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
    /// **Adopter-emitted:** the ceremony is yours.
    DeviceTrustGranted,
    /// A `Device` transitioned to `Revoked`. `error` carries
    /// the reason (`"user_action"`, `"refresh_family_revoked"`,
    /// `"admin"`, `"fingerprint_mismatch"`).
    DeviceRevoked,
    /// A `Device` row was hard-deleted (retention sweep or
    /// Art 17 erasure). `device_id` is a tombstone; the row is gone.
    /// **Adopter-emitted:** the retention sweep is yours.
    DevicePurged,
    /// A new `DeviceBinding` (`Cookie` / `WebAuthn`) was
    /// attached to a `Device`. `error` carries the binding kind.
    DeviceBindingAdded,
    /// A request carried a valid `device_id` cookie but the
    /// recomputed `FingerprintHash` did not match. Always
    /// `Suspicious`: canonical cookie-replay signal. **Adopter-emitted:**
    /// it comes from your [`DeviceResolver`](crate::device::DeviceResolver),
    /// which is also why `AuthEventStatus::Suspicious` is never set by axess.
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
    /// Failed due to expiry. **Adopter-set:** the paths where it applies,
    /// such as `refresh_session`, are free functions with no audit sink in
    /// their signature, so axess never writes this.
    Expired,
    /// Flagged as suspicious (e.g., anomaly detected). **Adopter-set:** its
    /// canonical producer is
    /// [`DeviceFingerprintMismatch`](AuthEventType::DeviceFingerprintMismatch),
    /// which comes from an adopter-implemented resolver.
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

/// Why a failed [`AuthEvent`] failed.
///
/// This is the field a SOC dashboard groups by, so it is an enum rather
/// than free text. It used to be a `String`, which is the same defect
/// [`AuthEventBuilder::locked`](super::event::AuthEventBuilder::locked)
/// was introduced to fix for the *outcome*: querying meant matching a
/// string, and a string nothing enforced. One call site wrote
/// `"cross-tenant impersonation refused"`, with spaces, so it did not
/// even sort alongside the snake_case tags it sat beside.
///
/// [`Other`](Self::Other) carries anything axess has no tag for,
/// including an adopter's own detail. Parsing never fails: an
/// unrecognised string becomes `Other`, so rows written by an older
/// version, or by an adopter, read back without loss.
///
/// The wire form is the string from [`as_str`](Self::as_str), in both
/// serde and database columns, so this is a Rust-level type change only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum AuthFailureReason {
    /// The account or factor exists but is not in an active state.
    NotActive,
    /// The identity is valid and active but has no usable authentication
    /// method configured, so there is nothing to challenge.
    NoFactorsConfigured,
    /// No tenant matched the identifier supplied at login.
    UnknownTenant,
    /// The tenant row was present but could not be interpreted.
    InvalidTenantRow,
    /// No identity matched the identifier supplied at login.
    UnknownIdentifier,
    /// An administrator tried to impersonate across a tenant boundary.
    CrossTenantImpersonation,
    /// An OAuth refresh-token exchange failed.
    TokenRefresh,
    /// A refresh was attempted with no refresh token stored.
    TokenRefreshNoToken,
    /// A refresh named a provider that is not registered.
    TokenRefreshUnknownProvider,
    /// The identity provider rejected the refresh token.
    TokenRefreshProviderRejected,
    /// The OAuth ceremony outlived its timeout before the callback.
    CeremonyExpired,
    /// The `state` returned by the identity provider did not match.
    CsrfMismatch,
    /// The stored ceremony carried no issuer to compare against.
    MissingIssuer,
    /// The stored PKCE verifier was absent or unusable.
    PkceVerifierInvalid,
    /// The authorization-code exchange was rejected.
    TokenExchange,
    /// The callback's provider did not match the one the flow began with.
    ProviderMismatch,
    /// Anything axess has no tag for, including adopter-supplied detail.
    ///
    /// Prefer a variant where one fits: `Other` is not queryable as a
    /// class, which is the problem this type exists to solve.
    Other(String),
}

impl AuthFailureReason {
    /// Stable string representation for database storage.
    ///
    /// Not `&'static str`, unlike
    /// [`AuthEventStatus::as_str`](AuthEventStatus::as_str), because
    /// [`Other`](Self::Other) borrows its own payload.
    pub fn as_str(&self) -> &str {
        match self {
            Self::NotActive => "not_active",
            Self::NoFactorsConfigured => "no_factors_configured",
            Self::UnknownTenant => "unknown_tenant",
            Self::InvalidTenantRow => "invalid_tenant_row",
            Self::UnknownIdentifier => "unknown_identifier",
            Self::CrossTenantImpersonation => "cross_tenant_impersonation",
            Self::TokenRefresh => "token_refresh",
            Self::TokenRefreshNoToken => "token_refresh_no_token",
            Self::TokenRefreshUnknownProvider => "token_refresh_unknown_provider",
            Self::TokenRefreshProviderRejected => "token_refresh_provider_rejected",
            Self::CeremonyExpired => "ceremony_expired",
            Self::CsrfMismatch => "csrf_mismatch",
            Self::MissingIssuer => "missing_issuer",
            Self::PkceVerifierInvalid => "pkce_verifier_invalid",
            Self::TokenExchange => "token_exchange",
            Self::ProviderMismatch => "provider_mismatch",
            Self::Other(s) => s,
        }
    }
}

impl From<&str> for AuthFailureReason {
    fn from(s: &str) -> Self {
        match s {
            "not_active" => Self::NotActive,
            "no_factors_configured" => Self::NoFactorsConfigured,
            "unknown_tenant" => Self::UnknownTenant,
            "invalid_tenant_row" => Self::InvalidTenantRow,
            "unknown_identifier" => Self::UnknownIdentifier,
            "cross_tenant_impersonation" => Self::CrossTenantImpersonation,
            "token_refresh" => Self::TokenRefresh,
            "token_refresh_no_token" => Self::TokenRefreshNoToken,
            "token_refresh_unknown_provider" => Self::TokenRefreshUnknownProvider,
            "token_refresh_provider_rejected" => Self::TokenRefreshProviderRejected,
            "ceremony_expired" => Self::CeremonyExpired,
            "csrf_mismatch" => Self::CsrfMismatch,
            "missing_issuer" => Self::MissingIssuer,
            "pkce_verifier_invalid" => Self::PkceVerifierInvalid,
            "token_exchange" => Self::TokenExchange,
            "provider_mismatch" => Self::ProviderMismatch,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl From<String> for AuthFailureReason {
    fn from(s: String) -> Self {
        // Route through the borrowed form so the tag table lives once,
        // then avoid re-allocating when nothing matched.
        match Self::from(s.as_str()) {
            Self::Other(_) => Self::Other(s),
            known => known,
        }
    }
}

impl FromStr for AuthFailureReason {
    /// Parsing cannot fail: an unrecognised tag becomes
    /// [`Other`](Self::Other) rather than an error, so an audit row is
    /// never dropped for carrying a reason this version does not know.
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

impl fmt::Display for AuthFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// Serialized as the plain tag string rather than as a Rust enum, so the
// JSON an adopter already stores is unchanged by this type existing.
impl Serialize for AuthFailureReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AuthFailureReason {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from(String::deserialize(deserializer)?))
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
    ///
    /// Typed rather than free text so a forged or malformed value cannot
    /// be stored at all. Resolve it with
    /// [`TrustedProxies::client_ip`](crate::client_ip::TrustedProxies::client_ip)
    /// against the peer your server accepted; `None` is the honest value
    /// where no trustworthy address is available.
    pub ip_address: Option<std::net::IpAddr>,
    /// How [`ip_address`](Self::ip_address) was arrived at. See
    /// [`AuditContext::ip_source`].
    pub ip_source: crate::client_ip::Source,
    /// W3C trace id. See [`AuditContext::trace_id`].
    pub trace_id: Option<String>,
    /// Optional user agent string.
    pub user_agent: Option<String>,
    /// Optional request ID for log correlation (from `X-Request-Id`).
    pub request_id: Option<String>,
    /// Optional ISO 3166-1 alpha-2 country code derived from client IP.
    pub geo_country: Option<String>,
    /// Why the event failed, for failed events.
    ///
    /// Typed so a dashboard can group by it; see [`AuthFailureReason`].
    pub error: Option<AuthFailureReason>,
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
