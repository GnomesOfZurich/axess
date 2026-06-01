//! [`AuthEventBuilder`]: ergonomic construction of [`super::AuthEvent`].
//!
//! Pulled sideways from `event.rs` because the builder is ~280 lines of
//! its own, bigger than every other concern in the event surface
//! combined. Kept inside the `event` module so `pub use` at the parent
//! re-export site preserves the existing
//! `axess_core::authn::event::AuthEventBuilder` import path.

use super::{AuditContext, AuthEvent, AuthEventStatus, AuthEventType};
use crate::authn::factor::FactorKind;
use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::session::id::SessionId;
use chrono::{DateTime, Utc};

/// Builder for constructing [`AuthEvent`] records ergonomically.
///
/// # Example
///
/// ```
/// use axess_core::authn::event::{AuthEventBuilder, AuthEventType};
/// use axess_identity::testing::{tenant, user};
///
/// let event = AuthEventBuilder::success(AuthEventType::Authenticated)
///     .attributed_to(&user("alice"), &tenant("acme"))
///     .with_ip("203.0.113.7")
///     .with_user_agent("Mozilla/5.0")
///     .with_request_id("req-7f3a")
///     .build();
///
/// // `event` is now an `AuthEvent` ready to hand to an audit sink.
/// # assert_eq!(event.event_type, AuthEventType::Authenticated);
/// ```
pub struct AuthEventBuilder {
    user_id: Option<UserId>,
    tenant_id: Option<TenantId>,
    event_type: AuthEventType,
    event_status: AuthEventStatus,
    session_id: Option<SessionId>,
    factor_kind: Option<FactorKind>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    request_id: Option<String>,
    geo_country: Option<String>,
    error: Option<String>,
    actor_id: Option<UserId>,
    device_id: Option<DeviceId>,
    factors_completed: Vec<FactorKind>,
}

impl AuthEventBuilder {
    /// Create a builder accepting optional attribution.
    ///
    /// Most call sites want [`attributed`](Self::attributed) (user + tenant
    /// known) or [`unattributed`](Self::unattributed) (pre-auth failure
    /// with no resolved principal). Use `new` when attribution is
    /// conditional: e.g. a session may or may not have resolved its
    /// tenant and you want to pass what you have.
    pub fn new(
        user_id: Option<UserId>,
        tenant_id: Option<TenantId>,
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
            request_id: None,
            geo_country: None,
            error: None,
            actor_id: None,
            device_id: None,
            factors_completed: Vec::new(),
        }
    }

    /// Convenience constructor for events with known user + tenant.
    ///
    /// This is the common case: authenticated actions, logout of an
    /// established session, factor verification against a resolved user.
    pub fn attributed(
        user_id: UserId,
        tenant_id: TenantId,
        event_type: AuthEventType,
        event_status: AuthEventStatus,
    ) -> Self {
        Self::new(Some(user_id), Some(tenant_id), event_type, event_status)
    }

    /// Convenience constructor for events emitted before a principal is
    /// resolved: failed login for an unknown user, OAuth callback with a
    /// malformed subject, rate-limit denial on anonymous input, etc.
    ///
    /// The resulting audit row has no user or tenant attribution; the
    /// [`event_type`](AuthEventType) plus any error/context fields carry
    /// the diagnostic information.
    pub fn unattributed(event_type: AuthEventType, event_status: AuthEventStatus) -> Self {
        Self::new(None, None, event_type, event_status)
    }

    /// Start a `Failure`-status builder for `event_type`.
    ///
    /// Hoisting the status into the verb means it can no longer be
    /// silently swapped with `event_type`: a positional bug the older
    /// `attributed(user, tenant, type, status)` shape allowed. Pair
    /// with [`attributed_to`](Self::attributed_to) when both ids are
    /// available, or pipe directly to one of the [`with_*`](Self) setters.
    ///
    /// # Example
    /// ```
    /// # use axess_core::authn::event::{AuthEventBuilder, AuthEventType};
    /// # use axess_core::authn::ids::{UserId, TenantId};
    /// # let user_id = axess_identity::testing::user("u1");
    /// # let tenant_id = axess_identity::testing::tenant("t1");
    /// let event = AuthEventBuilder::failure(AuthEventType::FactorVerified)
    ///     .attributed_to(&user_id, &tenant_id);
    /// ```
    pub fn failure(event_type: AuthEventType) -> Self {
        Self::new(None, None, event_type, AuthEventStatus::Failure)
    }

    /// Start a `Success`-status builder for `event_type`.
    ///
    /// Mirrors [`failure`](Self::failure): the same anti-positional-swap
    /// motivation applies to success rows (an audit emitter that
    /// accidentally records `Success` on a failure path is, if anything,
    /// a more pernicious bug since it silently launders the failure into
    /// the SOC dashboard).
    pub fn success(event_type: AuthEventType) -> Self {
        Self::new(None, None, event_type, AuthEventStatus::Success)
    }

    /// Attach both user and tenant attribution in one call.
    ///
    /// Takes refs and clones internally so call sites avoid the
    /// `(user_id.clone(), tenant_id.clone())` boilerplate that the
    /// earlier `attributed(user, tenant, ...)` constructor required.
    /// Both ids are `Arc<str>`-backed so the clone is cheap; the win
    /// is purely about call-site noise.
    pub fn attributed_to(mut self, user_id: &UserId, tenant_id: &TenantId) -> Self {
        self.user_id = Some(*user_id);
        self.tenant_id = Some(*tenant_id);
        self
    }

    /// Attach optional user and tenant attribution.
    ///
    /// Companion to [`attributed_to`](Self::attributed_to) for sites
    /// where attribution is conditional: e.g. an OAuth callback's
    /// `subject` may or may not parse as a typed `UserId`, the local
    /// tenant may not be resolved yet, or a logout for a session
    /// missing its tenant attribution. Pass `None` for either field
    /// to leave it unset; pass `Some(&id)` to set it (cloned
    /// internally).
    ///
    /// Use [`attributed_to`](Self::attributed_to) when both ids are
    /// known. Reach for the lower-level [`new`](Self::new) /
    /// [`unattributed`](Self::unattributed) constructors only when
    /// the partial-attribution shape doesn't fit either chainable.
    pub fn maybe_attributed_to(
        mut self,
        user_id: Option<&UserId>,
        tenant_id: Option<&TenantId>,
    ) -> Self {
        self.user_id = user_id.cloned();
        self.tenant_id = tenant_id.cloned();
        self
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
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Attach the user agent string.
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Attach a request ID for log correlation.
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Attach a geo-IP country code (ISO 3166-1 alpha-2).
    pub fn with_geo_country(mut self, country: impl Into<String>) -> Self {
        self.geo_country = Some(country.into());
        self
    }

    /// Attach an error description for failed events.
    pub fn with_error(mut self, err: impl Into<String>) -> Self {
        self.error = Some(err.into());
        self
    }

    /// Attach the administrator identity that initiated the action on the
    /// subject's behalf. Use on impersonation, suspension, activation, and
    /// admin-initiated password / factor reset events. Leave unset for
    /// self-service actions.
    pub fn with_actor(mut self, actor: UserId) -> Self {
        self.actor_id = Some(actor);
        self
    }

    /// Attach the [`DeviceId`] that originated this event.
    ///
    /// Required on every `Device*` [`AuthEventType`] variant: emitting
    /// e.g. `DeviceFirstSeen` without a `device_id` is an integrity
    /// violation. Optional on the auth-flow types
    /// (`Authenticated` / `LoginAttempt` / etc.) where the device
    /// subsystem may or may not have resolved a row by event time.
    pub fn with_device(mut self, device: DeviceId) -> Self {
        self.device_id = Some(device);
        self
    }

    /// Append a verified factor to the `factors_completed` list. Call once
    /// per factor that was verified to reach the authenticated state, in
    /// completion order. The library does this automatically for the
    /// `Authenticated` event emitted by `complete_factor_step`.
    pub fn with_factors_completed(mut self, kind: FactorKind) -> Self {
        self.factors_completed.push(kind);
        self
    }

    /// Stamp the builder with all fields from an [`AuditContext`].
    ///
    /// This is the preferred way to enrich events: call
    /// [`extract_audit_context`](super::extract_audit_context) (or the
    /// async variant) once per request, then pass the result here.
    pub fn with_audit_context(mut self, ctx: &AuditContext) -> Self {
        if let Some(ip) = &ctx.ip_address {
            self.ip_address = Some(ip.to_string());
        }
        if let Some(ua) = &ctx.user_agent {
            self.user_agent = Some(ua.clone());
        }
        if let Some(rid) = &ctx.request_id {
            self.request_id = Some(rid.clone());
        }
        if let Some(geo) = &ctx.geo_country {
            self.geo_country = Some(geo.clone());
        }
        if let Some(sid) = &ctx.session_id {
            // Only set session_id on the builder if the caller hasn't already
            // attached one via `with_session`. AuditContext carries a String
            // while the builder uses SessionId, so we parse it.
            if self.session_id.is_none()
                && let Ok(parsed) = sid.parse::<uuid::Uuid>()
            {
                self.session_id = Some(SessionId::from_bytes(*parsed.as_bytes()));
            }
        }
        self
    }

    /// Consume the builder and produce an [`AuthEvent`] timestamped now.
    pub fn build(self) -> AuthEvent {
        self.build_at(Utc::now())
    }

    /// Consume the builder and produce an [`AuthEvent`] with a specific timestamp.
    ///
    /// Use this with an injectable [`Clock`](axess_clock::Clock) for DST.
    /// The `DateTime<Utc>` is converted to epoch microseconds at the
    /// boundary so the resulting event is rkyv-archivable.
    pub fn build_at(self, event_time: DateTime<Utc>) -> AuthEvent {
        AuthEvent {
            user_id: self.user_id,
            tenant_id: self.tenant_id,
            session_id: self.session_id,
            event_type: self.event_type,
            event_status: self.event_status,
            event_time: event_time.timestamp_micros(),
            factor_kind: self.factor_kind,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            request_id: self.request_id,
            geo_country: self.geo_country,
            error: self.error,
            actor_id: self.actor_id,
            device_id: self.device_id,
            factors_completed: self.factors_completed,
        }
    }
}
