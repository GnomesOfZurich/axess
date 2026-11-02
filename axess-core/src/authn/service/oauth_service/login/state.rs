//! Shared ceremony-state helpers used across the OAuth login submodules.
//!
//! `is_oauth_expired`, `record_oauth_failure`, `record_oauth_failure_and_clear`,
//! `clear_oauth_state` and the ceremony's tenant binding are needed by
//! multiple ceremony steps (begin clears stale state, finish records failures
//! and checks expiry, complete checks the tenant). They live here so the
//! per-step modules can stay focused on their own happy path.

use crate::authn::service::{AuthnService, RequestAuthnService};
use crate::authn::{
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::FactorKind,
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;
use axess_factors::oauth::{OAuthError, keys as oauth_keys};

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Record an OAuth failure audit row AND clear the in-flight
    /// ceremony state.
    ///
    /// Every failure branch in `finish_oauth_login` must do both:
    /// the audit row gives the SOC the signal that the ceremony was
    /// cut short, and `clear_oauth_state` releases the session-side
    /// PKCE verifier / CSRF state / nonce / etc. so a subsequent
    /// `begin_oauth_login` doesn't trip the "in-flight ceremony
    /// already running" rail. Earlier these were two manual calls
    /// at five sites; one of them subtly omitted the clear in an
    /// earlier revision before being fixed. Roll them into one
    /// helper so the next site that fails partway through gets the
    /// contract for free.
    pub(super) async fn record_oauth_failure_and_clear(
        &self,
        reason: AuthFailureReason,
        provider_name: &str,
        session: &AuthSession,
    ) -> Result<(), OAuthError> {
        // Clear the ceremony state even when the audit write fails: the
        // state is unusable either way, and leaving it behind would let a
        // replay of the same callback find a live ceremony.
        let recorded = self
            .record_oauth_failure(reason, provider_name, session)
            .await;
        self.clear_oauth_state(session).await;
        recorded
    }

    /// Record an OAuth failure audit event.
    pub(super) async fn record_oauth_failure(
        &self,
        reason: AuthFailureReason,
        provider_name: &str,
        session: &AuthSession,
    ) -> Result<(), OAuthError> {
        // Use whatever attribution the session carries; a pre-auth failure
        // legitimately has `None` for both ids, and the event_type +
        // error field carry the diagnostic information.
        let user_id = session.pending_user_id().await;
        let tenant_id = session.pending_tenant_id().await;

        self.emit_audit(
            AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                .maybe_attributed_to(user_id.as_ref(), tenant_id.as_ref())
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(provider_name.into()),
                ))
                .with_error(reason),
        )
        .await
        .map_err(|e| OAuthError::AuditStore(e.to_string()))
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Check if the OAuth ceremony has exceeded `configured`, the timeout
    /// of the provider the ceremony runs against.
    ///
    /// Caps the effective ceremony timeout at the RFC 6749 §4.1.2
    /// RECOMMENDED authorization-code lifetime of **10 minutes** (600s).
    /// An operator who set `ceremony_timeout = 30 min` to accommodate slow
    /// MFA otherwise gets an *authorization-code lifetime* of 30 min as a
    /// side effect, well beyond the spec recommendation. Capping here
    /// keeps the ceremony bounded by the spec; if the call site needs a
    /// longer end-to-end window, it should use `prompt=none` re-auth or
    /// a refresh token instead of widening the auth-code window.
    pub(super) async fn is_oauth_expired(
        &self,
        session: &AuthSession,
        provider_name: &str,
        configured: std::time::Duration,
    ) -> bool {
        use axess_factors::oauth::types::keys as oauth_keys;
        const RFC_6749_AUTH_CODE_MAX: std::time::Duration = std::time::Duration::from_secs(600);

        // Fail closed: if the start timestamp is missing or unparseable,
        // treat the ceremony as expired. This prevents accepting ceremonies
        // that were never properly initiated.
        let Some(started) = session.get_custom(oauth_keys::STARTED).await else {
            return true;
        };
        let Some(ts) = started.as_str() else {
            return true;
        };
        let Ok(started_at) = chrono::DateTime::parse_from_rfc3339(ts) else {
            return true;
        };
        let timeout = configured.min(RFC_6749_AUTH_CODE_MAX);
        if configured > RFC_6749_AUTH_CODE_MAX {
            tracing::warn!(
                provider = %provider_name,
                configured_secs = configured.as_secs(),
                cap_secs = RFC_6749_AUTH_CODE_MAX.as_secs(),
                "provider ceremony_timeout exceeds RFC 6749 §4.1.2 RECOMMENDED 600s; capped"
            );
        }
        let elapsed = self.inner.clock.now() - started_at.with_timezone(&chrono::Utc);
        elapsed.to_std().unwrap_or_default() > timeout
    }

    /// Clear all OAuth ceremony state from the session.
    ///
    /// Removes the keys outright rather than overwriting them with `null` so
    /// the session's `custom` bag does not accumulate dead entries with
    /// every flow; repeated logins under the size cap would otherwise
    /// eventually trip the `max_custom_bytes` guard and wipe the entire bag.
    ///
    /// Every removal, the tenant binding included, runs inside one
    /// [`AuthSession::mutate_custom`] closure (a single write-lock
    /// acquisition): a concurrent `begin_oauth_login` (or any caller of
    /// `set_custom`) cannot re-insert one of these keys mid-clear and leave
    /// the session with partial ceremony state that downstream calls would
    /// treat as an active flow.
    pub(super) async fn clear_oauth_state(&self, session: &AuthSession) {
        remove_ceremony_keys(session, true).await;
    }

    /// Clear the ceremony state but keep the tenant binding.
    ///
    /// `finish_oauth_login` uses this: the binding must survive until
    /// `complete_oauth_login` has compared it with the resolved user's
    /// tenant, and `complete` removes it afterwards
    /// ([`take_ceremony_tenant`]).
    pub(super) async fn clear_oauth_state_except_tenant(&self, session: &AuthSession) {
        remove_ceremony_keys(session, false).await;
    }
}

/// The keys of an in-flight ceremony, in one place: what
/// `stash_oauth_ceremony` writes (and the PAR marker) is what is cleared.
const CEREMONY_KEYS: &[&str] = &[
    oauth_keys::PKCE_VERIFIER,
    oauth_keys::CSRF_STATE,
    oauth_keys::NONCE,
    oauth_keys::PROVIDER,
    oauth_keys::PROVIDER_ISSUER,
    oauth_keys::STARTED,
    oauth_keys::DPOP_KEY,
    oauth_keys::PAR_INFLIGHT,
];

async fn remove_ceremony_keys(session: &AuthSession, with_tenant: bool) {
    session
        .mutate_custom(|obj| {
            for key in CEREMONY_KEYS {
                obj.remove(*key);
            }
            if with_tenant {
                obj.remove(oauth_keys::CEREMONY_TENANT);
            }
        })
        .await;
}

/// A stored tenant binding that does not read: tampering, or a session
/// written by something else. Refused, never taken for no binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UnreadableBinding;

/// The tenant a ceremony is bound to: `complete_oauth_login` refuses a
/// resolved user of another tenant, and, when `provider_from_tenant`, the
/// callback resolves the provider from this tenant's configuration instead
/// of the global registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::authn::service::oauth_service) struct CeremonyTenant {
    pub(in crate::authn::service::oauth_service) tenant: crate::authn::ids::TenantId,
    pub(in crate::authn::service::oauth_service) provider_from_tenant: bool,
}

impl CeremonyTenant {
    /// The session-bag form: `{"tenant": <id>, "provider_from_tenant": bool}`.
    pub(super) fn to_value(self) -> serde_json::Value {
        serde_json::json!({
            "tenant": self.tenant.to_string(),
            "provider_from_tenant": self.provider_from_tenant,
        })
    }

    /// Read the session-bag form. A plain string is the binding a 0.13
    /// `begin_oauth_login_in_tenant` wrote under the same key (a tenant
    /// with the global provider). [`UnreadableBinding`] for anything else.
    fn from_value(value: &serde_json::Value) -> Result<Self, UnreadableBinding> {
        let parse = |v: &serde_json::Value| {
            v.as_str()
                .and_then(|t| t.parse().ok())
                .ok_or(UnreadableBinding)
        };
        match value {
            serde_json::Value::String(_) => Ok(Self {
                tenant: parse(value)?,
                provider_from_tenant: false,
            }),
            serde_json::Value::Object(map) => Ok(Self {
                tenant: map.get("tenant").map(parse).ok_or(UnreadableBinding)??,
                provider_from_tenant: map
                    .get("provider_from_tenant")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(UnreadableBinding)?,
            }),
            _ => Err(UnreadableBinding),
        }
    }
}

/// The ceremony's tenant binding, if it has one; `Err` when the stored
/// binding does not read.
pub(super) async fn ceremony_tenant(
    session: &AuthSession,
) -> Result<Option<CeremonyTenant>, UnreadableBinding> {
    session
        .get_custom(oauth_keys::CEREMONY_TENANT)
        .await
        .map(|v| CeremonyTenant::from_value(&v))
        .transpose()
}

/// Remove the ceremony's tenant binding and return what it was: the binding
/// is single-use, gone whether the check that reads it passes or not.
pub(super) async fn take_ceremony_tenant(
    session: &AuthSession,
) -> Result<Option<CeremonyTenant>, UnreadableBinding> {
    // Removed under the session's own lock, not `take_custom`: that one
    // answers `None` when the store cannot confirm the removal, and `None`
    // here would read as "no binding" and skip the tenant check.
    session
        .mutate_custom(|obj| obj.remove(oauth_keys::CEREMONY_TENANT))
        .await
        .map(|v| CeremonyTenant::from_value(&v))
        .transpose()
}
