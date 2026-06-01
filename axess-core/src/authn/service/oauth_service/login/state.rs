//! Shared ceremony-state helpers used across the OAuth login submodules.
//!
//! `is_oauth_expired`, `record_oauth_failure`, `record_oauth_failure_and_clear`,
//! and `clear_oauth_state` are needed by multiple ceremony steps (begin clears
//! stale state, finish records failures and checks expiry). They live here so
//! the per-step modules can stay focused on their own happy path.

use crate::authn::service::AuthnService;
use crate::authn::{
    event::{AuthEventBuilder, AuthEventType},
    factor::FactorKind,
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Check if the OAuth ceremony has exceeded the provider's timeout.
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
        let configured = self
            .oauth_providers
            .get(provider_name)
            .map(|p| p.ceremony_timeout())
            .unwrap_or(RFC_6749_AUTH_CODE_MAX);
        let timeout = configured.min(RFC_6749_AUTH_CODE_MAX);
        if configured > RFC_6749_AUTH_CODE_MAX {
            tracing::warn!(
                provider = %provider_name,
                configured_secs = configured.as_secs(),
                cap_secs = RFC_6749_AUTH_CODE_MAX.as_secs(),
                "provider ceremony_timeout exceeds RFC 6749 §4.1.2 RECOMMENDED 600s; capped"
            );
        }
        let elapsed = self.clock.now() - started_at.with_timezone(&chrono::Utc);
        elapsed.to_std().unwrap_or_default() > timeout
    }

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
        reason: &str,
        provider_name: &str,
        session: &AuthSession,
    ) {
        self.record_oauth_failure(reason, provider_name, session)
            .await;
        self.clear_oauth_state(session).await;
    }

    /// Record an OAuth failure audit event.
    pub(super) async fn record_oauth_failure(
        &self,
        reason: &str,
        provider_name: &str,
        session: &AuthSession,
    ) {
        // Use whatever attribution the session carries; a pre-auth failure
        // legitimately has `None` for both ids, and the event_type +
        // error field carry the diagnostic information.
        let user_id = session.user_id().await;
        let tenant_id = session.tenant_id().await;

        self.emit_audit(
            AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                .maybe_attributed_to(user_id.as_ref(), tenant_id.as_ref())
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(provider_name.into()),
                ))
                .with_error(reason),
        )
        .await;
    }

    /// Clear all OAuth ceremony state from the session.
    ///
    /// Removes the keys outright rather than overwriting them with `null` so
    /// the session's `custom` bag does not accumulate dead entries with
    /// every flow; repeated logins under the size cap would otherwise
    /// eventually trip the `max_custom_bytes` guard and wipe the entire bag.
    ///
    /// All eight removals run inside one
    /// [`AuthSession::mutate_custom`] closure (a single write-lock
    /// acquisition). The previous implementation issued the removals
    /// serially via `remove_custom`; a concurrent `begin_oauth_login`
    /// (or any caller of `set_custom`) could re-insert one of these
    /// keys mid-clear, leaving the session with partial ceremony state
    /// that downstream calls would treat as "active flow".
    pub(super) async fn clear_oauth_state(&self, session: &AuthSession) {
        use axess_factors::oauth::types::keys as oauth_keys;
        const KEYS: &[&str] = &[
            oauth_keys::PKCE_VERIFIER,
            oauth_keys::CSRF_STATE,
            oauth_keys::NONCE,
            oauth_keys::PROVIDER,
            oauth_keys::PROVIDER_ISSUER,
            oauth_keys::STARTED,
            oauth_keys::EXPECTED_TENANT,
            // Cleared after the OIDC callback completes.
            oauth_keys::PAR_INFLIGHT,
        ];
        session
            .mutate_custom(|obj| {
                for key in KEYS {
                    obj.remove(*key);
                }
            })
            .await;
    }
}
