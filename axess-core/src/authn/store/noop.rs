//! The no-op [`IdentityAuthnLog`] adapter.

use super::*;
use crate::authn::event::AuthEvent;
use crate::authn::types::{Throttle, ThrottleState, ThrottleSubject};

/// Wraps an [`IdentityLookup`] backend with a no-op [`IdentityAuthnLog`]
/// impl on top, so it satisfies the `AuthnService::new` bound without
/// the adopter writing audit + lockout impls.
///
/// **Semantics, read carefully before reaching for this:**
///
/// - `record_event` silently discards every audit event. No SOC trail.
/// - `record_failed_attempt` always returns `Ok(0)` and `failed_attempts`
///   always reports `(0, None)`. Lockout policy is effectively disabled;
///   the counter never accumulates, so no `max_attempts` threshold (not
///   even a policy of one) is crossed regardless of how many failures
///   occur.
/// - `reset_failed_attempts` is a no-op.
/// - `throttle_state` always reports `None` and `record_throttle_failure`
///   stores nothing, so the throttle is off with the lockout: no delay is
///   ever earned, whatever `LockoutPolicy::throttle` says.
/// - `record_last_login` is a no-op.
///
/// Appropriate uses:
///
/// - Integration tests / fixtures that don't exercise the lockout or
///   audit paths.
/// - Read-replica integrations where audit goes through a separate
///   pipeline (e.g. database CDC, a sidecar log forwarder).
/// - Prototypes that want login working before the audit table is
///   designed.
///
/// **Production deployments must override `IdentityAuthnLog` directly.**
/// A failure counter that never accumulates (every failed attempt answered
/// `Ok(0)`) is a security regression on any surface accepting untrusted
/// input.
pub struct NoopAuthnLog<L>(pub L);

impl<L: IdentityLookup + Clone> Clone for NoopAuthnLog<L> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<L: IdentityLookup> IdentityLookup for NoopAuthnLog<L> {
    type Error = L::Error;

    fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<Option<User>, Self::Error>> + Send {
        self.0.find_user(identifier, tenant_id)
    }

    fn get_user(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<Option<User>, Self::Error>> + Send {
        self.0.get_user(user_id)
    }

    fn get_user_tenant(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<Option<TenantId>, Self::Error>> + Send {
        self.0.get_user_tenant(user_id)
    }

    fn get_user_in_tenant(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<Option<User>, Self::Error>> + Send {
        self.0.get_user_in_tenant(user_id, tenant_id)
    }

    fn get_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<Option<Tenant>, Self::Error>> + Send {
        self.0.get_tenant(tenant_id)
    }

    fn find_tenant(
        &self,
        identifier: &str,
    ) -> impl std::future::Future<Output = Result<Option<Tenant>, Self::Error>> + Send {
        self.0.find_tenant(identifier)
    }

    fn default_tenant(
        &self,
    ) -> impl std::future::Future<Output = Result<Tenant, Self::Error>> + Send {
        self.0.default_tenant()
    }

    fn account_status(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<EntityState, Self::Error>> + Send {
        self.0.account_status(user_id)
    }

    fn lockout_policy_for_tenant(&self, tenant_id: &TenantId) -> LockoutPolicy {
        self.0.lockout_policy_for_tenant(tenant_id)
    }

    fn password_rules_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<PasswordRules, Self::Error>> + Send {
        self.0.password_rules_for_tenant(tenant_id)
    }

    fn ip_policy_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<crate::authn::types::IpPolicy, Self::Error>> + Send
    {
        self.0.ip_policy_for_tenant(tenant_id)
    }
}

impl<L: IdentityLookup> IdentityAuthnLog for NoopAuthnLog<L> {
    async fn record_event(&self, event: AuthEvent) -> Result<AuditOutcome, Self::Error> {
        tracing::trace!(
            target: "axess::authn::noop_log",
            event_type = ?event.event_type,
            user_id = ?event.user_id,
            "NoopAuthnLog: event discarded (no SOC trail wired up)",
        );
        // Honest rather than convenient: this sink drops every event, so
        // it reports every event as shed. `Recorded` would claim a write
        // that never happens.
        Ok(AuditOutcome::Shed)
    }

    async fn record_failed_attempt(&self, user_id: &UserId) -> Result<u32, Self::Error> {
        tracing::trace!(
            target: "axess::authn::noop_log",
            %user_id,
            "NoopAuthnLog: failed attempt not persisted; lockout policy disabled",
        );
        Ok(0)
    }

    async fn reserve_attempt(
        &self,
        _user_id: &UserId,
        _policy: &crate::authn::types::LockoutPolicy,
    ) -> Result<Option<u32>, Self::Error> {
        // Nothing is stored, so there is no count to cross: every guess is
        // granted, as every failure is counted as zero.
        Ok(Some(0))
    }

    async fn release_attempt(&self, _user_id: &UserId) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn failed_attempts(
        &self,
        _user_id: &UserId,
    ) -> Result<(u32, Option<chrono::DateTime<chrono::Utc>>), Self::Error> {
        Ok((0, None))
    }

    async fn reset_failed_attempts(&self, user_id: &UserId) -> Result<(), Self::Error> {
        tracing::trace!(
            target: "axess::authn::noop_log",
            %user_id,
            "NoopAuthnLog: reset_failed_attempts is a no-op",
        );
        Ok(())
    }

    async fn throttle_state(
        &self,
        _key: &ThrottleSubject,
    ) -> Result<Option<ThrottleState>, Self::Error> {
        // Nothing is stored, so no delay is ever earned: the throttle is off
        // with the lockout.
        Ok(None)
    }

    async fn record_throttle_failure(
        &self,
        key: &ThrottleSubject,
        _throttle: &Throttle,
    ) -> Result<(), Self::Error> {
        tracing::trace!(
            target: "axess::authn::noop_log",
            user_id = %key.user_id,
            "NoopAuthnLog: throttle failure not persisted; throttle disabled",
        );
        Ok(())
    }

    async fn clear_throttle(&self, _key: &ThrottleSubject) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn record_last_login(
        &self,
        _user_id: &UserId,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Self::Error> {
        // The inner store is an `IdentityLookup` only: there is no
        // last-login column to forward to.
        Ok(())
    }
}
