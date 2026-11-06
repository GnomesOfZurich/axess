//! The throttle gate before a guess, and the record after one.
//!
//! The per-account lock caps how many guesses an account takes; the
//! throttle slows one guesser down before that cap is reached, under a key
//! of the account and the client address (see
//! [`Throttle`](crate::authn::types::Throttle)). It runs before the guess is
//! reserved, so a throttled request costs no counter write and no hash; a
//! wrong guess records under the key after the reservation; a right one
//! clears it. A session on a device the account has used is not throttled,
//! as it is not locked: the delay keeps strangers out, not the owner.

use super::super::RequestAuthnService;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::FactorKind,
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
    types::{CounterUnavailable, Throttle, ThrottleKey, ThrottleSubject},
};
use crate::session::extractor::AuthSession;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// The tenant's throttle resolved for one request: the policy's
/// [`Throttle`], the key this request is counted under, and what to do when
/// the store cannot be read.
struct ResolvedThrottle {
    throttle: Throttle,
    key: ThrottleSubject,
    on_store_unavailable: CounterUnavailable,
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The throttle this request's guesses for `user_id` run under, or
    /// `None` when the tenant's policy throttles nothing.
    ///
    /// Under [`ThrottleKey::AccountAndAddress`] the key carries the address
    /// the client-IP layer resolved. A request with no address is keyed on
    /// the account alone, and when the address is unknown because the layer
    /// is not installed (`ip_source` is `Unknown`) that is a deployment
    /// fault, reported once per service.
    fn resolve_throttle(&self, user_id: &UserId, tenant_id: &TenantId) -> Option<ResolvedThrottle> {
        let policy = self.inner.identity.lockout_policy_for_tenant(tenant_id);
        let throttle = policy.throttle?;
        if throttle.key == ThrottleKey::AccountAndAddress
            && self.audit.ip_address.is_none()
            && self.audit.ip_source == crate::client_ip::Source::Unknown
            && !self
                .inner
                .throttle_address_unknown_reported
                .swap(true, Ordering::Relaxed)
        {
            tracing::error!(
                tenant = %tenant_id,
                ip_source = self.audit.ip_source.as_str(),
                "the throttle keys on account and client address and this request \
                 has no resolved client address, so guesses are throttled per account \
                 for every address; install axess::client_ip::layer on the router \
                 (reported once per service)"
            );
        }
        Some(ResolvedThrottle {
            key: throttle.subject(tenant_id, user_id, self.audit.ip_address),
            throttle,
            on_store_unavailable: policy.on_counter_unavailable,
        })
    }

    /// How long a guess for `user_id` from this request must wait, or
    /// `None` when it may run.
    ///
    /// Reads the store's entry under the request's key and applies
    /// [`Throttle::retry_after`] at the injected clock's now. A store that
    /// cannot be read follows the policy's [`CounterUnavailable`], as the
    /// lock does: `Lock` refuses for the longest delay, `Allow` lets the
    /// guess through. A session on a device the account has used is never
    /// throttled.
    pub(super) async fn throttle_for(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        session: &AuthSession,
    ) -> Result<Option<Duration>, AuthnError<I::Error>> {
        let Some(resolved) = self.resolve_throttle(user_id, tenant_id) else {
            return Ok(None);
        };
        let now = self.inner.clock.now();
        let retry_after = match self.inner.identity.throttle_state(&resolved.key).await {
            Ok(state) => resolved.throttle.retry_after(state.as_ref(), now),
            Err(e) => {
                self.inner.metrics.factors.factor_counter_store_outage();
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    outage = "factor_counter_store",
                    on_counter_unavailable = ?resolved.on_store_unavailable,
                    "throttle_state errored; throttle state unknown"
                );
                match resolved.on_store_unavailable {
                    CounterUnavailable::Lock => Some(resolved.throttle.max_delay),
                    CounterUnavailable::Allow => None,
                }
            }
        };
        if retry_after.is_some() && self.on_known_device(user_id, tenant_id, session).await {
            return Ok(None);
        }
        Ok(retry_after)
    }

    /// Record a wrong guess for `user_id` under this request's key.
    ///
    /// A store that cannot record is logged and the flow carries on, as a
    /// failed `record_failed_attempt` is: the counter has already moved, and
    /// refusing now would be an answer a guesser can tell apart.
    pub(super) async fn record_throttled_guess(&self, user_id: &UserId, tenant_id: &TenantId) {
        let Some(resolved) = self.resolve_throttle(user_id, tenant_id) else {
            return;
        };
        if let Err(e) = self
            .inner
            .identity
            .record_throttle_failure(&resolved.key, &resolved.throttle)
            .await
        {
            self.inner.metrics.factors.factor_counter_store_outage();
            tracing::warn!(
                user_id = %user_id,
                error = %e,
                outage = "factor_counter_store",
                "record_throttle_failure errored; the wrong guess earns no delay"
            );
        }
    }

    /// Clear the throttle under this request's key: the guess was right.
    ///
    /// A store that cannot clear is logged; the key then stays throttled,
    /// which errs towards the delay.
    pub(in crate::authn::service) async fn clear_throttle_for(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) {
        let Some(resolved) = self.resolve_throttle(user_id, tenant_id) else {
            return;
        };
        if let Err(e) = self.inner.identity.clear_throttle(&resolved.key).await {
            tracing::warn!(
                user_id = %user_id,
                error = %e,
                "clear_throttle errored; the key stays throttled"
            );
        }
    }

    /// Emit the `FactorVerified Failure` audit row, with reason
    /// [`AuthFailureReason::Throttled`], for a guess the throttle refused.
    pub(super) async fn record_throttled_attempt_audit(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        next_kind: Option<FactorKind>,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        let mut builder = AuthEventBuilder::failure(AuthEventType::FactorVerified)
            .attributed_to(user_id, tenant_id)
            .with_error(AuthFailureReason::Throttled)
            .with_session(session.session_id().await);
        if let Some(k) = next_kind {
            builder = builder.with_factor(k);
        }
        self.emit_audit(builder).await
    }
}
