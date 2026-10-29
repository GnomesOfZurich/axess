//! Reserving a guess before the credential is checked.
//!
//! A lockout read before the verifier and a counter moved after it leave a
//! window the width of one verification: N parallel guesses all read a count
//! below the limit, all run, and all but the first are free. Reserving moves
//! the counter first and atomically in the store, so the limit is a limit on
//! verifiers started, not on verdicts reached.

use super::super::{RequestAuthnService, outcomes::FactorOutcome};
use crate::authn::{
    error::AuthnError,
    factor::FactorKind,
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
    types::CounterUnavailable,
};
use crate::session::extractor::AuthSession;

/// What reserving a guess came to.
#[derive(Debug)]
pub(in crate::authn::service) enum GuessSlot {
    /// The guess is reserved; the counter now reads this count.
    Reserved(u32),
    /// The counter store is down and the tenant's policy lets attempts
    /// through: the check runs unmetered and a failure is counted afterwards,
    /// if the store allows.
    Unmetered,
    /// The account is at its limit, or the counter cannot be read under a
    /// policy that fails closed. The outcome to answer, without running the
    /// verifier.
    Refused(FactorOutcome),
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Reserve one guess against the failure counter for `user_id`.
    ///
    /// Calls the identity store's `reserve_attempt` with the tenant's
    /// lockout policy. A refusal is audited as an attempt against a
    /// locked account and answers [`FactorOutcome::Locked`] with the expiry
    /// the counter implies.
    pub(in crate::authn::service) async fn reserve_guess(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        kind: &FactorKind,
        session: &AuthSession,
    ) -> Result<GuessSlot, AuthnError<I::Error>> {
        let policy = self.inner.identity.lockout_policy_for_tenant(tenant_id);
        let reserved = self.inner.identity.reserve_attempt(user_id, &policy).await;
        let fallback_until = || {
            policy.duration.and_then(|d| {
                chrono::Duration::from_std(d)
                    .ok()
                    .map(|d| self.inner.clock.now() + d)
            })
        };
        match reserved {
            Ok(Some(count)) => Ok(GuessSlot::Reserved(count)),
            Ok(None) => {
                self.inner.metrics.account_locked();
                self.record_locked_attempt_audit(user_id, tenant_id, Some(kind.clone()), session)
                    .await?;
                let until = match self.derived_lockout(user_id, tenant_id).await? {
                    Some(lock) => lock.until,
                    None => fallback_until(),
                };
                Ok(GuessSlot::Refused(FactorOutcome::Locked { until }))
            }
            Err(e) => {
                self.inner.metrics.factor_counter_store_outage();
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    outage = "factor_counter_store",
                    on_counter_unavailable = ?policy.on_counter_unavailable,
                    "reserve_attempt errored; lockout state unknown"
                );
                Ok(match policy.on_counter_unavailable {
                    CounterUnavailable::Lock => {
                        self.inner.metrics.account_locked();
                        GuessSlot::Refused(FactorOutcome::Locked {
                            until: fallback_until(),
                        })
                    }
                    CounterUnavailable::Allow => GuessSlot::Unmetered,
                })
            }
        }
    }

    /// Give back the reservation of a guess whose credential verified, or
    /// whose check ended in something other than a verdict on the credential.
    ///
    /// Failures that preceded the reservation stay counted; the counter is
    /// reset when the whole login succeeds. A store that cannot release is
    /// logged: the guess then stays counted, which errs towards the lockout.
    pub(in crate::authn::service) async fn release_guess(
        &self,
        reserved: Option<u32>,
        user_id: &UserId,
    ) {
        if reserved.is_none() {
            return;
        }
        if let Err(e) = self.inner.identity.release_attempt(user_id).await {
            tracing::warn!(
                user_id = %user_id,
                error = %e,
                "release_attempt errored; the verified guess stays counted"
            );
        }
    }
}
