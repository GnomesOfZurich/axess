//! Shared building blocks for the factor verify/prepare pipelines.
//!
//! [`AuthnService::verify_factor`] and [`AuthnService::prepare_factor`] both:
//! - extract the `Authenticating` triple from the session (or fail with
//!   [`AuthnError::NoFlow`]),
//! - re-check account status against the store on every step (lockout
//!   enforcement bypass-proofing: the store is authoritative, never
//!   the session),
//! - emit audit rows on attempts against locked accounts.
//!
//! `verify_factor` additionally needs:
//! - a `FailWithUpdate` CAS-retry loop for atomic counter increments
//!   (Email OTP / HOTP),
//! - the generic failure-handling block (audit + counter + lockout-policy
//!   verdict),
//! - user-scope CAS-or-insert persistence on `PassWithUpdate` (TOTP
//!   replay-prevention step / HOTP counter advance).
//!
//! Each concern lives here as a `pub(super)` method so:
//! - they can be tested independently (rather than only through the
//!   full factor-flow surface),
//! - the calling pipelines read top-to-bottom, with orthogonal
//!   concerns delegated rather than nested in `if let` ladders.
//!
//! Before this split, `verify_factor` was 345 lines in one
//! method; afterwards it is a ~50-line pipeline. `prepare_factor`'s
//! account-status block was a copy-paste of `verify_factor`'s; both
//! now share [`AuthnService::enforce_account_status`].
//!
//! [`AuthnError::NoFlow`]: crate::authn::error::AuthnError::NoFlow

use super::AuthnService;
use super::outcomes::FactorOutcome;
use super::verification::{apply_email_otp_failure, apply_hotp_failure};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    factor::{FactorConfig, FactorKind},
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
    types::{AuthnScope, EntityState},
};
use crate::session::extractor::AuthSession;

/// Outcome of [`AuthnService::enforce_account_status`].
///
/// Caller maps each variant to its own response shape:
/// - `verify_factor` → `Locked { until }` becomes [`FactorOutcome::Locked { until }`],
/// - `prepare_factor` → `Locked { until }` becomes `Err(AuthnError::Locked { until })`,
///   `NotActive(status)` becomes `Err(AuthnError::NotActive(status))`.
///
/// Both call sites audit identically before reaching this point: the
/// `Failure` row was emitted by `enforce_account_status` itself.
///
/// The `Locked` variant carries only `until` (not the full
/// `EntityState`): `Locked` and `NotActive` map to distinct
/// `AuthnError` variants, so the suspended-state carrier is not
/// needed downstream.
#[derive(Debug)]
pub(super) enum AccountStatusEnforcement {
    /// Account is in good standing: proceed.
    Ok,
    /// Account is `Suspended`. Audit row already emitted.
    Locked {
        /// Suspension expiry, when set; `None` means indefinite.
        until: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Account is in some other non-login-allowing state
    /// (`Pending`, `Terminated`, `Archived`, `Candidate`, `Guest`).
    /// No audit row was emitted; only `Suspended` triggers the audit.
    NotActive(EntityState),
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Re-check account status from the store and emit the audit
    /// row when the account is locked.
    ///
    /// The store is queried on every factor step rather than relying
    /// on session state: a session-based counter can be bypassed by
    /// the client starting a new session; the store-side counter
    /// cannot.
    ///
    /// Locked-account attempts MUST emit a `Failure` audit
    /// row. Without it, every attempt against a locked account
    /// vanishes from the audit log, losing visibility into the *most
    /// interesting* phase of an attack (the attacker confirming the
    /// username is valid by tripping the lockout).
    pub(super) async fn enforce_account_status(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        next_kind: Option<FactorKind>,
        session: &AuthSession,
    ) -> Result<AccountStatusEnforcement, AuthnError<I::Error>> {
        let status = self
            .identity
            .account_status(user_id)
            .await
            .map_err(AuthnError::Store)?;

        if status.is_locked() {
            let until = if let EntityState::Suspended(detail) = &status {
                detail.until
            } else {
                None
            };
            self.record_locked_attempt_audit(user_id, tenant_id, next_kind, session)
                .await;
            return Ok(AccountStatusEnforcement::Locked { until });
        }
        if !status.allows_login() {
            return Ok(AccountStatusEnforcement::NotActive(status));
        }
        Ok(AccountStatusEnforcement::Ok)
    }

    /// Emit the `FactorVerified Failure` audit row for an
    /// attempt against a locked account.
    async fn record_locked_attempt_audit(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        next_kind: Option<FactorKind>,
        session: &AuthSession,
    ) {
        let mut builder = AuthEventBuilder::failure(AuthEventType::FactorVerified)
            .attributed_to(user_id, tenant_id)
            .with_session(session.session_id().await)
            .with_error("locked");
        if let Some(k) = next_kind {
            builder = builder.with_factor(k);
        }
        self.emit_audit(builder).await;
    }

    /// Atomically apply a `FailWithUpdate` factor-config increment
    /// against the user-scope row.
    ///
    /// Why this exists: when `verify_credential` returns
    /// `FailWithUpdate(updated_config)`, the failure counter must
    /// advance by exactly one regardless of how many concurrent wrong
    /// attempts are in flight. Naïve "load → mutate → save" loses
    /// updates: N parallel attempts all read N=k, all save N=k+1,
    /// the counter ends at k+1 instead of k+N: the brute-force
    /// limit is effectively bypassed.
    ///
    /// Strategy:
    /// 1. **Probe user-scope** before entering the CAS loop.
    ///    The `updated_config` we received was computed against
    ///    whatever scope `load_factor_with_fallback` returned: that
    ///    may have been tenant or global. Using it as the CAS
    ///    `prior_config` against a user-scope row would always lose
    ///    the first round (different bytes), then fall through to
    ///    the reload-and-save path which can silently overwrite a
    ///    concurrent user-scope write (admin reconfiguration, prior
    ///    failed attempt). Probing first lets us:
    ///    - plain-insert when no user-scope row exists (no race),
    ///    - CAS against an authoritative user-scope value otherwise.
    /// 2. **Bounded CAS loop**: on swap failure, reload the live
    ///    user-scope value, recompute the `next_config` increment
    ///    from that value via the per-`FactorKind` `apply_*_failure`
    ///    helpers, retry. After `MAX_FAIL_UPDATE_RETRIES` we give up
    ///    and log: better to under-count than to spin forever under
    ///    pathological contention.
    /// 3. **Missing-row fallback**: if a reload returns `None`
    ///    mid-loop (admin deleted the row), fall back to a plain
    ///    save so the failure is recorded somewhere.
    /// 4. **Wrong-kind bail-out**: if the reloaded row has a
    ///    different `FactorKind` (admin reconfigured the user
    ///    mid-flow), break without retry: the failure update no
    ///    longer makes sense.
    pub(super) async fn persist_fail_with_update(
        &self,
        user_scope: &AuthnScope,
        current_kind: FactorKind,
        updated_config: &FactorConfig,
    ) -> Result<(), AuthnError<I::Error>> {
        const MAX_FAIL_UPDATE_RETRIES: usize = 8;

        let initial_user_scope = self
            .factors
            .load_factor(user_scope, current_kind.clone())
            .await
            .map_err(AuthnError::Store)?;

        let mut applied = false;
        let (mut prior_config, mut next_config) = if let Some(existing) = initial_user_scope {
            // Recompute the failure update against the live user-scope
            // value rather than the (possibly inherited) template that
            // initial verification used.
            let recomputed = match &existing {
                FactorConfig::EmailOtp(otp) => FactorConfig::EmailOtp(apply_email_otp_failure(otp)),
                FactorConfig::Hotp(otp) => FactorConfig::Hotp(apply_hotp_failure(otp)),
                _ => updated_config.clone(),
            };
            (existing, recomputed)
        } else {
            // No user-scope row yet; plain insert is correct, no
            // concurrent writer can race because there is nothing to
            // race with.
            self.factors
                .save_factor(user_scope, updated_config.clone())
                .await
                .map_err(AuthnError::Store)?;
            applied = true;
            (updated_config.clone(), updated_config.clone())
        };

        for _ in 0..MAX_FAIL_UPDATE_RETRIES {
            if applied {
                break;
            }
            // CAS-loss here is operationally normal: a concurrent
            // verification incremented the same counter between our
            // load and our save. Reload + recompute the increment
            // against the new prior on the next loop iteration. Not a
            // security signal; only the post-success CAS in
            // `persist_pass_with_update` treats `Ok(false)` as replay.
            let swapped = self
                .factors
                .compare_and_save_factor(user_scope, &prior_config, next_config.clone())
                .await
                .map_err(AuthnError::Store)?;
            if swapped {
                applied = true;
                break;
            }
            // CAS lost the race; reload and recompute the increment
            // from whatever the concurrent writer left behind.
            let reloaded = self
                .factors
                .load_factor(user_scope, current_kind.clone())
                .await
                .map_err(AuthnError::Store)?;
            let Some(reloaded_config) = reloaded else {
                // No user-scope row exists at all; fall back to a plain
                // save so the failure is at least recorded somewhere.
                if let Err(e) = self
                    .factors
                    .save_factor(user_scope, updated_config.clone())
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        "fallback save_factor on missing user-scope row \
                         also failed; failure counter not persisted"
                    );
                }
                applied = true;
                break;
            };
            match &reloaded_config {
                FactorConfig::EmailOtp(otp) => {
                    next_config = FactorConfig::EmailOtp(apply_email_otp_failure(otp));
                    prior_config = reloaded_config;
                }
                FactorConfig::Hotp(otp) => {
                    next_config = FactorConfig::Hotp(apply_hotp_failure(otp));
                    prior_config = reloaded_config;
                }
                _ => {
                    // Different factor kind appeared under user_scope (race
                    // with admin reconfiguration). Bail out without retry.
                    break;
                }
            }
        }

        if !applied {
            tracing::warn!("factor: failed to atomically increment failure counter after retries");
        }

        Ok(())
    }

    /// Record a factor-verification failure: audit emit, counter
    /// increment, lockout-policy verdict.
    ///
    /// Returns the [`FactorOutcome`] to bubble up: `Locked { until: None }`
    /// once the lockout threshold is reached, otherwise `InvalidCredential`.
    ///
    /// Audit-emit comes BEFORE the counter increment so audit-store
    /// errors fail loudly instead of letting counter and log diverge
    /// (otherwise a user could get locked with no explanatory audit
    /// row, leaving the SOC team correlating inconsistent state).
    ///
    /// Store errors on `record_failed_attempt` are NOT
    /// propagated as `Err(AuthnError::Store)`. Doing so would leak a
    /// distinct timing/error signature to the attacker (a Store-error
    /// response is measurably different from a normal
    /// `InvalidCredential`), letting them tell good usernames apart
    /// from bad ones AND letting them brute-force without ever
    /// incrementing the lockout counter. Instead we log + return
    /// `InvalidCredential`. Persistent counter outages should be
    /// monitored externally (metrics hook + log levels) and a
    /// circuit-breaker added at the application layer if needed.
    pub(super) async fn record_factor_failure(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        current_kind: &FactorKind,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        self.metrics.factor_failure();

        // This is the one intentional bypass of `emit_audit` /
        // `emit_audit_at`. The audit-ordering fix needs a `tracing::error!` with
        // `user_id = %user_id` context that the generic emit helpers
        // don't provide; every other audit emit in the crate goes
        // through them. Direct `self.identity.record_event(...)` is
        // load-bearing here, not stylistic.
        if let Err(e) = self
            .identity
            .record_event(
                AuthEventBuilder::failure(AuthEventType::FactorVerified)
                    .attributed_to(user_id, tenant_id)
                    .with_factor(current_kind.clone())
                    .build_at(self.clock.now()),
            )
            .await
        {
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "failed to record FactorVerified Failure audit event; \
                 SOC dashboards will be missing this attempt; proceeding with counter update"
            );
        }

        let count = match self.identity.record_failed_attempt(user_id).await {
            Ok(n) => n,
            Err(e) => {
                // Counter-store outage is operationally distinct from the
                // user typing a wrong password: the request still maps to
                // InvalidCredential (so an attacker probing for outages
                // gets the same response shape as a normal mismatch), but
                // lockout policy is silently disabled while the outage
                // lasts. Tag the metric separately so operators can alert
                // on it without false-firing on every wrong password.
                self.metrics.factor_counter_store_outage();
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    outage = "factor_counter_store",
                    "record_failed_attempt errored; returning InvalidCredential \
                     without lockout-counter update; monitor counter-store health"
                );
                session.record_attempt_at(self.clock.now()).await;
                return Ok(FactorOutcome::InvalidCredential);
            }
        };

        // Update session state for UI feedback only; never used for
        // lockout decisions (those are store-authoritative).
        session.record_attempt_at(self.clock.now()).await;

        let policy = self.identity.lockout_policy_for_tenant(tenant_id);
        if count >= policy.max_attempts {
            self.metrics.account_locked();
            // Surface the lockout window to the caller as `now +
            // policy.duration`, computed at the verdict that creates
            // the lockout (mirrors what production stores write into
            // the suspension row at the same moment). UIs avoid a
            // follow-up `enforce_account_status` round-trip to learn
            // the expiry.
            let until = policy.duration.and_then(|d| {
                chrono::Duration::from_std(d)
                    .ok()
                    .map(|d| self.clock.now() + d)
            });
            return Ok(FactorOutcome::Locked { until });
        }
        Ok(FactorOutcome::InvalidCredential)
    }

    /// Persist a `PassWithUpdate` factor-config change to the user
    /// scope, using compare-and-swap when a user-scope row already
    /// exists so a concurrent verification cannot race past the
    /// replay-prevention counter.
    ///
    /// For TOTP this records the accepted step (replay prevention).
    /// For HOTP this advances the counter past the matched value.
    ///
    /// The updated config is always saved to the user scope, even
    /// when the original config was loaded from a tenant or global
    /// scope via fallback. This is intentional: per-user mutable
    /// state (TOTP `last_step`, HOTP counter) must be stored
    /// per-user, while the inherited template (secret, digits,
    /// period) remains at the higher scope.
    ///
    /// Returns `Ok(true)` on a successful save, `Ok(false)` when CAS
    /// loses the race (concurrent verification spent the same
    /// step/counter first; caller treats as a replay and rejects).
    pub(super) async fn persist_pass_with_update(
        &self,
        user_scope: &AuthnScope,
        current_kind: FactorKind,
        updated_config: FactorConfig,
    ) -> Result<bool, AuthnError<I::Error>> {
        let existing_user_scope = self
            .factors
            .load_factor(user_scope, current_kind)
            .await
            .map_err(AuthnError::Store)?;
        match existing_user_scope {
            // CAS-loss here is a **security signal**: a concurrent
            // verification spent the same TOTP step / HOTP counter
            // first. `Ok(false)` propagates up as replay-detected and
            // the caller rejects the credential. Distinct from the
            // failure-counter CAS in `apply_failure_update`, where
            // `Ok(false)` means "retry."
            Some(prior) => self
                .factors
                .compare_and_save_factor(user_scope, &prior, updated_config)
                .await
                .map_err(AuthnError::Store),
            None => {
                self.factors
                    .save_factor(user_scope, updated_config)
                    .await
                    .map_err(AuthnError::Store)?;
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests;
