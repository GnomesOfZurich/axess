//! Account management, split into orthogonal sub-modules per concern:
//!
//! - `signup`: `begin_signup` + `complete_signup`.
//! - `admin`: `suspend_user` / `activate_user` and the four variants
//!   each (`_by`, `_in_tenant`, `_by_in_tenant`).
//! - `impersonation`: `begin_impersonation` + `_in_tenant`.
//! - `password_reset`: `begin_password_reset`,
//!   `complete_password_reset`, and the cross-tenant rail.
//!
//! Split from the previous monolithic `account.rs` (1067 lines) into
//! these submodules. Each submodule contributes its own
//! `impl<I, F> AuthnService<I, F>` block. Rust allows
//! multiple impl blocks on the same type, so the public method surface
//! is byte-identical to before the split.
//!
//! This `mod.rs` itself only carries the **internal helper**
//! [`RequestAuthnService::complete_factor_step`] that supports the
//! multi-factor login path. Scope resolution moved into the store
//! trait ([`FactorStore::resolve_factor`]); the service layer calls
//! it directly instead of wrapping it.

mod admin;
mod impersonation;
mod password_reset;
mod signup;

use crate::authn::service::RequestAuthnService;
use crate::authn::service::outcomes::FactorOutcome;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;
use crate::session::store::note_revocation;
use std::ops::ControlFlow;

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The user's account status as of the injected clock's now.
    ///
    /// Reads the store's status and applies
    /// [`EntityState::effective_at`](crate::authn::types::EntityState::effective_at),
    /// so a suspension whose `until` has passed no longer blocks, and no
    /// store has to run a job to lift it. Every login-time status decision
    /// goes through here rather than calling the store directly.
    pub(crate) async fn current_account_status(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<crate::authn::types::EntityState, AuthnError<I::Error>> {
        let status = self
            .inner
            .identity
            .account_status(user_id)
            .await
            .map_err(AuthnError::Store)?;
        Ok(status.effective_at(self.inner.clock.now()))
    }

    /// Revoke every refresh token of `user_id` when a refresh store was
    /// attached with
    /// [`with_refresh_store`](crate::authn::service::AuthnServiceBuilder::with_refresh_store);
    /// a no-op otherwise.
    pub(crate) async fn revoke_refresh_tokens(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), AuthnError<I::Error>> {
        let Some(revoker) = &self.inner.refresh_revoker else {
            return Ok(());
        };
        revoker.revoke_user_tokens(user_id).await.map_err(|e| {
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "could not revoke the user's refresh tokens"
            );
            AuthnError::ExternalService("refresh token revocation failed".to_string())
        })
    }

    /// Undo an authentication whose audit row could not be written.
    ///
    /// The flow fails when the audit store is down, but by then the session
    /// is already authenticated and registered. Returning the error alone
    /// would leave a live session behind a failed login, so end it: drop the
    /// registry entry and wipe the session state.
    pub(crate) async fn end_session_after_audit_failure(
        &self,
        user_id: &crate::authn::ids::UserId,
        session: &AuthSession,
    ) {
        let sid = session.session_id().await;
        if let Some(reg) = &self.inner.registry {
            note_revocation(
                reg.invalidate_session(user_id, &sid).await,
                "refusing a login step",
            );
        }
        session.clear().await;
    }

    /// Invalidate each of `victims`, oldest first.
    async fn evict_sessions(
        &self,
        reg: &dyn crate::session::store::SessionRegistryHandle,
        user_id: &crate::authn::ids::UserId,
        victims: &[crate::session::id::SessionId],
    ) {
        for old_sid in victims {
            note_revocation(
                reg.invalidate_session(user_id, old_sid).await,
                "refusing a login step",
            );
            tracing::info!(
                user_id = %user_id,
                evicted_session = %old_sid,
                "concurrent session limit reached; evicting oldest session"
            );
            self.inner.metrics.session_invalidated();
        }
    }

    /// Make a just-authenticated session reachable by the eviction path.
    ///
    /// Enforces the concurrent session limit, registers the session and
    /// re-reads the account status. Breaks with [`FactorOutcome::Locked`]
    /// (session revoked and cleared) when the account was suspended in the
    /// meantime; a register failure or a status-read failure clears the
    /// session and is an error. With no registry configured it does nothing.
    async fn register_authenticated_session(
        &self,
        user_id: &crate::authn::ids::UserId,
        tenant_id: &crate::authn::ids::TenantId,
        sid: &crate::session::id::SessionId,
        session: &AuthSession,
    ) -> Result<ControlFlow<FactorOutcome>, AuthnError<I::Error>> {
        // Register in the session registry BEFORE any other store
        // calls. The session has already transitioned to Authenticated in
        // `advance_factor`; if the registry register is skipped because a
        // subsequent call errored out early, `invalidate_user` would have
        // no way to evict this session; it would be authenticated but
        // un-trackable. Register first so the session is always reachable
        // by the eviction path even if subsequent steps fail.
        if let Some(reg) = &self.inner.registry {
            // Enforce concurrent session limit: evict oldest sessions.
            if let Some(max) = self.inner.max_sessions_per_user {
                let active = reg.active_sessions(user_id).await;
                let victims = victims_before_register(&active, sid, max);
                self.evict_sessions(reg.as_ref(), user_id, &victims).await;
            }
            // Register-failure must clear the session and
            // refuse authentication. Without this, the just-set
            // Authenticated state would ride out as a cookie that
            // `invalidate_user` cannot reach.
            if !reg.register(user_id, sid).await {
                tracing::error!(
                    user_id = %user_id,
                    "complete_factor_step register failed; clearing session and \
                     refusing authentication"
                );
                session.clear().await;
                return Err(AuthnError::NoFlow);
            }

            // Trim again now that this session is registered. The count above
            // and the register are separate registry calls, so parallel logins
            // can each see room and together leave the user above the cap.
            // Every one of them keeps the NEWEST `max` registrations and
            // evicts the rest, itself included, so they all pick the same
            // survivors: the set converges on the cap and the logins that
            // lost the race fail rather than report success with a session
            // a peer has already revoked. (Evicting "everyone but me" made two
            // parallel logins at a cap of one revoke each other.)
            if let Some(max) = self.inner.max_sessions_per_user {
                let active = reg.active_sessions(user_id).await;
                let victims = victims_after_register(&active, max);
                self.evict_sessions(reg.as_ref(), user_id, victims).await;
                if victims.contains(sid) {
                    tracing::warn!(
                        user_id = %user_id,
                        "concurrent session limit: this login lost the race for the \
                         last slot; clearing session and refusing authentication"
                    );
                    session.clear().await;
                    return Err(AuthnError::NoFlow);
                }
            }

            // The credentials the login began against must still be the
            // credentials now. A password reset that landed after the
            // password was verified invalidates the user's registered
            // sessions, but this one was not registered yet, so it would
            // survive; checked here, after registering, a reset either
            // sees this session (and invalidates it) or is seen by this check.
            match self.flow_still_current(session, user_id, tenant_id).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        user_id = %user_id,
                        "credentials changed while the login was in flight; \
                         revoking just-registered session and refusing authentication"
                    );
                    note_revocation(
                        reg.invalidate_session(user_id, sid).await,
                        "refusing a login step",
                    );
                    session.clear().await;
                    return Err(AuthnError::NoFlow);
                }
                Err(e) => {
                    note_revocation(
                        reg.invalidate_session(user_id, sid).await,
                        "refusing a login step",
                    );
                    session.clear().await;
                    return Err(e);
                }
            }

            // Re-read account status AFTER registering. Closes the
            // race where a concurrent `suspend_user` call lands its
            // status-update + `invalidate_user` between this function's
            // initial status check (in `verify_factor`) and the register
            // above; without this re-check, the just-registered session
            // would survive the suspension as if the suspend never happened.
            match self.current_account_status(user_id).await {
                Ok(status) if !status.allows_login() => {
                    tracing::warn!(
                        user_id = %user_id,
                        status = ?status,
                        "account status flipped to non-loginable mid-flow; \
                         revoking just-registered session and refusing authentication"
                    );
                    note_revocation(
                        reg.invalidate_session(user_id, sid).await,
                        "refusing a login step",
                    );
                    // Wipe the in-memory session state so the response cookie
                    // does not ship a Set-Cookie for an authenticated session.
                    session.clear().await;
                    self.inner.metrics.account_locked();
                    let until = if let crate::authn::types::EntityState::Suspended(detail) = &status
                    {
                        detail.until
                    } else {
                        None
                    };
                    return Ok(ControlFlow::Break(FactorOutcome::Locked { until }));
                }
                Ok(_) => {}
                Err(e) => {
                    // Fail closed on store error; better to force a re-auth
                    // than risk leaving a session live across an
                    // inconsistent suspension state.
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "post-register status re-check failed; failing closed"
                    );
                    note_revocation(
                        reg.invalidate_session(user_id, sid).await,
                        "refusing a login step",
                    );
                    session.clear().await;
                    return Err(e);
                }
            }
        } else if !self.flow_still_current(session, user_id, tenant_id).await? {
            // No registry: nothing could have invalidated this session, but
            // the credentials it was verified against still must be current.
            session.clear().await;
            return Err(AuthnError::NoFlow);
        }
        Ok(ControlFlow::Continue(()))
    }

    /// Shared post-factor-success logic: check if all factors are complete,
    /// and if so, reset the failed-attempt counter, register in the session
    /// registry, and emit an Authenticated audit event.
    ///
    /// Returns `FactorOutcome::Authenticated` or `FactorOutcome::FactorRequired(next)`.
    pub(crate) async fn complete_factor_step(
        &self,
        user_id: &crate::authn::ids::UserId,
        tenant_id: &crate::authn::ids::TenantId,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let new_state = session.auth_state().await;
        if new_state.is_authenticated() {
            // Capture the verified-factor list off the new state so the
            // audit event records "which factors actually got us here";
            // distinguishes legitimate single-factor login (tenant
            // disabled TOTP) from a bypass attack that skipped a step.
            let factors_completed = match &new_state {
                crate::session::data::AuthState::Authenticated {
                    factors_completed, ..
                } => factors_completed.clone(),
                _ => Vec::new(),
            };

            let sid = session.session_id().await;

            if let ControlFlow::Break(outcome) = self
                .register_authenticated_session(user_id, tenant_id, &sid, session)
                .await?
            {
                return Ok(outcome);
            }

            // Reset the failed-attempt counter AFTER registry register
            // and AFTER the status re-check above. If this errors, the
            // session is already authenticated, registered, and tracked; log
            // the error and continue. Worst case the counter stays elevated;
            // the next successful login will reset it. The alternative (fail
            // the request) would leave behind an authenticated registered
            // session with no way to reach it through the response.
            if let Err(e) = self.inner.identity.reset_failed_attempts(user_id).await {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "failed to reset failed-attempt counter post-auth; \
                     proceeding (counter will reset on next successful login)"
                );
            }

            let mut event_builder = AuthEventBuilder::success(AuthEventType::Authenticated)
                .attributed_to(user_id, tenant_id)
                .with_session(sid);
            for kind in &factors_completed {
                event_builder = event_builder.with_factors_completed(kind.clone());
            }
            if let Err(e) = self.emit_audit(event_builder).await {
                self.end_session_after_audit_failure(user_id, session).await;
                return Err(e);
            }

            // Record last login time for compliance/audit.
            if let Err(e) = self
                .inner
                .identity
                .record_last_login(user_id, self.inner.clock.now())
                .await
            {
                tracing::error!(error = %e, "failed to record last login");
            }

            self.inner.metrics.auth_success();
            return Ok(FactorOutcome::Authenticated);
        }

        // More factors remain; return the next kind.
        let next_kind = match &new_state {
            crate::session::data::AuthState::Authenticating { remaining, .. } => remaining
                .first()
                .and_then(crate::authn::factor::FactorStep::primary)
                .cloned(),
            _ => None,
        };

        Ok(next_kind.map_or(FactorOutcome::Authenticated, FactorOutcome::FactorRequired))
    }
}

/// The sessions to evict to make room for `sid` under a cap of `max`:
/// the oldest of the OTHERS, enough that the others plus `sid` fit.
///
/// `sid` may already be registered (a re-run of the completing step), and
/// is then not counted twice: counting it as an existing session as well
/// as the incoming one evicted one session too many.
pub(super) fn victims_before_register(
    active: &[crate::session::id::SessionId],
    sid: &crate::session::id::SessionId,
    max: usize,
) -> Vec<crate::session::id::SessionId> {
    let others: Vec<_> = active.iter().filter(|s| *s != sid).copied().collect();
    let to_evict = (others.len() + 1).saturating_sub(max).min(others.len());
    others[..to_evict].to_vec()
}

/// The sessions to evict once `active` (oldest first) includes the new
/// login: everything but the newest `max`, the new login itself included
/// if it is not among them.
pub(super) fn victims_after_register(
    active: &[crate::session::id::SessionId],
    max: usize,
) -> &[crate::session::id::SessionId] {
    &active[..active.len().saturating_sub(max)]
}

#[cfg(test)]
mod eviction_tests {
    use super::*;
    use crate::session::id::SessionId;

    fn ids(n: u64) -> Vec<SessionId> {
        let rng = crate::testing::MockRng::new(n);
        (0..6).map(|_| SessionId::new(&rng)).collect()
    }

    #[test]
    fn an_already_registered_sid_is_not_counted_twice() {
        let s = ids(3);
        let (a, b, mine) = (s[0], s[1], s[2]);
        // a, mine registered; cap 2: nobody needs to go.
        assert!(victims_before_register(&[a, mine], &mine, 2).is_empty());
        // a, b, mine registered; cap 2: only the oldest of the others.
        assert_eq!(victims_before_register(&[a, b, mine], &mine, 2), vec![a]);
    }

    #[test]
    fn the_trim_after_register_keeps_the_newest_max_whoever_they_are() {
        let s = ids(4);
        let (mine, rival) = (s[0], s[1]);
        // The rival registered after this login: this login is the surplus.
        assert_eq!(victims_after_register(&[mine, rival], 1), &[mine]);
        assert!(victims_after_register(&[rival, mine], 1).contains(&rival));
        assert!(victims_after_register(&[mine], 1).is_empty());
    }
}
