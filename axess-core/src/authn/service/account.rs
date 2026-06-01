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
//! This `mod.rs` itself only carries the **internal helpers** that
//! support the multi-factor login path
//! ([`AuthnService::complete_factor_step`]) and the scope-fallback
//! lookup ([`AuthnService::load_factor_with_fallback`]) that
//! `service::login` and `service::fido2_service` consume. They live
//! under `account/` for historical reasons and are `pub(crate)`-scoped.

mod admin;
mod impersonation;
mod password_reset;
mod signup;

use crate::authn::service::AuthnService;
use crate::authn::service::outcomes::FactorOutcome;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    factor::{FactorConfig, FactorKind},
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};
use crate::session::extractor::AuthSession;

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Load a factor config, trying User → Tenant → Global scope in order.
    pub(crate) async fn load_factor_with_fallback(
        &self,
        user_scope: &AuthnScope,
        tenant_id: &crate::authn::ids::TenantId,
        kind: FactorKind,
    ) -> Result<FactorConfig, AuthnError<I::Error>> {
        if let Some(cfg) = self
            .factors
            .load_factor(user_scope, kind.clone())
            .await
            .map_err(AuthnError::Store)?
        {
            return Ok(cfg);
        }
        let tenant_scope = AuthnScope::Tenant(*tenant_id);
        if let Some(cfg) = self
            .factors
            .load_factor(&tenant_scope, kind.clone())
            .await
            .map_err(AuthnError::Store)?
        {
            return Ok(cfg);
        }
        self.factors
            .load_factor(&AuthnScope::Global, kind)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)
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

            // Register in the session registry BEFORE any other store
            // calls. The session has already transitioned to Authenticated in
            // `advance_factor`; if the registry register is skipped because a
            // subsequent call errored out early, `invalidate_user` would have
            // no way to evict this session; it would be authenticated but
            // un-trackable. Register first so the session is always reachable
            // by the eviction path even if subsequent steps fail.
            if let Some(reg) = &self.registry {
                // Enforce concurrent session limit: evict oldest sessions.
                if let Some(max) = self.max_sessions_per_user {
                    let active = reg.active_sessions(user_id).await;
                    if active.len() >= max {
                        let to_evict = active.len() - max + 1;
                        for old_sid in active.iter().take(to_evict) {
                            reg.invalidate_session(user_id, old_sid).await;
                            tracing::info!(
                                user_id = %user_id,
                                evicted_session = %old_sid,
                                "concurrent session limit reached; evicting oldest session"
                            );
                            self.metrics.session_invalidated();
                        }
                    }
                }
                // Register-failure must clear the session and
                // refuse authentication. Without this, the just-set
                // Authenticated state would ride out as a cookie that
                // `invalidate_user` cannot reach.
                if !reg.register(user_id, &sid).await {
                    tracing::error!(
                        user_id = %user_id,
                        "complete_factor_step register failed; clearing session and \
                         refusing authentication"
                    );
                    session.clear().await;
                    return Err(AuthnError::NoFlow);
                }

                // Re-read account status AFTER registering. Closes the
                // race where a concurrent `suspend_user` call lands its
                // status-update + `invalidate_user` between this function's
                // initial status check (in `verify_factor`) and the register
                // above; without this re-check, the just-registered session
                // would survive the suspension as if the suspend never happened.
                match self.identity.account_status(user_id).await {
                    Ok(status) if !status.allows_login() => {
                        tracing::warn!(
                            user_id = %user_id,
                            status = ?status,
                            "account status flipped to non-loginable mid-flow; \
                             revoking just-registered session and refusing authentication"
                        );
                        reg.invalidate_session(user_id, &sid).await;
                        // Wipe the in-memory session state so the response cookie
                        // does not ship a Set-Cookie for an authenticated session.
                        session.clear().await;
                        self.metrics.account_locked();
                        let until =
                            if let crate::authn::types::EntityState::Suspended(detail) = &status {
                                detail.until
                            } else {
                                None
                            };
                        return Ok(FactorOutcome::Locked { until });
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
                        reg.invalidate_session(user_id, &sid).await;
                        session.clear().await;
                        return Err(AuthnError::Store(e));
                    }
                }
            }

            // Reset the failed-attempt counter AFTER registry register
            // and AFTER the status re-check above. If this errors, the
            // session is already authenticated, registered, and tracked; log
            // the error and continue. Worst case the counter stays elevated;
            // the next successful login will reset it. The alternative (fail
            // the request) would leave behind an authenticated registered
            // session with no way to reach it through the response.
            if let Err(e) = self.identity.reset_failed_attempts(user_id).await {
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
            self.emit_audit(event_builder).await;

            // Record last login time for compliance/audit.
            if let Err(e) = self
                .identity
                .record_last_login(user_id, self.clock.now())
                .await
            {
                tracing::error!(error = %e, "failed to record last login");
            }

            self.metrics.auth_success();
            return Ok(FactorOutcome::Authenticated);
        }

        // More factors remain; return the next kind.
        let next_kind = match &new_state {
            crate::session::data::AuthState::Authenticating { remaining, .. } => {
                remaining.first().cloned()
            }
            _ => None,
        };

        Ok(next_kind.map_or(FactorOutcome::Authenticated, FactorOutcome::FactorRequired))
    }
}
