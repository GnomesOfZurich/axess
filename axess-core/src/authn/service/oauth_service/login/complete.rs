//! Step 3 of the OAuth/OIDC login ceremony: `complete_oauth_login`.
//!
//! Verifies the claim-binding lock minted by `finish_oauth_login`,
//! enforces the expected-tenant rail, flips the session to
//! Authenticated, registers it in the session registry, and installs
//! the OIDC `sid` → local-session mapping for back-channel logout.

use super::helpers::compute_claim_lock;
use crate::authn::service::{AuthnService, RequestAuthnService};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    factor::FactorKind,
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;
use crate::session::store::SessionLiveness;
use crate::session::store::note_revocation;
use subtle::ConstantTimeEq;

mod concurrent;
mod pending_ends;

#[cfg(test)]
mod audit_failure;
#[cfg(test)]
mod cancellation;
#[cfg(test)]
mod concurrency;
#[cfg(test)]
mod sid_map_upkeep;
#[cfg(test)]
mod subject_registry;

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Verify the single-use claim-binding lock minted by
    /// `finish_oauth_login`.
    ///
    /// Atomically takes the stashed lock value from the session
    /// (single-use semantics: a replay of `complete_oauth_login` with
    /// the same session can't satisfy the check twice) and constant-
    /// time compares against the value recomputed from the claims and
    /// current session id. A caller that bypassed `finish_oauth_login`
    /// (calling `complete` directly with attacker-supplied `User` /
    /// `OAuthClaims`) cannot satisfy this check because the session
    /// won't carry a matching lock.
    async fn verify_oauth_claim_lock(
        &self,
        user: &crate::authn::types::User,
        claims: &axess_factors::oauth::OAuthClaims,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        use axess_factors::oauth::types::keys as oauth_keys;
        let stashed_lock = session
            .take_custom(oauth_keys::CLAIM_LOCK)
            .await
            .and_then(|v| v.as_str().map(str::to_owned));
        let expected_lock =
            compute_claim_lock(claims.provider.as_ref(), &claims.subject, session).await;
        match stashed_lock {
            Some(s) if bool::from(s.as_bytes().ct_eq(expected_lock.as_bytes())) => Ok(()),
            _ => {
                tracing::warn!(
                    user_id = %user.id,
                    provider = %claims.provider,
                    "complete_oauth_login claim_lock missing or mismatched; \
                     refusing (caller likely bypassed finish_oauth_login)"
                );
                Err(AuthnError::NoFlow)
            }
        }
    }

    /// Enforce the expected-tenant rail when the begin-side
    /// stashed one.
    ///
    /// Closes the gap where a buggy claims→user resolver returns a
    /// user from a different tenant (common when the same external
    /// email exists in two tenants and the resolver searches by
    /// email alone). The check is no-op when no expectation was
    /// stashed (e.g. tenant-agnostic begin path).
    async fn enforce_oauth_expected_tenant(
        &self,
        user: &crate::authn::types::User,
        claims: &axess_factors::oauth::OAuthClaims,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        use axess_factors::oauth::types::keys as oauth_keys;
        if let Some(serde_json::Value::String(expected)) =
            session.get_custom(oauth_keys::EXPECTED_TENANT).await
            && user.tenant_id.to_string() != expected
        {
            tracing::warn!(
                user_id = %user.id,
                user_tenant = %user.tenant_id,
                expected_tenant = %expected,
                provider = %claims.provider,
                "OAuth completion refused; resolved user is in a different tenant than begin_oauth_login_in_tenant declared"
            );
            return Err(AuthnError::CrossTenant);
        }
        Ok(())
    }

    /// Register the now-Authenticated session in
    /// the session registry, or clear the session and refuse.
    ///
    /// The register call MUST come before any other store call: the
    /// session has already been flipped to Authenticated; if we
    /// error out before register runs, `invalidate_user` would have
    /// no way to evict this session and it would be authenticated
    /// but un-trackable. Mirrors the ordering used by the
    /// core factor flow's `complete_factor_step`.
    ///
    /// On register failure the session is cleared so the
    /// user does not walk away with an Authenticated cookie that
    /// the registry never saw; the cookie would otherwise survive
    /// a `logout` (or `invalidate_user`) because the registry has
    /// no record of the session id.
    async fn register_oauth_session_or_clear(
        &self,
        user: &crate::authn::types::User,
        claims: &axess_factors::oauth::OAuthClaims,
        session: &AuthSession,
        sid: &crate::session::id::SessionId,
    ) -> Result<(), AuthnError<I::Error>> {
        let Some(reg) = &self.inner.registry else {
            return Ok(());
        };

        if !reg.register(&user.id, sid).await {
            tracing::error!(
                user_id = %user.id,
                tenant_id = %user.tenant_id,
                provider = %claims.provider,
                "complete_oauth_login register failed; clearing session and refusing"
            );
            session.clear().await;
            return Err(AuthnError::NoFlow);
        }

        // Re-read account status AFTER registering so a concurrent
        // `suspend_user` that fired `invalidate_user` between the
        // application's claims-resolver and this point can't survive
        // as an Authenticated OAuth session. Without this check, an
        // invalidate that ran when no session was registered yet
        // would be effectively undone by a subsequent register.
        // `effective_at(now)` ends a timed suspension whose `until` has passed,
        // the same reading every login-time status decision uses.
        let status = self
            .inner
            .identity
            .account_status(&user.id)
            .await
            .map(|status| status.effective_at(self.inner.clock.now()));
        match status {
            Ok(status) if !status.allows_login() => {
                tracing::warn!(
                    user_id = %user.id,
                    tenant_id = %user.tenant_id,
                    provider = %claims.provider,
                    status = ?status,
                    "OAuth completion: account status flipped to non-loginable \
                     mid-flow; revoking just-registered session and refusing"
                );
                note_revocation(
                    reg.invalidate_session(&user.id, sid).await,
                    "refusing an OAuth login",
                );
                session.clear().await;
                self.inner.metrics.account_locked();
                Err(match status {
                    crate::authn::types::EntityState::Suspended(detail) => AuthnError::Locked {
                        until: detail.until,
                    },
                    other => AuthnError::NotActive(other),
                })
            }
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::warn!(
                    user_id = %user.id,
                    error = %e,
                    "OAuth post-register status re-check failed; failing closed"
                );
                note_revocation(
                    reg.invalidate_session(&user.id, sid).await,
                    "refusing an OAuth login",
                );
                session.clear().await;
                Err(AuthnError::Store(e))
            }
        }
    }

    /// Maintain the `(issuer, oidc_sid)` → local-session
    /// mapping that powers OIDC back-channel logout by `sid`.
    ///
    /// **Skipped entirely** when no session registry is configured (nothing
    /// could be ended, and the entries would never be forgotten). The `sid`
    /// mapping alone is skipped when `claims.oidc_sid` is missing (non-OIDC
    /// OAuth flow) or exceeds the length cap (compromised IdP
    /// returning an inflated `sid` claim; without the cap each OAuth
    /// login would amortize that length into permanent map memory).
    /// The subject registry is filled in either case, so back-channel logout
    /// by `sub` still works.
    ///
    /// Returns what the pruning and the swap took out of the map, as
    /// [`PendingEnds`](pending_ends::PendingEnds): the caller settles it once
    /// the audit row is written (`commit` when the login stands, `refuse`
    /// when it does not, which puts the displaced mapping back), and a caller
    /// that is dropped first still gets the sessions ended.
    ///
    /// Strategy when an entry would be inserted:
    /// 1. **TTL prune**: drop entries older than `SID_MAP_TTL` (24h) and
    ///    return their sessions to be ended, at most `PRUNE_BATCH` per call so one login
    ///    never waits on an unbounded run of registry calls; a backlog
    ///    drains over the logins that follow. The entries come off the
    ///    front of an insertion-ordered queue, so the cost is the number
    ///    pruned, not the size of the map.
    /// 2. **Capacity evict**: if at/over `self.inner.sid_map_capacity`
    ///    (default `DEFAULT_SID_MAP_CAPACITY = 10 000`; override via
    ///    [`AuthnServiceBuilder::with_sid_map_capacity`]) after the prune,
    ///    drop the `EVICT_BATCH` oldest mappings from the same queue. Only
    ///    the mapping goes: the user's session stays valid, and a logout
    ///    from the IdP for that `sid` finds nothing under its key. The
    ///    subject registry entry goes only if the session is already gone,
    ///    so a logout token that carries a `sub` as well still ends it.
    /// 3. **Atomic swap**: the insert returns any displaced mapping under
    ///    the same lock. The displaced session is returned to be ended.
    ///    Doing the swap atomically (not
    ///    `remove()` then `insert()`) closes the window where a
    ///    concurrent OAuth completion for the same
    ///    `(issuer, oidc_sid)` could be silently overwritten.
    async fn maintain_oidc_sid_map(
        &self,
        user: &crate::authn::types::User,
        claims: &axess_factors::oauth::OAuthClaims,
        sid: &crate::session::id::SessionId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> pending_ends::PendingEnds {
        use crate::federation::sid_map::SidKey;

        // Holds what the steps below owe an end to from the moment they
        // take it out of the map, so that dropping this future at any
        // await loses none of it.
        let mut pending =
            pending_ends::PendingEnds::new(self.inner.registry.clone(), self.inner.sid_map.clone());

        // Without a session registry no session is registered anywhere a
        // logout could end it, so a mapping or a subject entry would only
        // accumulate: neither is recorded.
        if self.inner.registry.is_none() {
            return pending;
        }

        // Cap oidc_sid length. A compromised IdP can return
        // an arbitrarily long `sid` claim; without a cap, every OAuth
        // login under that IdP would inflate sid_map memory by the
        // chosen length. 256 bytes matches the rate-limit
        // `MAX_KEY_LEN` cap and is well above any realistic OIDC
        // session id (typically <64 chars).
        const MAX_OIDC_SID_BYTES: usize = 256;
        // Capacity cap is per-service configurable via
        // `AuthnServiceBuilder::with_sid_map_capacity` (default
        // `DEFAULT_SID_MAP_CAPACITY = 10_000`). High-throughput OAuth
        // deployments raise it so legitimate concurrent OIDC sessions
        // do not trip the batch-eviction path and lose back-channel
        // logout precision on the evicted mappings.
        let max_sid_map_entries = self.inner.sid_map_capacity;
        const SID_MAP_TTL: chrono::TimeDelta = chrono::TimeDelta::hours(24);
        const EVICT_BATCH: usize = 128;
        const PRUNE_BATCH: usize = 128;

        let issuer = self
            .inner
            .oauth_providers
            .get(claims.provider.as_ref())
            .and_then(|p| p.issuer().map(|s| s.to_string()))
            .unwrap_or_else(|| claims.provider.to_string());

        // Every login enters the subject registry, with or without a `sid`,
        // so a logout by `sub` alone can always find the session.
        self.inner
            .sid_map
            .register_subject_session(&issuer, &claims.subject, user.id, *sid);
        self.sweep_subject_registry().await;

        let Some(oidc_sid) = claims.oidc_sid.as_ref().filter(|s| {
            if s.len() > MAX_OIDC_SID_BYTES {
                tracing::warn!(
                    provider = %claims.provider,
                    oidc_sid_len = s.len(),
                    "oidc_sid exceeds {MAX_OIDC_SID_BYTES} bytes; skipping sid_map entry \
                     (back-channel logout by `sid` will not work for this session; `sub` still works)"
                );
                false
            } else {
                true
            }
        }) else {
            return pending;
        };

        let key: SidKey = (issuer.clone(), oidc_sid.clone());

        // Phase 1: TTL prune, bounded per call.
        let cutoff = now - SID_MAP_TTL;
        for (evict_key, (evict_user, evict_sid, _)) in self
            .inner
            .sid_map
            .evict_inserted_before(cutoff, PRUNE_BATCH)
        {
            tracing::debug!(
                evicted_iss = %evict_key.0,
                evicted_oidc_sid = %evict_key.1,
                "sid_map: evicted stale entry (TTL expired)"
            );
            pending.age_out((evict_key.0, evict_user, evict_sid));
        }

        // Phase 2: capacity-based batch eviction. Drops the mapping only;
        // the user's session is still valid. The subject registry keeps a
        // live session reachable by `sub`; only a session the registry
        // reports gone is forgotten there, never one whose liveness it could
        // not answer. The liveness checks of the batch run concurrently.
        if self.inner.sid_map.len() >= max_sid_map_entries {
            let evicted = self.inner.sid_map.evict_oldest(EVICT_BATCH);
            for (evict_key, (evict_user, _, _)) in &evicted {
                tracing::warn!(
                    evicted_iss = %evict_key.0,
                    evicted_oidc_sid = %evict_key.1,
                    user_id = %evict_user,
                    "sid_map capacity reached; dropped oldest mapping (its session stays valid \
                 and a logout by `sub` still reaches it)"
                );
            }
            let candidates = evicted
                .into_iter()
                .map(|(key, (user, session, _))| (key.0, user, session))
                .collect();
            self.forget_gone_subject_sessions(candidates).await;
        }

        // Atomic swap with displaced-mapping invalidation.
        let displaced =
            self.inner
                .sid_map
                .insert_displacing(key.clone(), &claims.subject, user.id, *sid, now);
        if let Some(displaced) = displaced {
            tracing::warn!(
                iss = %issuer,
                oidc_sid = %oidc_sid,
                old_user = %displaced.user,
                "SidMap atomic swap displaced existing mapping; invalidating old session"
            );
            pending.displace(key, displaced);
        }
        pending
    }

    /// Ask the registry about each `(issuer, user, session)`, concurrently,
    /// and forget in the subject registry those it reports gone. A session
    /// whose liveness the registry could not answer stays.
    async fn forget_gone_subject_sessions(&self, candidates: Vec<SubjectSession>) {
        let Some(reg) = &self.inner.registry else {
            return;
        };
        let answers = concurrent::bounded(candidates, |(_, user, session)| {
            let reg = std::sync::Arc::clone(reg);
            async move { reg.liveness(&user, &session).await }
        })
        .await;
        for ((issuer, user, session), liveness) in answers {
            if liveness == SessionLiveness::Gone {
                self.inner
                    .sid_map
                    .forget_subject_session(&issuer, &user, &session);
            }
        }
    }

    /// Check a bounded batch of the subject registry against the session
    /// registry and forget the sessions that are gone, so sessions that ended
    /// by expiry or logout do not accumulate. Live sessions stay, and so do
    /// sessions whose liveness the registry could not answer. Without a
    /// registry nothing can be judged and nothing is forgotten.
    async fn sweep_subject_registry(&self) {
        const SWEEP_BATCH: usize = 64;
        if self.inner.registry.is_none() {
            return;
        }
        let candidates = self.inner.sid_map.sweep_subject_candidates(SWEEP_BATCH);
        self.forget_gone_subject_sessions(candidates).await;
    }
}

/// `(issuer, local user, session)`: one entry of the subject registry.
type SubjectSession = (
    String,
    crate::authn::ids::UserId,
    crate::session::id::SessionId,
);

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Complete an OAuth login by linking claims to a local user and
    /// establishing an authenticated session.
    ///
    /// OAuth uses a three-step flow (unlike the two-step core and FIDO2 flows):
    /// 1. `begin_oauth_login`: redirect the user to the IdP
    /// 2. `finish_oauth_login`: handle the callback, get `OAuthClaims`
    /// 3. `complete_oauth_login`: the application resolves the local `User`
    ///    from the claims (find or create), then calls this to establish the
    ///    session. This step is separate because user resolution is
    ///    application-specific logic that the library cannot perform.
    #[tracing::instrument(skip(self, user, claims, session))]
    pub async fn complete_oauth_login(
        &self,
        user: &crate::authn::types::User,
        claims: &axess_factors::oauth::OAuthClaims,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        // Pre-flip checks: claim-lock binding + tenant rail.
        // Both refuse before mutating session state so a
        // bypass attempt never produces a partially-completed login.
        self.verify_oauth_claim_lock(user, claims, session).await?;
        let tenant_check = self
            .enforce_oauth_expected_tenant(user, claims, session)
            .await;
        // The binding is single-use: gone whether the check passed or not.
        super::state::remove_expected_tenant(session).await;
        tenant_check?;

        // The tenant's own gates, as `begin_login` runs them: its status and
        // its IP policy. The OAuth completion used to skip both, so a user
        // of a suspended tenant still logged in through an IdP.
        if let std::ops::ControlFlow::Break(_) = self
            .admit_tenant_by_id(&user.identifier, &user.tenant_id)
            .await?
        {
            tracing::warn!(
                user_id = %user.id,
                tenant_id = %user.tenant_id,
                provider = %claims.provider,
                "OAuth completion refused; the tenant does not admit logins"
            );
            return Err(AuthnError::CrossTenant);
        }

        let now = self.inner.clock.now();
        session
            .set_authenticated_keeping(
                user.id,
                user.tenant_id,
                now,
                &self.inner.preserved_custom_keys,
            )
            .await;
        let sid = session.session_id().await;

        // Post-flip session-binding work: register-or-clear MUST come
        // first because the session is already Authenticated;
        // subsequent fail-soft operations may log on outage but
        // cannot bubble Err here without leaking an un-trackable
        // Authenticated session to the caller.
        self.register_oauth_session_or_clear(user, claims, session, &sid)
            .await?;

        // reset_failed_attempts must NOT propagate as Err(Store).
        // The session is already authenticated and registered; failing
        // the request now would leave behind a tracked authenticated
        // session with no way to deliver the response cookie.
        // Log + continue.
        if let Err(e) = self.inner.identity.reset_failed_attempts(&user.id).await {
            tracing::warn!(
                user_id = %user.id,
                error = %e,
                "failed to reset failed-attempt counter post-OAuth; \
                 proceeding (counter will reset on next successful login)"
            );
        }

        // Maintain the (issuer, oidc_sid) → local
        // session mapping that powers OIDC back-channel logout by
        // `sid`. Self-contained; see helper for the TTL-prune /
        // capacity-evict / atomic-swap-with-displaced-invalidation
        // sequence.
        let pending = self.maintain_oidc_sid_map(user, claims, &sid, now).await;

        let emitted = self
            .emit_audit_at(
                AuthEventBuilder::success(AuthEventType::Authenticated)
                    .attributed_to(&user.id, &user.tenant_id)
                    .with_factor(FactorKind::Federated(
                        crate::authn::factor::FederatedProvider::Custom(
                            claims.provider.to_string(),
                        ),
                    ))
                    .with_session(sid),
                now,
            )
            .await;
        if let Err(e) = emitted {
            // The login is refused, so nothing of it may stay reachable:
            // not the registry entry, not the session state, and not the
            // back-channel `sid` mapping installed above.
            self.inner.sid_map.remove_session(&sid);
            // The mapping this login displaced goes back (its user must stay
            // reachable by a logout for that `sid`), and only the sessions
            // that aged out are ended.
            pending.refuse().await;
            self.end_session_after_audit_failure(&user.id, session)
                .await;
            return Err(e);
        }

        // The login stands, so the sessions it displaced or aged out of the
        // map end now; a refused login would have ended nobody's.
        pending.commit().await;

        Ok(())
    }
}
