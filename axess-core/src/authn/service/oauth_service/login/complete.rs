//! Step 3 of the OAuth/OIDC login ceremony: `complete_oauth_login`.
//!
//! Verifies the claim-binding lock minted by `finish_oauth_login`,
//! enforces the expected-tenant rail, flips the session to
//! Authenticated, registers it in the session registry, and installs
//! the OIDC `sid` → local-session mapping for back-channel logout.

use super::helpers::compute_claim_lock;
use crate::authn::service::AuthnService;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    factor::FactorKind,
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;
use subtle::ConstantTimeEq;

impl<I, F> AuthnService<I, F>
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
        self.enforce_oauth_expected_tenant(user, claims, session)
            .await?;

        let now = self.clock.now();
        session
            .set_authenticated(user.id, user.tenant_id, now)
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
        if let Err(e) = self.identity.reset_failed_attempts(&user.id).await {
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
        self.maintain_oidc_sid_map(user, claims, &sid, now).await;

        self.emit_audit_at(
            AuthEventBuilder::success(AuthEventType::Authenticated)
                .attributed_to(&user.id, &user.tenant_id)
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(claims.provider.to_string()),
                ))
                .with_session(sid),
            now,
        )
        .await;

        Ok(())
    }

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
        let Some(reg) = &self.registry else {
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
        match self.identity.account_status(&user.id).await {
            Ok(status) if !status.allows_login() => {
                tracing::warn!(
                    user_id = %user.id,
                    tenant_id = %user.tenant_id,
                    provider = %claims.provider,
                    status = ?status,
                    "OAuth completion: account status flipped to non-loginable \
                     mid-flow; revoking just-registered session and refusing"
                );
                reg.invalidate_session(&user.id, sid).await;
                session.clear().await;
                self.metrics.account_locked();
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
                reg.invalidate_session(&user.id, sid).await;
                session.clear().await;
                Err(AuthnError::Store(e))
            }
        }
    }

    /// Maintain the `(issuer, oidc_sid)` → local-session
    /// mapping that powers OIDC back-channel logout by `sid`.
    ///
    /// **Skipped entirely** when `claims.oidc_sid` is missing (non-OIDC
    /// OAuth flow) or exceeds the length cap (compromised IdP
    /// returning an inflated `sid` claim; without the cap each OAuth
    /// login would amortize that length into permanent map memory).
    /// Back-channel logout by `sub` still works in either case.
    ///
    /// Strategy when an entry would be inserted:
    /// 1. **TTL prune**: drop entries older than `SID_MAP_TTL` (24h).
    ///    Steady-state cleanup so an OIDC session the IdP never
    ///    explicitly logged out eventually ages out.
    /// 2. **Capacity evict**: if at/over `MAX_SID_MAP_ENTRIES` after
    ///    TTL prune, evict a *batch* of oldest entries via a single
    ///    bounded scan. Sort + `take(BATCH)` is O(N log K) for K=128,
    ///    keeping the per-batch cost bounded under burst load.
    /// 3. **Atomic swap**: `DashMap::insert` returns any displaced
    ///    value atomically. We invalidate the displaced session in the
    ///    registry after the swap. Doing the swap atomically (not
    ///    `remove()` then `insert()`) closes the window where a
    ///    concurrent OAuth completion for the same
    ///    `(issuer, oidc_sid)` could be silently overwritten.
    async fn maintain_oidc_sid_map(
        &self,
        user: &crate::authn::types::User,
        claims: &axess_factors::oauth::OAuthClaims,
        sid: &crate::session::id::SessionId,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        use crate::federation::backchannel_logout::SidKey;

        // Cap oidc_sid length. A compromised IdP can return
        // an arbitrarily long `sid` claim; without a cap, every OAuth
        // login under that IdP would inflate sid_map memory by the
        // chosen length. 256 bytes matches the rate-limit
        // `MAX_KEY_LEN` cap and is well above any realistic OIDC
        // session id (typically <64 chars).
        const MAX_OIDC_SID_BYTES: usize = 256;
        const MAX_SID_MAP_ENTRIES: usize = 10_000;
        const SID_MAP_TTL: chrono::TimeDelta = chrono::TimeDelta::hours(24);
        const EVICT_BATCH: usize = 128;

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
            return;
        };

        let issuer = self
            .oauth_providers
            .get(claims.provider.as_ref())
            .and_then(|p| p.issuer().map(|s| s.to_string()))
            .unwrap_or_else(|| claims.provider.to_string());
        let key: SidKey = (issuer.clone(), oidc_sid.clone());

        // Phase 1: TTL prune.
        let cutoff = now - SID_MAP_TTL;
        let stale_keys: Vec<SidKey> = self
            .sid_map
            .iter()
            .filter(|e| e.value().2 < cutoff)
            .map(|e| e.key().clone())
            .collect();
        for evict_key in stale_keys {
            if let Some((_, (evict_user, evict_sid, _))) = self.sid_map.remove(&evict_key) {
                if let Some(reg) = &self.registry {
                    reg.invalidate_session(&evict_user, &evict_sid).await;
                }
                tracing::debug!(
                    evicted_iss = %evict_key.0,
                    evicted_oidc_sid = %evict_key.1,
                    "sid_map: evicted stale entry (TTL expired)"
                );
            }
        }

        // Phase 2: capacity-based batch eviction.
        if self.sid_map.len() >= MAX_SID_MAP_ENTRIES {
            let mut oldest: Vec<(chrono::DateTime<chrono::Utc>, SidKey)> = self
                .sid_map
                .iter()
                .map(|e| (e.value().2, e.key().clone()))
                .collect();
            oldest.sort_by_key(|(ts, _)| *ts);
            for (_, evict_key) in oldest.into_iter().take(EVICT_BATCH) {
                if let Some((_, (evict_user, evict_sid, _))) = self.sid_map.remove(&evict_key) {
                    if let Some(reg) = &self.registry {
                        reg.invalidate_session(&evict_user, &evict_sid).await;
                    }
                    tracing::warn!(
                        evicted_iss = %evict_key.0,
                        evicted_oidc_sid = %evict_key.1,
                        user_id = %evict_user,
                        "sid_map capacity reached; evicted oldest mapping"
                    );
                }
            }
        }

        // Atomic swap with displaced-mapping invalidation.
        let displaced = self.sid_map.insert(key, (user.id, *sid, now));
        if let Some((old_user_id, old_session_id, _)) = displaced {
            tracing::warn!(
                iss = %issuer,
                oidc_sid = %oidc_sid,
                old_user = %old_user_id,
                "SidMap atomic swap displaced existing mapping; invalidating old session"
            );
            if let Some(reg) = &self.registry {
                reg.invalidate_session(&old_user_id, &old_session_id).await;
            }
        }
    }
}
