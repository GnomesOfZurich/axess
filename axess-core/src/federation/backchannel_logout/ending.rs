//! Ending the sessions a validated logout token names: the one its `sid`
//! maps to, or those of its `sub` that the issuer established.

use super::{BackChannelLogoutHandler, LogoutTokenClaims, SidKey, loggable};
use crate::authn::ids::UserId;
use crate::session::id::SessionId;

/// What the token's `sid` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SidOutcome {
    /// The token has no `sid`, or it maps to no session: the `sub` decides.
    Unmapped,
    /// The session the `sid` maps to ended.
    Ended,
    /// The `sid` maps to a session the registry could not end.
    Failed,
}

impl BackChannelLogoutHandler {
    /// End the session the token's `sid` maps to, if it maps to one.
    pub(super) async fn end_by_sid(&self, claims: &LogoutTokenClaims) -> SidOutcome {
        let Some(ref sid) = claims.sid else {
            return SidOutcome::Unmapped;
        };
        let key: SidKey = (claims.iss.clone(), sid.clone());
        let Some((user_id, session_id, _inserted_at)) = self.sid_map.get(&key) else {
            if claims.sub.is_none() {
                tracing::warn!(
                    iss = %loggable(&claims.iss),
                    "back-channel logout: sid not found in sid map and no sub to fall back to"
                );
            }
            return SidOutcome::Unmapped;
        };
        tracing::info!(
            iss = %loggable(&claims.iss),
            user_id = %user_id,
            "back-channel logout: invalidating session by OIDC sid"
        );
        // The mapping goes only if it still names this session; a login that
        // re-mapped the sid meanwhile keeps its own.
        let ended = self
            .end_one(&claims.iss, "sid", &user_id, &session_id, || {
                self.sid_map.remove_if(&key, |entry| entry.1 == session_id);
            })
            .await;
        if ended {
            SidOutcome::Ended
        } else {
            SidOutcome::Failed
        }
    }

    /// End every session of the token's `sub` that its issuer established.
    /// Returns whether the registry failed to end one.
    pub(super) async fn end_by_sub(&self, claims: &LogoutTokenClaims) -> bool {
        let Some(ref sub) = claims.sub else {
            return false;
        };
        let owned = self.sid_map.subject_sessions(&claims.iss, sub);
        if owned.is_empty() {
            tracing::warn!(
                iss = %loggable(&claims.iss),
                "back-channel logout: no session of this subject was established \
                 through this issuer; ignoring sub"
            );
        }
        let mut failed = false;
        for (user_id, session_id) in owned {
            let ended = self
                .end_one(&claims.iss, "sub", &user_id, &session_id, || {
                    self.sid_map.remove_session(&session_id);
                })
                .await;
            failed |= !ended;
        }
        failed
    }

    /// End one session in the registry. Once the registry confirms, drop its
    /// mappings with `drop_mapping` and report it to the audit hook; when the
    /// registry fails, leave the mappings for the IdP's retry and log it.
    /// Returns whether the session ended.
    async fn end_one(
        &self,
        iss: &str,
        by: &'static str,
        user_id: &UserId,
        session_id: &SessionId,
        drop_mapping: impl FnOnce(),
    ) -> bool {
        match self.registry.invalidate_session(user_id, session_id).await {
            Ok(()) => {
                drop_mapping();
                self.report_ended(iss, user_id, session_id).await;
                true
            }
            Err(e) => {
                tracing::warn!(
                    iss = %loggable(iss),
                    by,
                    error = %e,
                    "back-channel logout: the registry did not end a session; answering retryable"
                );
                false
            }
        }
    }
}
