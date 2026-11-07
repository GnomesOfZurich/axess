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
    /// The `sid` maps to a session the registry could not end, or the store
    /// could not be read.
    Failed,
}

/// What the token's `sub` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SubOutcome {
    /// The registry, or the store, failed for at least one session.
    pub(super) failed: bool,
    /// How many sessions of the subject the store listed for the verifying
    /// tenant.
    pub(super) found: usize,
}

impl BackChannelLogoutHandler {
    /// End the session the token's `sid` maps to, if it maps to one.
    pub(super) async fn end_by_sid(&self, claims: &LogoutTokenClaims) -> SidOutcome {
        let Some(ref sid) = claims.sid else {
            return SidOutcome::Unmapped;
        };
        let key: SidKey = (claims.iss.clone(), sid.clone());
        // Only a mapping recorded for the tenant whose provider verified the
        // token is this token's to end.
        let found = match self.sid_map.get(&key, claims.tenant.as_ref()).await {
            Ok(found) => found,
            Err(e) => {
                tracing::warn!(
                    iss = %loggable(&claims.iss),
                    error = %e,
                    "back-channel logout: the sid store could not be read; answering retryable"
                );
                return SidOutcome::Failed;
            }
        };
        let Some((user_id, session_id, _inserted_at)) = found else {
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
        if !self
            .invalidate(&claims.iss, "sid", &user_id, &session_id)
            .await
        {
            return SidOutcome::Failed;
        }
        // The mapping goes only if it still names this session; a login that
        // re-mapped the sid meanwhile keeps its own.
        if let Err(e) = self.sid_map.remove_if_session(&key, &session_id).await {
            tracing::warn!(error = %e, "back-channel logout: the mapping was not removed");
        }
        self.report_ended(&claims.iss, &user_id, &session_id).await;
        SidOutcome::Ended
    }

    /// End every session of the token's `sub` that its issuer established.
    pub(super) async fn end_by_sub(&self, claims: &LogoutTokenClaims) -> SubOutcome {
        let Some(ref sub) = claims.sub else {
            return SubOutcome {
                failed: false,
                found: 0,
            };
        };
        let owned = match self
            .sid_map
            .subject_sessions(&claims.iss, sub, claims.tenant.as_ref())
            .await
        {
            Ok(owned) => owned,
            Err(e) => {
                tracing::warn!(
                    iss = %loggable(&claims.iss),
                    error = %e,
                    "back-channel logout: the sid store could not be read; answering retryable"
                );
                return SubOutcome {
                    failed: true,
                    found: 0,
                };
            }
        };
        if owned.is_empty() {
            tracing::warn!(
                iss = %loggable(&claims.iss),
                "back-channel logout: no session of this subject was established \
                 through this issuer; ignoring sub"
            );
        }
        let found = owned.len();
        let mut failed = false;
        for (user_id, session_id) in owned {
            if self
                .invalidate(&claims.iss, "sub", &user_id, &session_id)
                .await
            {
                if let Err(e) = self.sid_map.remove_session(&session_id).await {
                    tracing::warn!(error = %e, "back-channel logout: the mappings were not removed");
                }
                self.report_ended(&claims.iss, &user_id, &session_id).await;
            } else {
                failed = true;
            }
        }
        SubOutcome { failed, found }
    }

    /// End one session in the registry. When the registry fails, leave the
    /// mappings for the IdP's retry and log it. Returns whether the session
    /// ended.
    async fn invalidate(
        &self,
        iss: &str,
        by: &'static str,
        user_id: &UserId,
        session_id: &SessionId,
    ) -> bool {
        match self.registry.invalidate_session(user_id, session_id).await {
            Ok(()) => true,
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
