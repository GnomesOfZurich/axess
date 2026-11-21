//! Ending the sessions a validated logout token names: the one its `sid`
//! maps to, or those of its `sub` that the issuer established.
//!
//! The sid store holds the key each login registered. A rotation since (a
//! step-up, `rotate_session`, `regenerate`) moved the session to a new key,
//! and the registry answers for the key it held before: it follows the
//! move both when asked which key the session is under now and when asked
//! to end it. A session the registry holds under no key has ended already,
//! so nothing is ended or reported for it: a logout reports only an ending
//! that happened.

use super::{BackChannelLogoutHandler, LogoutTokenClaims, SidKey, loggable};
use crate::authn::ids::UserId;
use crate::session::id::SessionKey;

/// What the token's `sid` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SidOutcome {
    /// The token has no `sid`, or it maps to no session: the `sub` decides.
    Unmapped,
    /// The session the `sid` maps to ended.
    Ended,
    /// The `sid` maps to a session the registry could not end or could not
    /// be asked about, or the store could not be read.
    Failed,
}

/// What asking the registry to end one session did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// The registry held the session and ended it.
    Ended,
    /// The registry holds no session under the key, nor under a key a move
    /// took it to: it has ended already, and nothing was asked to end.
    NotHeld,
    /// The registry could not be asked, or could not end the session.
    Failed,
}

/// What the token's `sub` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SubOutcome {
    /// The registry, or the store, failed for at least one session.
    pub(super) failed: bool,
    /// How many sessions of the subject the store listed for the verifying
    /// tenant that the registry still held (ended, or failed to end). A
    /// listed session that had ended already is not counted: a token that
    /// ended nothing is counted as unmatched.
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
        let Some((user_id, session_id, _)) = found else {
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
        match self
            .invalidate(&claims.iss, "sid", &user_id, &session_id)
            .await
        {
            Ending::Ended => {}
            Ending::Failed => return SidOutcome::Failed,
            Ending::NotHeld => {
                // Gone already: the mapping goes so the sid is not looked
                // up again, nothing is reported, and the `sub` decides.
                if let Err(e) = self.sid_map.remove_if_session(&key, &session_id).await {
                    tracing::warn!(error = %e, "back-channel logout: the mapping was not removed");
                }
                return SidOutcome::Unmapped;
            }
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
        let (mut found, mut failed) = (0, false);
        for (user_id, session_id) in owned {
            let ending = self
                .invalidate(&claims.iss, "sub", &user_id, &session_id)
                .await;
            if ending == Ending::Failed {
                found += 1;
                failed = true;
                continue;
            }
            // Ended, or gone already: either way the records go.
            if let Err(e) = self.sid_map.remove_session(&session_id).await {
                tracing::warn!(error = %e, "back-channel logout: the mappings were not removed");
            }
            if ending == Ending::Ended {
                found += 1;
                self.report_ended(&claims.iss, &user_id, &session_id).await;
            }
        }
        SubOutcome { failed, found }
    }

    /// End one session in the registry, named by the key the sid store
    /// holds: first ask whether the registry holds the session under that
    /// key or a key a move took it to, then end it by the same key (the
    /// ending follows any move, one that lands after the question too).
    /// When the registry fails, leave the mappings for the IdP's retry and
    /// log it.
    async fn invalidate(
        &self,
        iss: &str,
        by: &'static str,
        user_id: &UserId,
        session_id: &SessionKey,
    ) -> Ending {
        let ended = match self.registry.current_key(user_id, session_id).await {
            Ok(None) => {
                tracing::debug!(
                    iss = %loggable(iss),
                    by,
                    "back-channel logout: the registry no longer holds the session; nothing to end"
                );
                return Ending::NotHeld;
            }
            Ok(Some(_)) => self.registry.invalidate_session(user_id, session_id).await,
            Err(e) => Err(e),
        };
        match ended {
            Ok(()) => Ending::Ended,
            Err(e) => {
                tracing::warn!(
                    iss = %loggable(iss),
                    by,
                    error = %e,
                    "back-channel logout: the registry did not end a session; answering retryable"
                );
                Ending::Failed
            }
        }
    }
}
