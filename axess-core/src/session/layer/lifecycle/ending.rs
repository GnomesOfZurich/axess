//! Ending a stored session the load decided to end: claim it, record the
//! ending, remove the row, in that order and in a task of its own.
//!
//! The order is what keeps the audit trail whole. The row is written before
//! the session is removed, so a session is never gone without its row; a
//! sink that fails leaves the session stored (and refused), so the next
//! request that presents it tries again. The claim comes before both, so of
//! several requests that carry the same cookie one records the ending and
//! the others record nothing. And the three steps run in a task the request
//! only waits for, so a client that disconnects between two of them does
//! not stop the third.
//!
//! The claim is the decision to end the session, and it keeps the reason.
//! A request that finds a claim older than its lease finishes that ending,
//! for that reason, whatever the session looks like by then: the audit row
//! may already be written, and a session with a row that says it ended is
//! not served again. Such an ending is never taken back. Only the request
//! that made a claim takes it back, when its own audit write failed.

use std::sync::Arc;
use std::time::Duration;

use axess_clock::Timestamp;

use crate::session::data::{EndingClaim, SessionData};
use crate::session::id::SessionKey;
use crate::session::layer::audit::{LayerSessionEnded, SessionEndAudit, SessionEndReason};
use crate::session::store::{
    ConditionalUpdate, SessionRegistryHandle, SessionStore, note_revocation,
};

/// The session `data` is, as the audit sink is told of its ending under
/// `key`: `None` for a record that is not signed in (a guest, a login in
/// progress, a pending workflow), whose ending is nobody's audit row. A
/// step-up is the signed-in session it began from, and is recorded as it.
pub(crate) fn ended_record(
    data: &SessionData,
    key: SessionKey,
    reason: SessionEndReason,
) -> Option<LayerSessionEnded> {
    // One view names the whole session: its user, the tenant it signed in
    // to and its impersonation, whether it is authenticated or in a step-up.
    let signed_in = data.auth_state.signed_in()?;
    Some(LayerSessionEnded {
        user_id: *signed_in.user_id,
        tenant_id: *signed_in.tenant_id,
        session_id: key,
        impersonator: signed_in.impersonator.map(|imp| imp.admin),
        reason,
    })
}

/// A registry entry: whose it is, and under which key.
pub(crate) type Entry = (crate::authn::ids::UserId, SessionKey);

/// The registry entries a session that ended leaves behind: its own, under
/// `key`, and for an impersonation the entry its administrator holds it by.
/// None for a session that was not signed in.
pub(crate) fn entries_left(data: &SessionData, key: SessionKey) -> Vec<Entry> {
    let Some(signed_in) = data.auth_state.signed_in() else {
        return Vec::new();
    };
    let mut entries = vec![(*signed_in.user_id, key)];
    if let Some(imp) = signed_in.impersonator {
        entries.push((imp.admin, imp.registry_anchor(signed_in.user_id)));
    }
    entries
}

/// Remove `entries` from the registry, once each: the last step of an
/// ending, which cannot undo it. Without it an ended session stays listed by
/// `active_sessions`, counted by the session limit, and a socket that
/// watches it is never told. A registry that fails is logged, as every
/// revocation is; the entry then lapses with its lifetime.
pub(crate) async fn release_entries(
    registry: Option<&dyn SessionRegistryHandle>,
    entries: &[Entry],
) {
    let Some(registry) = registry else {
        return;
    };
    let mut released: Vec<&Entry> = Vec::new();
    for entry in entries {
        if released.contains(&entry) {
            continue;
        }
        released.push(entry);
        note_revocation(
            registry.invalidate_session(&entry.0, &entry.1).await,
            "removing the registry entry of a session the layer ended",
        );
    }
}

/// What became of an ending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ended {
    /// This call ended the session: its ending is recorded and its row
    /// removed (or left claimed, when the store failed the removal).
    Done,
    /// This call ended nothing: another request holds the ending, or the
    /// row could not be claimed or the ending recorded. The row stands and
    /// the session is refused for this request.
    Deferred,
}

/// Everything the ending of a stored session needs, owned, so that it runs
/// to its end whatever becomes of the request that found the session.
pub(crate) struct StoredEnding<S> {
    pub(crate) store: S,
    pub(crate) audit: Arc<dyn SessionEndAudit>,
    /// What is ended, and how.
    pub(crate) what: Ending,
}

/// A stored session to end: the row, what the sink is told, and the terms
/// of the claim.
pub(crate) struct Ending {
    /// The row as the store holds it: its revision is what the claim
    /// compares.
    pub(crate) row: SessionData,
    pub(crate) ended: LayerSessionEnded,
    /// The layer's clock, which stamps the claim.
    pub(crate) now: Timestamp,
    pub(crate) ttl: Duration,
    /// The row already carried a claim, older than its lease: an earlier
    /// request decided this ending and did not finish it. Its audit row may
    /// already be written, so the ending is not taken back when the sink
    /// fails here; the claim this request stamps is left to lapse, and the
    /// next request that presents the session finishes it.
    pub(crate) resumed: bool,
}

/// How many times the removal of a recorded ending is asked of the store.
const REMOVAL_ATTEMPTS: usize = 2;

/// How many times a claim is taken back when concurrent writes keep moving
/// the row it is on.
const RELEASE_ATTEMPTS: usize = 3;

impl<S> StoredEnding<S>
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    /// Run the ending in a task of its own and wait for it. Dropping the
    /// caller does not stop the task.
    pub(crate) async fn run_detached(self) -> Ended {
        match tokio::spawn(self.run()).await {
            Ok(ended) => ended,
            Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
            // The runtime is shutting down: nothing is known to be ended.
            Err(_) => Ended::Deferred,
        }
    }

    async fn run(self) -> Ended {
        end_stored(&self.store, &*self.audit, self.what).await
    }
}

/// End a stored session: claim it, record the ending, remove the row. For a
/// caller that already runs in a task the request only waits for (the
/// finish of a request); the load goes through [`StoredEnding`].
pub(crate) async fn end_stored<S>(store: &S, audit: &dyn SessionEndAudit, what: Ending) -> Ended
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let Ending {
        row,
        ended,
        now,
        ttl,
        resumed,
    } = what;
    // The record names the session by the key of its row.
    let key = ended.session_id;

    // 1. The claim: of the requests that loaded this revision, one.
    let claim = EndingClaim {
        since: now,
        reason: ended.reason,
    };
    let mut claimed = row.clone();
    claimed.revision = row.revision.wrapping_add(1);
    claimed.ending = Some(claim);
    match store
        .update_if_revision(&key, row.revision, &claimed, ttl)
        .await
    {
        Ok(ConditionalUpdate::Written) => {}
        Ok(ConditionalUpdate::Conflict | ConditionalUpdate::Gone) => {
            tracing::debug!(
                "another request wrote or ended the session first; its ending is left to it"
            );
            return Ended::Deferred;
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "claiming a session to end it failed; it is refused and left for the next request"
            );
            return Ended::Deferred;
        }
    }

    // 2. The row, while the session is still stored.
    if let Err(e) = audit.session_ended(&ended).await {
        tracing::error!(
            error = %e,
            reason = ended.reason.as_str(),
            "session layer: the audit row of an ending could not be written; \
             the session is not ended"
        );
        if resumed {
            tracing::error!(
                "the ending was begun by an earlier request and may already be recorded: \
                 it is not taken back, and the next request that presents the session \
                 after the claim's lease tries again"
            );
        } else {
            release(store, &key, claim, ttl).await;
        }
        return Ended::Deferred;
    }

    // 3. The removal. The ending is recorded, so a store that fails here is
    // asked once more before the row is left to its claim.
    for attempt in 1..=REMOVAL_ATTEMPTS {
        match store.delete(&key).await {
            Ok(()) => break,
            Err(e) if attempt < REMOVAL_ATTEMPTS => {
                tracing::warn!(error = %e, "deleting an ended session failed; trying again");
            }
            Err(e) => tracing::error!(
                error = %e,
                "deleting an ended session failed; the row stays claimed and refused, and a \
                 request that presents it after the claim's lease ends and records it again"
            ),
        }
    }
    Ended::Done
}

/// Take `claim` back: the ending could not be recorded, so it is not
/// performed. Requests that were already running may have written the row
/// meanwhile (a write keeps the claim it finds), so the claim is cleared on
/// the row as it is stored now, and only while it is still this claim. A
/// claim that cannot be taken back lapses, and the next request that
/// presents the session finishes the ending.
async fn release<S>(store: &S, key: &SessionKey, claim: EndingClaim, ttl: Duration)
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    for _ in 0..RELEASE_ATTEMPTS {
        let current = match super::load_current(store, key).await {
            Ok(Some(current)) if current.ending == Some(claim) => current,
            // Gone, or under another request's claim: not this one's to
            // clear.
            Ok(_) => return,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "releasing the claim on a session failed; the claim lapses by itself"
                );
                return;
            }
        };
        let mut released = current.clone();
        released.revision = current.revision.wrapping_add(1);
        released.ending = None;
        match store
            .update_if_revision(key, current.revision, &released, ttl)
            .await
        {
            Ok(ConditionalUpdate::Written | ConditionalUpdate::Gone) => return,
            Ok(ConditionalUpdate::Conflict) => {}
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "releasing the claim on a session failed; the claim lapses by itself"
                );
                return;
            }
        }
    }
    tracing::error!(
        "releasing the claim on a session kept losing to concurrent writes; \
         the claim lapses by itself"
    );
}
