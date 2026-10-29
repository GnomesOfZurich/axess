//! The sessions one login owes an end to, held so that no way out of the
//! login can lose them.
//!
//! `maintain_oidc_sid_map` takes mappings out of the `sid` map at once: the
//! entries aged past the TTL, and the mapping the login displaces. The
//! sessions behind them have to be ended too, but only later (after the
//! `Authenticated` audit row is written), so between the two there is a gap in
//! which the caller can drop the future (a client that hangs up, a timeout).
//! A session whose mapping is gone and which was never ended is out of reach
//! of any `sid` logout, for good.
//!
//! [`PendingEnds`] closes the gap. It owns what is owed; whichever way the
//! login leaves, it settles:
//!
//! - [`commit`](PendingEnds::commit): the login stands, so every owed session
//!   ends;
//! - [`refuse`](PendingEnds::refuse): the login was refused, so the displaced
//!   mapping goes back (a refused login ends nobody\'s session) and only the
//!   aged-out sessions end;
//! - dropped without either: the future was cancelled, so every owed session
//!   ends on a spawned task, which outlives the cancelled caller.
//!
//! The ending itself also runs on a spawned task, so cancelling the caller
//! while it is in flight does not abort the invalidations it started.

use super::SubjectSession;
use super::concurrent;
use crate::federation::sid_map::{DisplacedSid, SidKey, SidMap};
use crate::session::store::{SessionRegistryHandle, note_revocation};
use std::sync::Arc;

/// Sessions owed an end by one login. See the [module docs](self).
pub(super) struct PendingEnds {
    registry: Option<Arc<dyn SessionRegistryHandle>>,
    sid_map: SidMap,
    /// Aged out of the `sid` map by the TTL prune: ended whether or not the
    /// login stands.
    aged: Vec<SubjectSession>,
    /// The mapping this login displaced, and the issuer it was under: ended
    /// only if the login stands, put back if it is refused.
    displaced: Option<(SidKey, DisplacedSid)>,
    settled: bool,
}

impl PendingEnds {
    /// A holder with nothing owed yet. Without a registry nothing can be
    /// ended and nothing is ever owed.
    pub(super) fn new(registry: Option<Arc<dyn SessionRegistryHandle>>, sid_map: SidMap) -> Self {
        Self {
            registry,
            sid_map,
            aged: Vec::new(),
            displaced: None,
            settled: false,
        }
    }

    /// Owe the end of a session the TTL prune took out of the map.
    pub(super) fn age_out(&mut self, session: SubjectSession) {
        self.aged.push(session);
    }

    /// Owe the displaced mapping, to be ended or restored.
    pub(super) fn displace(&mut self, key: SidKey, displaced: DisplacedSid) {
        self.displaced = Some((key, displaced));
    }

    /// The login stands: end every owed session.
    pub(super) async fn commit(mut self) {
        self.settled = true;
        let mut owed = std::mem::take(&mut self.aged);
        if let Some((key, displaced)) = self.displaced.take() {
            owed.push((key.0, displaced.user, displaced.session));
        }
        self.end(owed).await;
    }

    /// The login was refused: put the displaced mapping back and end only the
    /// sessions that aged out.
    pub(super) async fn refuse(mut self) {
        self.settled = true;
        if let Some((key, displaced)) = self.displaced.take() {
            let session = displaced.session;
            if self.sid_map.restore_if_vacant(key.clone(), displaced) {
                tracing::debug!(
                    iss = %key.0,
                    "sid_map: put back the mapping a refused login had displaced"
                );
            } else {
                tracing::debug!(
                    iss = %key.0,
                    session = %session,
                    "sid_map: the displaced mapping was not put back (key taken or session ended)"
                );
            }
        }
        let owed = std::mem::take(&mut self.aged);
        self.end(owed).await;
    }

    /// End `sessions` on a spawned task and wait for it. The task is not tied
    /// to this future: if the caller drops it while waiting, the task still
    /// finishes.
    async fn end(&self, sessions: Vec<SubjectSession>) {
        let Some(registry) = self.registry.clone() else {
            return;
        };
        if sessions.is_empty() {
            return;
        }
        let task = tokio::spawn(end_sessions(registry, self.sid_map.clone(), sessions));
        if let Err(e) = task.await {
            tracing::error!(error = %e, "ending the sessions a login owed failed");
        }
    }
}

impl Drop for PendingEnds {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // Dropped unsettled: the login future was cancelled. Whether it would
        // have stood is unknowable, and the mappings are already out of the
        // map, so the sessions end rather than stay unreachable.
        let mut owed = std::mem::take(&mut self.aged);
        if let Some((key, displaced)) = self.displaced.take() {
            owed.push((key.0, displaced.user, displaced.session));
        }
        let Some(registry) = self.registry.take() else {
            return;
        };
        if owed.is_empty() {
            return;
        }
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(end_sessions(registry, self.sid_map.clone(), owed));
            }
            Err(_) => tracing::error!(
                owed = owed.len(),
                "a cancelled OAuth login owed session ends and no runtime is left to run them"
            ),
        }
    }
}

/// End each session in the registry, concurrently within the bound, and forget
/// each in the subject registry.
async fn end_sessions(
    registry: Arc<dyn SessionRegistryHandle>,
    sid_map: SidMap,
    sessions: Vec<SubjectSession>,
) {
    let ended = concurrent::bounded(sessions, |(_, user, session)| {
        let registry = Arc::clone(&registry);
        async move {
            note_revocation(
                registry.invalidate_session(&user, &session).await,
                "ending a displaced OAuth session",
            );
        }
    })
    .await;
    for ((issuer, user, session), ()) in ended {
        sid_map.forget_subject_session(&issuer, &user, &session);
    }
}
