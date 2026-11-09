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
//!
//! What a cancelled login leaves in the map is its own mapping, the one
//! `insert_displacing` put in before the login settled. That is deliberate.
//! Whether the newcomer's session lives is unknowable from here: cancelled
//! above the session layer, its row was never written and the entry points
//! at nothing; cancelled inside a handler that still returns, the layer
//! saves the row and the entry is the only way a `sid` logout reaches that
//! session. Keeping the entry costs a stale map slot that the TTL prune or
//! the capacity eviction reclaims, and that `remove_session` drops when the
//! session ends; dropping it could leave a live session unreachable. The
//! displaced session ends for the same reason read the other way: its
//! mapping is already gone, so ending it is the only way to be sure it does
//! not stay reachable by nothing.

use super::SubjectSession;
use super::concurrent;
use crate::federation::sid_map::{DisplacedSid, SidKey};
use crate::federation::sid_store::SidStore;
use crate::session::store::{SessionRegistryHandle, note_revocation};
use std::sync::Arc;
use std::time::Duration;

/// How long a refused login waits for the `sid` store to put the displaced
/// mapping back before it ends that session instead: a store that hangs must
/// not leave a live session that no `sid` logout can reach.
const RESTORE_TIMEOUT: Duration = Duration::from_secs(5);

/// Sessions owed an end by one login. See the [module docs](self).
pub(super) struct PendingEnds {
    registry: Option<Arc<dyn SessionRegistryHandle>>,
    sid_map: Arc<dyn SidStore>,
    /// Aged out of the `sid` map by the TTL prune: ended whether or not the
    /// login stands.
    aged: Vec<SubjectSession>,
    /// The mapping this login displaced, and the issuer it was under: ended
    /// only if the login stands, put back if it is refused.
    displaced: Option<(SidKey, DisplacedSid)>,
    /// How long a refused login waits for the store to put the displaced
    /// mapping back before it ends that session instead.
    restore_timeout: Duration,
    settled: bool,
}

impl PendingEnds {
    /// A holder with nothing owed yet. Without a registry nothing can be
    /// ended and nothing is ever owed.
    pub(super) fn new(
        registry: Option<Arc<dyn SessionRegistryHandle>>,
        sid_map: Arc<dyn SidStore>,
    ) -> Self {
        Self {
            registry,
            sid_map,
            aged: Vec::new(),
            displaced: None,
            restore_timeout: RESTORE_TIMEOUT,
            settled: false,
        }
    }

    /// Wait `timeout` instead of [`RESTORE_TIMEOUT`] for the store to take
    /// the displaced mapping back of a refused login.
    #[cfg(test)]
    pub(super) fn restore_timeout(mut self, timeout: Duration) -> Self {
        self.restore_timeout = timeout;
        self
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
    ///
    /// The restore and the ends run on a spawned task, handed everything
    /// that is owed before the first await: a caller cancelled while the
    /// restore is on the wire (a networked store's round trip) leaves the
    /// task running, so neither the aged-out sessions nor the displaced
    /// mapping is lost.
    pub(super) async fn refuse(mut self) {
        self.settled = true;
        let task = tokio::spawn(settle_refused(
            self.registry.clone(),
            self.sid_map.clone(),
            std::mem::take(&mut self.aged),
            self.displaced.take(),
            self.restore_timeout,
        ));
        if let Err(e) = task.await {
            tracing::error!(error = %e, "settling a refused login's owed sessions failed");
        }
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

/// What a refused login owes: put the displaced mapping back, and end the
/// aged-out sessions.
///
/// The two run side by side, so a store that hangs on the restore does not
/// hold up the ends. A restore the store failed, or did not finish within
/// `timeout`, leaves the displaced session live with no mapping, out of reach
/// of every `sid` logout, so that session ends with the aged-out ones.
async fn settle_refused(
    registry: Option<Arc<dyn SessionRegistryHandle>>,
    sid_map: Arc<dyn SidStore>,
    aged: Vec<SubjectSession>,
    displaced: Option<(SidKey, DisplacedSid)>,
    timeout: Duration,
) {
    let end = |sessions: Vec<SubjectSession>| {
        let (registry, sid_map) = (registry.clone(), sid_map.clone());
        async move {
            if let Some(registry) = registry
                && !sessions.is_empty()
            {
                end_sessions(registry, sid_map, sessions).await;
            }
        }
    };
    let restore = async {
        let Some((key, displaced)) = displaced else {
            return;
        };
        let (user, session) = (displaced.user, displaced.session);
        let attempt =
            tokio::time::timeout(timeout, sid_map.restore_if_vacant(key.clone(), displaced)).await;
        match attempt {
            Ok(Ok(true)) => tracing::debug!(
                iss = %key.0,
                "sid_map: put back the mapping a refused login had displaced"
            ),
            Ok(Ok(false)) => tracing::debug!(
                iss = %key.0,
                session = %session,
                "sid_map: the displaced mapping was not put back (key taken or session ended)"
            ),
            Ok(Err(_)) | Err(_) => {
                tracing::warn!(
                    iss = %key.0,
                    session = %session,
                    "sid_map: the displaced mapping could not be put back; ending its session"
                );
                end(vec![(key.0, user, session)]).await;
            }
        }
    };
    tokio::join!(end(aged), restore);
}

/// End each session in the registry, concurrently within the bound, and forget
/// each the registry confirmed it ended in the subject registry.
///
/// A session the registry could not end is still live, and its `sid`
/// mapping is already gone, so the subject entry is the one way a later
/// `sub` logout still reaches it: it is kept. Forgetting it on the failed
/// end used to put the session out of reach of every logout for good.
async fn end_sessions(
    registry: Arc<dyn SessionRegistryHandle>,
    sid_map: Arc<dyn SidStore>,
    sessions: Vec<SubjectSession>,
) {
    let outcomes = concurrent::bounded(sessions, |(_, user, session)| {
        let registry = Arc::clone(&registry);
        async move {
            let outcome = registry.invalidate_session(&user, &session).await;
            let ended = outcome.is_ok();
            note_revocation(outcome, "ending a displaced OAuth session");
            ended
        }
    })
    .await;
    for ((issuer, user, session), ended) in outcomes {
        if ended {
            if let Err(e) = sid_map
                .forget_subject_session(&issuer, &user, &session)
                .await
            {
                tracing::warn!(error = %e, "sid store: an ended session was not forgotten");
            }
        } else {
            tracing::warn!(
                iss = %issuer,
                user_id = %user,
                session = %session,
                "the registry could not end a displaced OAuth session; \
                 it stays in the subject registry for a later logout"
            );
        }
    }
}
