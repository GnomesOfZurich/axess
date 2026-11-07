//! The receiving side: re-read the policy source on a notice and on a poll.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;
use tracing::{error, warn};

use super::{CoordinationError, ReloadFuture, ReloadReceiver};
use crate::authz::{
    error::AuthzError, provider::AuthzEntityProvider, session::AuthzStore, store::policy_set_digest,
};

/// The policy text and schema an instance should be running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundle {
    /// Cedar policy text.
    pub policy_text: String,
    /// The Cedar schema, JSON.
    pub schema_json: String,
}

impl PolicyBundle {
    /// The digest of this bundle, see
    /// [`policy_set_digest`](crate::authz::store::policy_set_digest).
    pub fn digest(&self) -> String {
        policy_set_digest(&self.policy_text, &self.schema_json)
    }
}

/// A [`PolicyBundle`] with the generation the source published it at.
///
/// A generation is a number the source raises whenever it publishes a new
/// set (a version column, a revision counter, a file's sequence number). A
/// follower never applies a bundle whose generation is lower than the one it
/// last applied, so a stale replica or cache cannot put an older, looser set
/// back in force. A bundle without a generation is applied whenever its
/// digest differs, as before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedBundle {
    bundle: PolicyBundle,
    generation: Option<u64>,
}

impl VersionedBundle {
    /// A bundle with no generation.
    pub fn new(bundle: PolicyBundle) -> Self {
        Self {
            bundle,
            generation: None,
        }
    }

    /// Set the generation the source published this bundle at.
    #[must_use]
    pub fn with_generation(mut self, generation: u64) -> Self {
        self.generation = Some(generation);
        self
    }

    /// The generation, when the source gave one.
    pub fn generation(&self) -> Option<u64> {
        self.generation
    }

    /// The bundle.
    pub fn bundle(&self) -> &PolicyBundle {
        &self.bundle
    }

    /// The bundle, without its generation.
    pub fn into_bundle(self) -> PolicyBundle {
        self.bundle
    }
}

/// Where the current policy lives: a file, a database row, an object store.
///
/// This is the trust boundary of a coordinated reload. A follower applies what
/// the source returns, never what a notice says.
pub trait PolicySource: Send + Sync {
    /// Read the policy set that should be in force.
    fn load(&self) -> ReloadFuture<'_, Result<PolicyBundle, AuthzError>>;

    /// Read the policy set with the generation it was published at.
    ///
    /// The follower calls this, not [`load`](Self::load). Override it when the
    /// source has a monotonic version, so a follower refuses to go back to an
    /// older bundle; the default returns [`load`](Self::load) with no
    /// generation.
    fn load_versioned(&self) -> ReloadFuture<'_, Result<VersionedBundle, AuthzError>> {
        Box::pin(async move { self.load().await.map(VersionedBundle::new) })
    }
}

/// What caused a reload, for the event and for the announce rule: only a
/// local reload announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadOrigin {
    /// [`AuthzStore::reload_policies`] was called on this instance.
    Local,
    /// A coordinator notice arrived.
    Notice,
    /// The follower's periodic re-read, or its read at start.
    Poll,
}

impl ReloadOrigin {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Notice => "notice",
            Self::Poll => "poll",
        }
    }
}

/// A running follower. Dropping it stops the task.
#[derive(Debug)]
pub struct ReloadFollower {
    task: JoinHandle<()>,
}

impl ReloadFollower {
    /// Stop following.
    pub fn stop(self) {}

    /// Whether the follower task has ended. A follower contains a panic in a
    /// source read and keeps going, so this is `true` only after the runtime
    /// shut down or the task was aborted; a health check can poll it.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Aborts the task it holds when dropped, so a stopped follower does not
/// leave a read running.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Drop for ReloadFollower {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl<P: AuthzEntityProvider + 'static> AuthzStore<P> {
    /// Keep this instance on the policy `source` returns.
    ///
    /// Reads the source once at start (to catch up on what was missed while
    /// not following), then again on every coordinator notice and every
    /// `poll_every`, and applies the bundle when its digest differs from the
    /// one in force. An applied bundle goes through the same validation as
    /// [`reload_policies`](Self::reload_policies) and is not announced again.
    /// A bundle that fails validation, a source that cannot be read, a read
    /// that outlasts [`ReloadTimeouts::source_read`](super::ReloadTimeouts), a
    /// read that panics, and a bundle whose generation (see
    /// [`PolicySource::load_versioned`]) is lower than the one in force are
    /// logged and counted on the refused counter; the instance keeps its set
    /// and retries at the next notice or poll.
    ///
    /// A reload made on this instance with
    /// [`reload_policies`](Self::reload_policies) and not written to the
    /// source is replaced by the source's bundle at the next notice or poll
    /// (this instance's own announcement included), because the source is the
    /// truth a follower converges on. Write an emergency change to the source.
    ///
    /// # Errors
    ///
    /// [`CoordinationError`] when no coordinator was set with
    /// [`with_coordinator`](Self::with_coordinator), when `poll_every` is
    /// zero, or when subscribing fails.
    pub async fn follow_reloads(
        self: &Arc<Self>,
        source: Arc<dyn PolicySource>,
        poll_every: Duration,
    ) -> Result<ReloadFollower, CoordinationError> {
        let Some(coordinator) = self.reload.coordinator.clone() else {
            return Err(CoordinationError(
                "follow_reloads needs a coordinator; set one with with_coordinator".into(),
            ));
        };
        if poll_every.is_zero() {
            return Err(CoordinationError(
                "poll_every must be longer than zero".into(),
            ));
        }
        let notices = coordinator.subscribe().await?;
        let store = Arc::clone(self);
        let task = tokio::spawn(async move {
            store.follow(source, poll_every, notices).await;
        });
        Ok(ReloadFollower { task })
    }

    async fn follow(
        self: Arc<Self>,
        source: Arc<dyn PolicySource>,
        poll_every: Duration,
        notices: ReloadReceiver,
    ) {
        let mut notices = Some(notices);
        let mut ticker = tokio::time::interval(poll_every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let origin = tokio::select! {
                _ = ticker.tick() => ReloadOrigin::Poll,
                received = next_notice(&mut notices) => match received {
                    Ok(()) => ReloadOrigin::Notice,
                    Err(RecvError::Lagged(_)) => ReloadOrigin::Notice,
                    Err(RecvError::Closed) => {
                        error!(
                            target: "axess::authz::reload",
                            "the reload coordinator closed; following by poll only",
                        );
                        notices = None;
                        continue;
                    }
                },
            };
            // One task per read: a panic in the source ends that read, is
            // counted, and the loop goes on. The guard aborts it with the
            // follower.
            let this = Arc::clone(&self);
            let src = Arc::clone(&source);
            let mut read = AbortOnDrop(tokio::spawn(async move {
                this.sync_from(src.as_ref(), origin).await;
            }));
            if let Err(e) = (&mut read.0).await
                && e.is_panic()
            {
                error!(
                    target: "axess::authz::reload",
                    origin = origin.as_str(),
                    "reading the policy source panicked; the previous policy set stays in force",
                );
                self.count_refused();
            }
        }
    }

    async fn sync_from(&self, source: &dyn PolicySource, origin: ReloadOrigin) {
        let limit = self.reload.timeouts.source_read;
        let versioned = match tokio::time::timeout(limit, source.load_versioned()).await {
            Ok(Ok(versioned)) => versioned,
            Ok(Err(e)) => {
                warn!(
                    target: "axess::authz::reload",
                    origin = origin.as_str(),
                    error = %e,
                    "the policy source could not be read; the previous policy set stays in force",
                );
                self.count_refused();
                return;
            }
            Err(_) => {
                error!(
                    target: "axess::authz::reload",
                    origin = origin.as_str(),
                    limit_ms = limit.as_millis() as u64,
                    "reading the policy source timed out; the previous policy set stays in force",
                );
                self.count_refused();
                return;
            }
        };
        let generation = versioned.generation();
        let bundle = versioned.into_bundle();
        if self.policy_digest().as_deref() == Some(bundle.digest().as_str()) {
            self.record_generation(generation);
            return;
        }
        if let (Some(offered), Some(in_force)) = (generation, self.generation_in_force())
            && offered < in_force
        {
            warn!(
                target: "axess::authz::reload",
                origin = origin.as_str(),
                offered,
                in_force,
                "the policy source offered an older generation than the one in force; refused",
            );
            self.count_refused();
            return;
        }
        // The refusal is logged and counted inside; the set in force stays.
        if self
            .reload_from(&bundle.policy_text, &bundle.schema_json, origin)
            .await
            .is_ok()
        {
            self.record_generation(generation);
        }
    }

    fn generation_in_force(&self) -> Option<u64> {
        *self
            .reload
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn record_generation(&self, generation: Option<u64>) {
        let Some(generation) = generation else {
            return;
        };
        let mut held = self
            .reload
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *held = Some(held.map_or(generation, |h| h.max(generation)));
    }
}

/// The next notice, or never when the coordinator is gone.
async fn next_notice(notices: &mut Option<ReloadReceiver>) -> Result<(), RecvError> {
    match notices {
        Some(receiver) => receiver.recv().await.map(|_| ()),
        None => std::future::pending().await,
    }
}
