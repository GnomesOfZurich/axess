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

/// Where the current policy lives: a file, a database row, an object store.
///
/// This is the trust boundary of a coordinated reload. A follower applies what
/// the source returns, never what a notice says.
pub trait PolicySource: Send + Sync {
    /// Read the policy set that should be in force.
    fn load(&self) -> ReloadFuture<'_, Result<PolicyBundle, AuthzError>>;
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
    /// A bundle that fails validation, or a source that cannot be read, is
    /// logged and counted; the instance keeps its set and retries at the next
    /// notice or poll.
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
            self.sync_from(source.as_ref(), origin).await;
        }
    }

    async fn sync_from(&self, source: &dyn PolicySource, origin: ReloadOrigin) {
        let bundle = match source.load().await {
            Ok(bundle) => bundle,
            Err(e) => {
                warn!(
                    target: "axess::authz::reload",
                    origin = origin.as_str(),
                    error = %e,
                    "the policy source could not be read; the previous policy set stays in force",
                );
                return;
            }
        };
        if self.policy_digest().as_deref() == Some(bundle.digest().as_str()) {
            return;
        }
        // The refusal is logged and counted inside; the set in force stays.
        let _ = self
            .reload_from(&bundle.policy_text, &bundle.schema_json, origin)
            .await;
    }
}

/// The next notice, or never when the coordinator is gone.
async fn next_notice(notices: &mut Option<ReloadReceiver>) -> Result<(), RecvError> {
    match notices {
        Some(receiver) => receiver.recv().await.map(|_| ()),
        None => std::future::pending().await,
    }
}
