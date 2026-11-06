//! The cross-instance notice: a reload on one instance tells the others to
//! look at the policy source.

use std::num::NonZeroUsize;

use tokio::sync::broadcast;

use super::ReloadFuture;

/// The receiving end of a coordinator's notices. A lagged receiver is a
/// missed notice; the follower treats it as one and re-reads the source.
pub type ReloadReceiver = broadcast::Receiver<ReloadNotice>;

/// Why the coordinator could not announce, subscribe, or be configured.
#[derive(Debug, thiserror::Error)]
#[error("reload coordination failed: {0}")]
pub struct CoordinationError(pub String);

/// A hint that the policy set changed somewhere.
///
/// The digest is for logs. Nothing in a notice is applied: the receiver reads
/// the state from its own source (the policy source of an `AuthzStore`, the
/// provider source of an `AuthnService`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadNotice {
    /// The digest the announcing instance put in force.
    pub digest: String,
}

/// Carries reload notices between instances.
///
/// Delivery is at most once; the follower's poll covers a notice that does
/// not arrive. Implementations must not carry policy text.
pub trait ReloadCoordinator: Send + Sync {
    /// Tell every subscriber, this instance included, that the policy set with
    /// `digest` is now in force on the announcing instance.
    fn announce<'a>(&'a self, digest: &'a str) -> ReloadFuture<'a, Result<(), CoordinationError>>;

    /// Receive the notices announced from now on.
    fn subscribe(&self) -> ReloadFuture<'_, Result<ReloadReceiver, CoordinationError>>;
}

/// A coordinator inside one process: for tests, and for several stores that
/// share a process.
///
/// Clones share one channel.
#[derive(Debug, Clone)]
pub struct InProcessCoordinator {
    sender: broadcast::Sender<ReloadNotice>,
}

impl InProcessCoordinator {
    /// A coordinator that buffers up to `capacity` unread notices per
    /// subscriber before a slow one lags.
    pub fn new(capacity: NonZeroUsize) -> Self {
        let (sender, _) = broadcast::channel(capacity.get());
        Self { sender }
    }
}

impl ReloadCoordinator for InProcessCoordinator {
    fn announce<'a>(&'a self, digest: &'a str) -> ReloadFuture<'a, Result<(), CoordinationError>> {
        Box::pin(async move {
            // No subscriber is not a failure: nobody needed telling.
            let _ = self.sender.send(ReloadNotice {
                digest: digest.to_string(),
            });
            Ok(())
        })
    }

    fn subscribe(&self) -> ReloadFuture<'_, Result<ReloadReceiver, CoordinationError>> {
        Box::pin(async move { Ok(self.sender.subscribe()) })
    }
}
