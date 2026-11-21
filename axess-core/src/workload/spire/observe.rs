//! What a watcher reports, and to whom.
//!
//! A watcher reports twice. A count goes to the rotation concern of the
//! crate's metrics ([`RotationMetrics`](crate::metrics::RotationMetrics)),
//! labelled with nothing but the kind of credential. The occurrence, with
//! the SPIFFE ID, the expiry and the error, goes to a
//! [`WorkloadApiListener`] and to a `tracing` event on the target
//! `axess::workload::spire`, where identity belongs.

use std::time::Duration;

use axess_clock::{Timestamp, Until};
use axess_identity::WorkloadId;

use super::error::SpireError;
use crate::metrics::WorkloadCredentialKind;

/// One thing a watcher did or failed to do. Borrowed from the watcher: a
/// listener copies what it keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadApiEvent<'a> {
    /// The watcher replaced what it holds with what the agent sent.
    Rotated {
        /// What was replaced.
        kind: WorkloadCredentialKind,
        /// The SPIFFE ID of an SVID; `None` for a bundle set.
        spiffe_id: Option<&'a WorkloadId>,
        /// When an SVID expires; `None` for a bundle set.
        expires_at: Option<Timestamp>,
        /// How many trust domains a bundle set holds; for an X.509 SVID,
        /// how many came with it.
        trust_domains: usize,
    },
    /// A refresh failed. The watcher retries after `retry_in`.
    RefreshFailed {
        /// What was being refreshed.
        kind: WorkloadCredentialKind,
        /// Why it failed.
        error: &'a SpireError,
        /// How many refreshes have failed in a row, this one included.
        consecutive_failures: u32,
        /// How long the watcher waits before the next attempt.
        retry_in: Duration,
        /// Whether readers are still served a value that is valid.
        still_serving: bool,
    },
    /// A bundle entry of another trust domain, sent with what the watcher
    /// took, did not read and was left out.
    BundleSkipped {
        /// What the entry came with.
        kind: WorkloadCredentialKind,
        /// The entry's key as the agent wrote it, escaped and cut.
        key: &'a str,
        /// Why it was left out.
        error: &'a SpireError,
    },
    /// The agent stopped issuing what the watcher held (it answered
    /// `PERMISSION_DENIED`, or its answer no longer holds the selected
    /// identity), and the watcher stopped serving it. Readers are refused
    /// until the agent issues it again; the watcher goes on asking.
    Withdrawn {
        /// What was withdrawn.
        kind: WorkloadCredentialKind,
        /// The SPIFFE ID of an SVID that was withdrawn; `None` for bundles.
        spiffe_id: Option<&'a WorkloadId>,
    },
    /// The agent answered `PERMISSION_DENIED` for what the watcher holds,
    /// and the client has a withdrawal grace: the value is served until
    /// `until`, and withdrawn then unless the agent has issued it again.
    /// Reported once for each such answer that starts a grace.
    WithdrawalDeferred {
        /// What the agent withdrew.
        kind: WorkloadCredentialKind,
        /// The SPIFFE ID of an SVID; `None` for bundles.
        spiffe_id: Option<&'a WorkloadId>,
        /// When the grace ends: never, for a grace that runs past the range
        /// of a reading.
        until: Until,
    },
    /// The agent answered with a status the Workload Endpoint standard
    /// says not to retry (`INVALID_ARGUMENT`, a fault of the client, or
    /// `UNIMPLEMENTED`), and the watcher asks no more. What it holds is
    /// served until it runs out.
    Stopped {
        /// What the watcher was keeping current.
        kind: WorkloadCredentialKind,
        /// The agent's answer.
        error: &'a SpireError,
    },
    /// What the watcher held ran out with no replacement: an SVID passed
    /// its expiry, or the agent did not confirm a bundle set within the
    /// maximum bundle age. Readers are refused until the agent answers.
    Expired {
        /// What ran out. For the bundles that came with an X.509 SVID it is
        /// the X.509 bundles, and the SVID is still served.
        kind: WorkloadCredentialKind,
        /// The SPIFFE ID of an SVID that expired; `None` for bundles.
        spiffe_id: Option<&'a WorkloadId>,
        /// When it ran out.
        expired_at: Timestamp,
    },
}

/// Receives each [`WorkloadApiEvent`] of the watchers of one client.
///
/// Called on the watcher's task, between two reads of the agent's stream:
/// an implementation returns quickly and does not block. The default body
/// does nothing, so a listener written for one event keeps compiling when
/// another is added.
///
/// ```
/// use axess_core::workload::spire::{WorkloadApiEvent, WorkloadApiListener};
/// use std::sync::atomic::{AtomicU64, Ordering};
///
/// #[derive(Default)]
/// struct FailedRefreshes(AtomicU64);
///
/// impl WorkloadApiListener for FailedRefreshes {
///     fn on_event(&self, event: &WorkloadApiEvent<'_>) {
///         if matches!(event, WorkloadApiEvent::RefreshFailed { .. }) {
///             self.0.fetch_add(1, Ordering::Relaxed);
///         }
///     }
/// }
/// ```
pub trait WorkloadApiListener: Send + Sync + 'static {
    /// One event. The default does nothing.
    fn on_event(&self, event: &WorkloadApiEvent<'_>) {
        let _ = event;
    }
}

/// The listener of a client that was given none.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopWorkloadApiListener;

impl WorkloadApiListener for NoopWorkloadApiListener {}
