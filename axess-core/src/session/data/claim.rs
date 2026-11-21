//! The session layer's claim on a session it is ending.

use axess_clock::Timestamp;
use serde::{Deserialize, Serialize};

/// The session layer's claim on a session it is ending
/// ([`SessionData::ending`](super::SessionData::ending)): when the claim was
/// made, and why the session ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndingClaim {
    /// When the claim was made, on the layer's clock.
    pub since: Timestamp,
    /// Why the session ends: the reason the audit row of the ending
    /// carries, whichever request writes it.
    pub reason: crate::session::layer::SessionEndReason,
}

impl EndingClaim {
    /// Whether the request that made the claim may still be ending the
    /// session at `now`: the claim is younger than [`ENDING_CLAIM_LEASE`].
    /// A claim stamped further in the future than a lease (a clock that
    /// stepped) does not hold either, so no claim keeps a session waiting
    /// for longer than the lease.
    pub fn holds_at(&self, now: Timestamp) -> bool {
        // Younger than a lease, and not stamped a lease or more ahead: the
        // size of the age, whichever way it runs, is under the lease.
        now.since(self.since).unsigned_abs() < ENDING_CLAIM_LEASE
    }
}

/// How long a claim to end a session
/// ([`SessionData::ending`](super::SessionData::ending)) keeps other
/// requests from finishing the ending themselves. The audit write and the
/// delete that follow a claim take milliseconds; a claim older than this
/// was left by a request that did not finish.
pub const ENDING_CLAIM_LEASE: std::time::Duration = std::time::Duration::from_secs(30);
