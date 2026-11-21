//! A short-lived negative cache of the issuers no provider is configured for.
//!
//! The back-channel route is unauthenticated, and it reads the issuer out of
//! the token before any signature is checked. Without this, every request
//! that names an issuer nobody configured costs a read of the tenant source
//! (and, behind it, a database query). An issuer the source answered "none"
//! for is remembered for a short time, so a loop of such requests costs one
//! read per interval.
//!
//! An issuer that is configured is never remembered here, and neither is a
//! failed read. A miss is trusted only while the source's generation is the
//! one seen when the miss was recorded, so a provider added through a live
//! reload is found at once; a source whose generation does not move (a store
//! another process writes) is found again once the interval has passed.

use axess_clock::{Timestamp, Until};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// Issuers remembered at once. The cache never grows past this: at the bound
/// a new unknown issuer is simply not remembered, and costs the read it would
/// have cost without the cache.
const MAX_ENTRIES: usize = 1024;

/// Longest issuer string remembered, in bytes. A longer one is not a real
/// issuer and is not worth a slot.
const MAX_ISSUER_BYTES: usize = 512;

/// Default time an unknown issuer is remembered.
pub(super) const DEFAULT_TTL_SECS: u64 = 30;

/// Issuers recently found to have no provider, each with when it expires.
pub(super) struct UnknownIssuers {
    ttl: Duration,
    seen: Mutex<HashMap<String, (Until, u64)>>,
}

impl UnknownIssuers {
    /// A cache that remembers an unknown issuer for `ttl`. A `ttl` of no
    /// time remembers nothing, and one past the range of a reading
    /// remembers until the source's generation moves.
    pub(super) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            seen: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Until, u64)>> {
        self.seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether `issuer` was found unknown, the answer is still fresh, and the
    /// source has not changed since (`generation`).
    pub(super) fn is_unknown(&self, issuer: &str, now: Timestamp, generation: u64) -> bool {
        self.lock()
            .get(issuer)
            .is_some_and(|(until, seen)| *until > Until::At(now) && *seen == generation)
    }

    /// Remember that `issuer` has no provider, as of `generation`, the
    /// source's generation read before it was asked.
    pub(super) fn remember(&self, issuer: &str, now: Timestamp, generation: u64) {
        if self.ttl.is_zero() || issuer.len() > MAX_ISSUER_BYTES {
            return;
        }
        let mut seen = self.lock();
        if seen.len() >= MAX_ENTRIES {
            seen.retain(|_, (until, _)| *until > Until::At(now));
            if seen.len() >= MAX_ENTRIES {
                return;
            }
        }
        seen.insert(
            issuer.to_string(),
            (Until::after(now, self.ttl), generation),
        );
    }
}

#[cfg(test)]
mod tests;
