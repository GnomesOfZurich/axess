//! The compare-and-swap by revision that every shipped session store runs
//! for [`SessionStore::update_if_revision`](super::SessionStore::update_if_revision).
//!
//! A store can only make a write conditional on what it can compare: the
//! stored bytes for the SQL and Valkey stores, the stored value for the
//! in-memory one. The revision inside the row is what decides, so the
//! driver reads the row, compares its revision, and then writes on the
//! condition that the row still holds what was read. Each store implements
//! the three steps ([`CasRow`]) in its own dialect; the policy lives here
//! once.

use crate::session::data::SessionData;
use crate::session::id::SessionId;
use crate::session::store::ConditionalUpdate;
use std::future::Future;
use std::time::Duration;

/// How many times a conditional write reads the row after its write found
/// the row no longer holding what was read.
///
/// Only a change that keeps the revision earns a second read: a concurrent
/// load's re-seal of a blob stored in an older form (another key, another
/// layout) writes new bytes under the same revision. A row re-sealed once
/// is in the current form and is not re-sealed again, so the second read
/// finds it settled. A concurrent writer moves the revision, which the next
/// read answers with [`ConditionalUpdate::Conflict`] without another write.
/// Two attempts therefore cover every case; a miss on the second means a
/// write that kept the revision raced this one, and is answered as a
/// conflict.
pub(crate) const CAS_ATTEMPTS: usize = 2;

/// What a conditional write against a row read earlier found.
pub(crate) enum CasWrite {
    /// The row still held what was read, and the write (or removal) landed.
    Done,
    /// The row holds something else now; read it again.
    Missed,
    /// The row is gone.
    Gone,
}

/// The three steps of a compare-and-swap that a session store implements in
/// its own dialect.
pub(crate) trait CasRow: Sync {
    /// What a conditional write compares the row with: the stored bytes, or
    /// whatever the store matches on.
    type Seen: Send + Sync;
    /// The store's error.
    type Error;

    /// The live row under `id`: the revision decoded from it, and what a
    /// conditional write compares; `None` for no live row.
    fn read(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Result<Option<(u64, Self::Seen)>, Self::Error>> + Send;

    /// Remove the row while it still holds `seen`.
    fn delete_if(
        &self,
        id: &SessionId,
        seen: &Self::Seen,
    ) -> impl Future<Output = Result<CasWrite, Self::Error>> + Send;

    /// Replace the row with `data`, living `ttl` from now, while it still
    /// holds `seen`. `ttl` is never zero.
    fn replace_if(
        &self,
        id: &SessionId,
        seen: &Self::Seen,
        data: &SessionData,
        ttl: Duration,
    ) -> impl Future<Output = Result<CasWrite, Self::Error>> + Send;
}

/// [`SessionStore::update_if_revision`](super::SessionStore::update_if_revision)
/// over a store's [`CasRow`] steps.
///
/// No live row is [`ConditionalUpdate::Gone`]; a row under another revision
/// is [`ConditionalUpdate::Conflict`] and is left as it is; otherwise `data`
/// replaces the row while it still holds what was read, and a write that
/// finds it changed reads it again, [`CAS_ATTEMPTS`] times in all. A zero
/// `ttl` stores nothing: the row whose revision matched is removed and the
/// session reported gone (the trait's "Zero TTL" section).
pub(crate) async fn cas_by_revision<R: CasRow>(
    row: &R,
    id: &SessionId,
    expected_revision: u64,
    data: &SessionData,
    ttl: Duration,
) -> Result<ConditionalUpdate, R::Error> {
    for _ in 0..CAS_ATTEMPTS {
        let Some((revision, seen)) = row.read(id).await? else {
            return Ok(ConditionalUpdate::Gone);
        };
        if revision != expected_revision {
            return Ok(ConditionalUpdate::Conflict);
        }
        let written = if ttl.is_zero() {
            match row.delete_if(id, &seen).await? {
                CasWrite::Done => CasWrite::Gone,
                other => other,
            }
        } else {
            row.replace_if(id, &seen, data, ttl).await?
        };
        match written {
            CasWrite::Done => return Ok(ConditionalUpdate::Written),
            CasWrite::Gone => return Ok(ConditionalUpdate::Gone),
            CasWrite::Missed => {}
        }
    }
    Ok(ConditionalUpdate::Conflict)
}

#[cfg(test)]
mod tests;
