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
use crate::session::id::SessionKey;
use crate::session::store::{ConditionalUpdate, CycleOutcome, SessionStore};
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

    /// The live row under `key`: the revision decoded from it, and what a
    /// conditional write compares; `None` for no live row.
    fn read(
        &self,
        key: &SessionKey,
    ) -> impl Future<Output = Result<Option<(u64, Self::Seen)>, Self::Error>> + Send;

    /// Remove the row while it still holds `seen`.
    fn delete_if(
        &self,
        key: &SessionKey,
        seen: &Self::Seen,
    ) -> impl Future<Output = Result<CasWrite, Self::Error>> + Send;

    /// Replace the row with `data`, living `ttl` from now, while it still
    /// holds `seen`. `ttl` is never zero.
    fn replace_if(
        &self,
        key: &SessionKey,
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
    key: &SessionKey,
    expected_revision: u64,
    data: &SessionData,
    ttl: Duration,
) -> Result<ConditionalUpdate, R::Error> {
    for _ in 0..CAS_ATTEMPTS {
        let Some((revision, seen)) = row.read(key).await? else {
            return Ok(ConditionalUpdate::Gone);
        };
        if revision != expected_revision {
            return Ok(ConditionalUpdate::Conflict);
        }
        let written = if ttl.is_zero() {
            match row.delete_if(key, &seen).await? {
                CasWrite::Done => CasWrite::Gone,
                other => other,
            }
        } else {
            row.replace_if(key, &seen, data, ttl).await?
        };
        match written {
            CasWrite::Done => return Ok(ConditionalUpdate::Written),
            CasWrite::Gone => return Ok(ConditionalUpdate::Gone),
            CasWrite::Missed => {}
        }
    }
    Ok(ConditionalUpdate::Conflict)
}

/// [`SessionStore::cycle_if_revision`](super::SessionStore::cycle_if_revision)
/// over a store's [`CasRow`] steps.
///
/// The old row is removed only while it still holds what was read at the
/// expected revision, so a write that landed between the caller's read and
/// the removal makes the removal miss and the answer
/// [`CycleOutcome::Conflict`]; whoever removes the row owns the rotation, as
/// the delete decides in `cycle`. The new row is written after the removal,
/// sealed for the new key: a row is never renamed in place, because a blob
/// sealed for one key does not authenticate under another.
/// A failure between the two leaves neither row, which the layer treats as
/// the failed rotation it fails closed on.
pub(crate) async fn cycle_by_revision<S>(
    store: &S,
    old: &SessionKey,
    new: &SessionKey,
    data: &SessionData,
    ttl: Duration,
    require_old: bool,
    expected_revision: u64,
) -> Result<CycleOutcome, <S as SessionStore>::Error>
where
    S: SessionStore + CasRow<Error = <S as SessionStore>::Error>,
{
    if ttl.is_zero() {
        // Nothing is stored for a zero ttl: both rows go, and the revision
        // only decides whether this caller still owned the row.
        if let Some((revision, _)) = CasRow::read(store, old).await?
            && revision != expected_revision
        {
            return Ok(CycleOutcome::Conflict);
        }
        return store.cycle(old, new, data, ttl, require_old).await;
    }
    for _ in 0..CAS_ATTEMPTS {
        let step = match CasRow::read(store, old).await? {
            None => CasWrite::Gone,
            Some((revision, _)) if revision != expected_revision => {
                return Ok(CycleOutcome::Conflict);
            }
            Some((_, seen)) if old == new => store.replace_if(new, &seen, data, ttl).await?,
            Some((_, seen)) => match store.delete_if(old, &seen).await? {
                CasWrite::Done => {
                    store.save(new, data, ttl).await?;
                    return Ok(CycleOutcome::Rotated);
                }
                other => other,
            },
        };
        match step {
            CasWrite::Done => return Ok(CycleOutcome::Rotated),
            CasWrite::Missed => {}
            CasWrite::Gone if require_old => return Ok(CycleOutcome::SessionGone),
            CasWrite::Gone => {
                // A login on a guest whose session was never stored: no old row
                // to remove (an expired remnant of it goes too), and the new
                // row is always written.
                if old != new {
                    store.delete(old).await?;
                }
                store.save(new, data, ttl).await?;
                return Ok(CycleOutcome::Rotated);
            }
        }
    }
    Ok(CycleOutcome::Conflict)
}

#[cfg(test)]
mod tests;
