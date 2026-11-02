//! The one write of a stored session that a concurrent request may have
//! changed: a compare-and-swap on the revision, and on a conflict this
//! request's changes merged onto the row as stored now, tried again.
//!
//! Both writers of a stored session during a request use it: a handler-time
//! consumption of a one-shot value
//! ([`SessionInner::consume_custom`](super::handle::SessionInner::consume_custom))
//! and the finalize of the response.
//!
//! # Retry budget
//!
//! A write makes at most [`SWAP_ATTEMPTS`] compare-and-swaps, with one read
//! of the row between two of them. Each compare-and-swap is one store call,
//! inside which a store that compares stored bytes reads the row once more
//! when a concurrent load re-sealed it under the same revision (see the
//! stores' `cas_by_revision` driver), so at most two reads and two writes
//! per attempt. One write therefore costs at most `SWAP_ATTEMPTS` (3) layer
//! attempts of up to four store round trips each, plus two reads between
//! them; past that the concurrent writers win and this request's changes
//! are discarded.

use crate::session::data::{SessionData, cap_custom, merge_concurrent};
use crate::session::id::SessionId;
use crate::session::store::{ConditionalUpdate, SessionStore};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// How many compare-and-swaps one write of a stored session makes before it
/// gives way to the concurrent writers that keep changing the row.
const SWAP_ATTEMPTS: usize = 3;

/// The error of a store whose type was erased.
pub(crate) type StoreError = Box<dyn std::error::Error + Send + Sync>;

/// A boxed future of a store call whose type was erased.
type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// The two store operations a merging write needs, erased so the per-request
/// state does not carry the store's type. Implemented for every
/// [`SessionStore`]; the store's own error is kept as the source.
pub(crate) trait SwapStore: Send + Sync {
    /// [`SessionStore::load`].
    fn load_row<'a>(&'a self, id: &'a SessionId) -> StoreFuture<'a, Option<SessionData>>;

    /// [`SessionStore::update_if_revision`].
    fn swap_row<'a>(
        &'a self,
        id: &'a SessionId,
        expected_revision: u64,
        data: &'a SessionData,
        ttl: Duration,
    ) -> StoreFuture<'a, ConditionalUpdate>;
}

impl<S: SessionStore> SwapStore for S {
    fn load_row<'a>(&'a self, id: &'a SessionId) -> StoreFuture<'a, Option<SessionData>> {
        Box::pin(async move { self.load(id).await.map_err(StoreError::from) })
    }

    fn swap_row<'a>(
        &'a self,
        id: &'a SessionId,
        expected_revision: u64,
        data: &'a SessionData,
        ttl: Duration,
    ) -> StoreFuture<'a, ConditionalUpdate> {
        Box::pin(async move {
            self.update_if_revision(id, expected_revision, data, ttl)
                .await
                .map_err(StoreError::from)
        })
    }
}

/// What a merging write settled on.
pub(crate) enum Swapped {
    /// The row now holds this data: this request's changes on the row as it
    /// was stored, under the next revision. It is the base of any later
    /// write of the same request.
    Written(Box<SessionData>),
    /// The row is gone (expired, logged out, revoked): nothing was written.
    Gone,
    /// Concurrent writes kept winning, or there was no base to merge from:
    /// nothing was written.
    Conflict,
    /// `prepare` declined the row it was shown: nothing was written.
    Declined,
}

/// The row a write starts from and the changes it carries.
pub(crate) struct Swap<'a> {
    /// The row's id in the store.
    pub(crate) row: &'a SessionId,
    /// The row as this request last saw it stored: as loaded, or as this
    /// request's previous write left it. `None` when the request has no
    /// stored row to merge from, and a conflict then discards the write.
    pub(crate) base: Option<&'a SessionData>,
    /// The session as this request holds it now. Every field in which it
    /// differs from `base` is this request's change.
    pub(crate) local: &'a SessionData,
    /// The revision the row carries when it is still as this request saw it.
    pub(crate) expected: u64,
    /// The lifetime given to the written row.
    pub(crate) ttl: Duration,
    /// The custom-data cap applied to what is written (zero is no cap).
    pub(crate) max_custom_bytes: usize,
}

/// Write `swap.local` over the stored row while the row still carries
/// `swap.expected`; when a concurrent request wrote it meanwhile, read the
/// row, let `prepare` look at it, merge this request's changes onto it
/// ([`merge_concurrent`]) and try again from the revision found, at most
/// [`SWAP_ATTEMPTS`] times in all.
///
/// The changes are always this request's own: every attempt merges `local`
/// against `base`, never against a row an earlier attempt merged, so a value
/// a concurrent request wrote and a third one removed between two attempts
/// is not written back. The written row carries the next revision, the later
/// of the two refresh stamps, and a custom bag within the cap.
///
/// `prepare` sees each row read after a conflict before the merge and may
/// change it (a consumption takes its value out of it); returning `false`
/// stops the write with [`Swapped::Declined`].
pub(crate) async fn swap_merging<St: SwapStore + ?Sized>(
    store: &St,
    swap: Swap<'_>,
    mut prepare: impl FnMut(&mut SessionData) -> bool,
) -> Result<Swapped, StoreError> {
    let mut expected = swap.expected;
    let mut next = swap.local.clone();
    for _ in 0..SWAP_ATTEMPTS {
        next.revision = expected.wrapping_add(1);
        cap_custom(&mut next.custom, swap.max_custom_bytes);
        match store.swap_row(swap.row, expected, &next, swap.ttl).await? {
            ConditionalUpdate::Written => return Ok(Swapped::Written(Box::new(next))),
            ConditionalUpdate::Gone => return Ok(Swapped::Gone),
            ConditionalUpdate::Conflict => {
                let Some(base) = swap.base else {
                    return Ok(Swapped::Conflict);
                };
                let Some(mut fresh) = store.load_row(swap.row).await? else {
                    return Ok(Swapped::Gone);
                };
                if !prepare(&mut fresh) {
                    return Ok(Swapped::Declined);
                }
                expected = fresh.revision;
                let touched_at = swap.local.touched_at.max(fresh.touched_at);
                next = merge_concurrent(base, swap.local, &fresh);
                next.touched_at = touched_at;
            }
        }
    }
    Ok(Swapped::Conflict)
}
