//! The slot of a source: what its watcher last accepted, and when a read
//! stops being answered with it.
//!
//! A read clones an `Arc` out of the slot and never waits. The slot itself
//! compares what it holds with the clock at each read, so nothing past its
//! end is served between two checks of the watcher: an SVID past its expiry,
//! a bundle set the agent has not confirmed within the maximum bundle age,
//! an identity whose withdrawal the grace no longer covers.

use std::sync::Arc;

use axess_clock::{Clock, SignedDuration, Timestamp, Until};
use tokio::sync::watch;

use super::error::SpireError;
use crate::metrics::WorkloadCredentialKind;

/// How long what a slot holds is served.
pub(crate) enum Lifetime<T> {
    /// Until the item's own expiry: an SVID.
    Own(fn(&T) -> Timestamp),
    /// For this long after the agent last confirmed it: a bundle set.
    Confirmed(SignedDuration),
}

/// Why a slot that held something holds nothing.
#[derive(Clone, Copy)]
pub(super) enum Lost {
    /// What it held passed its own expiry.
    Expired,
    /// The agent did not confirm what it held within the maximum age.
    Stale,
    /// The agent stopped issuing what it held.
    Withdrawn,
}

struct Slot<T> {
    value: Option<Arc<T>>,
    /// Counts every change of `value`, a loss included.
    generation: u64,
    /// Why `value` is empty, once it has held something.
    lost: Option<Lost>,
    /// When the agent last sent what `value` holds, or sent it again.
    confirmed_at: Option<Timestamp>,
    /// The answer after which the watcher asks no more, once it has had one.
    stopped: Option<SpireError>,
    /// When a withdrawal the agent stated with `PERMISSION_DENIED` takes
    /// effect: the end of the withdrawal grace. `None` when nothing was
    /// withdrawn, or the agent has sent the value again since.
    withdraw_at: Option<Until>,
}

/// The slot of one source, shared by its handles and its watcher.
pub(super) struct Shared<T> {
    slot: watch::Sender<Slot<T>>,
    kind: WorkloadCredentialKind,
    pub(super) clock: Arc<dyn Clock>,
    lifetime: Lifetime<T>,
}

impl<T> Shared<T> {
    pub(super) fn new(
        kind: WorkloadCredentialKind,
        clock: Arc<dyn Clock>,
        lifetime: Lifetime<T>,
    ) -> Self {
        let (slot, _) = watch::channel(Slot {
            value: None,
            generation: 0,
            lost: None,
            confirmed_at: None,
            stopped: None,
            withdraw_at: None,
        });
        Self {
            slot,
            kind,
            clock,
            lifetime,
        }
    }

    /// When `value`, last confirmed at `confirmed_at`, stops being served,
    /// and what it is then. A value with no confirmation on record is past
    /// its end already.
    pub(super) fn end(&self, value: &T, confirmed_at: Option<Timestamp>) -> (Timestamp, Lost) {
        match &self.lifetime {
            Lifetime::Own(expiry) => (expiry(value), Lost::Expired),
            Lifetime::Confirmed(age) => {
                // No confirmation on record, or an age that runs past the
                // range from it: the earliest reading, which is past at
                // every `now`.
                let end = confirmed_at
                    .and_then(|at| at.checked_add(*age))
                    .unwrap_or(Timestamp::MIN);
                (end, Lost::Stale)
            }
        }
    }

    pub(super) fn lost_error(&self, lost: Lost) -> SpireError {
        match lost {
            Lost::Expired => SpireError::Expired(self.kind),
            Lost::Stale => SpireError::Stale(self.kind),
            Lost::Withdrawn => SpireError::Withdrawn(self.kind),
        }
    }

    /// What the slot holds, unless it holds nothing or what it holds is
    /// past its end by the clock.
    pub(super) fn current(&self) -> Result<Arc<T>, SpireError> {
        self.current_confirmed().map(|(held, _)| held)
    }

    /// As [`current`](Self::current), with when the agent last confirmed
    /// it, read in the same instant.
    pub(super) fn current_confirmed(&self) -> Result<(Arc<T>, Option<Timestamp>), SpireError> {
        let slot = self.slot.borrow();
        let held = match (&slot.value, slot.lost) {
            (Some(value), _) => Ok((value.clone(), slot.confirmed_at, slot.withdraw_at)),
            (None, Some(lost)) => Err(self.lost_error(lost)),
            (None, None) => Err(slot
                .stopped
                .clone()
                .unwrap_or(SpireError::NotYetFetched(self.kind))),
        };
        drop(slot);
        let (held, confirmed_at, withdraw_at) = held?;
        let (end, lost) = self.end(&held, confirmed_at);
        let now = self.clock.now();
        if now >= end {
            return Err(self.lost_error(lost));
        }
        // The grace of a withdrawal has run out, and the watcher has not
        // looked yet.
        if withdraw_at.is_some_and(|at| Until::At(now) >= at) {
            return Err(self.lost_error(Lost::Withdrawn));
        }
        Ok((held, confirmed_at))
    }

    pub(super) fn held(&self) -> Option<(Arc<T>, Option<Timestamp>)> {
        let slot = self.slot.borrow();
        slot.value.clone().map(|value| (value, slot.confirmed_at))
    }

    pub(super) fn generation(&self) -> u64 {
        self.slot.borrow().generation
    }

    pub(super) fn confirmed_at(&self) -> Option<Timestamp> {
        self.slot.borrow().confirmed_at
    }

    pub(super) fn put(&self, value: Arc<T>, now: Timestamp) {
        self.slot.send_modify(|slot| {
            slot.value = Some(value);
            slot.generation += 1;
            slot.lost = None;
            slot.confirmed_at = Some(now);
            slot.withdraw_at = None;
        });
    }

    /// Record that the agent sent again what the slot holds. Readers
    /// waiting for a change are not woken: nothing they read has changed.
    pub(super) fn confirm(&self, now: Timestamp) {
        self.slot.send_if_modified(|slot| {
            slot.confirmed_at = Some(now);
            // The agent issues it again: a withdrawal under grace is over.
            slot.withdraw_at = None;
            false
        });
    }

    /// Have the withdrawal of what the slot holds take effect at `at`,
    /// unless one is pending already. Whether this call set it.
    pub(super) fn defer_withdrawal(&self, at: Until) -> bool {
        let mut set = false;
        self.slot.send_if_modified(|slot| {
            if slot.value.is_some() && slot.withdraw_at.is_none() {
                slot.withdraw_at = Some(at);
                set = true;
            }
            false
        });
        set
    }

    /// When a pending withdrawal takes effect.
    pub(super) fn withdraw_at(&self) -> Option<Until> {
        self.slot.borrow().withdraw_at
    }

    pub(super) fn clear(&self, lost: Lost) {
        self.slot.send_modify(|slot| {
            slot.value = None;
            slot.generation += 1;
            slot.lost = Some(lost);
            slot.withdraw_at = None;
        });
    }

    /// Record the answer after which the watcher asks no more.
    pub(super) fn stop(&self, error: &SpireError) {
        self.slot.send_if_modified(|slot| {
            slot.stopped = Some(error.clone());
            false
        });
    }

    pub(super) async fn ready(&self) {
        let mut changes = self.slot.subscribe();
        // The sender lives in `self`, so the wait cannot end in an error.
        let waited = changes.wait_for(|slot| slot.value.is_some()).await;
        drop(waited);
    }

    pub(super) async fn updated(&self, after: u64) -> u64 {
        let mut changes = self.slot.subscribe();
        match changes.wait_for(|slot| slot.generation > after).await {
            Ok(slot) => slot.generation,
            Err(_) => after,
        }
    }
}
