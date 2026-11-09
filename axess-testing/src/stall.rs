//! Cancellation tests: a future that never completes, and a gate a wrapped
//! store parks on so a test aborts its caller at exactly the awaited call.
//!
//! The shape: wrap the store call under test so it awaits [`Gate::wait`],
//! spawn the operation, [`abort_inside`] once the call is entered, then assert
//! what the operation's cancellation guard left behind.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

/// A gate a wrapped call parks on until the test opens it, which a test of
/// cancellation never does.
///
/// `entered` says the caller is parked inside the awaited call, so the test
/// aborts at exactly that point instead of guessing with a sleep.
#[derive(Clone, Default)]
pub struct Gate {
    entered: Arc<AtomicBool>,
    entered_notify: Arc<Notify>,
    open: Arc<AtomicBool>,
    open_notify: Arc<Notify>,
}

impl Gate {
    /// A gate nobody has entered and nobody has opened.
    pub fn new() -> Self {
        Self::default()
    }

    /// Park here: mark the gate entered, then wait until [`open`](Self::open)
    /// is called.
    pub async fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        self.entered_notify.notify_waiters();
        loop {
            let opened = self.open_notify.notified();
            if self.open.load(Ordering::SeqCst) {
                return;
            }
            opened.await;
        }
    }

    /// Whether a caller is parked in [`wait`](Self::wait), or was.
    pub fn is_entered(&self) -> bool {
        self.entered.load(Ordering::SeqCst)
    }

    /// Return once a caller has entered [`wait`](Self::wait).
    pub async fn until_entered(&self) {
        loop {
            let entered = self.entered_notify.notified();
            if self.is_entered() {
                return;
            }
            entered.await;
        }
    }

    /// Let every parked and future [`wait`](Self::wait) return.
    pub fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
        self.open_notify.notify_waiters();
    }
}

/// A future that never completes: what a networked store that hangs looks
/// like to its caller. Aborting or dropping the caller is the only way out.
pub async fn never_completes<T>() -> T {
    std::future::pending::<T>().await
}

/// Abort `handle` once `gate` has been entered, wait for the abort to land,
/// then give the cleanup tasks a cancelled operation spawned time to run.
///
/// # Panics
///
/// If the task finished instead of being cancelled: the gate did not hold it.
pub async fn abort_inside<T: 'static>(gate: &Gate, handle: tokio::task::JoinHandle<T>) {
    gate.until_entered().await;
    handle.abort();
    let joined = handle.await;
    assert!(
        joined
            .as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled),
        "the task was meant to be cancelled inside the gate"
    );
    settle_spawned().await;
}

/// Let tasks spawned by a drop guard run to completion: yields, then a short
/// sleep for work that touches the timer.
pub async fn settle_spawned() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Poll `condition` until it holds or a second has passed.
///
/// For asserting what a cleanup task eventually did without a fixed sleep.
pub async fn eventually<F, Fut>(mut condition: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    for _ in 0..100 {
        if condition().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}
