//! Cancellation tests: a future that never completes, and a gate a wrapped
//! store parks on so a test aborts its caller at exactly the awaited call.
//!
//! The shape: wrap the store call under test so it awaits [`Gate::wait`],
//! spawn the operation, [`abort_inside`] once the call is entered, then assert
//! what the operation's cancellation guard left behind.
//!
//! Every wait here is bounded by the gate's [`bound`](Gate::bound)
//! ([`Gate::DEFAULT_BOUND`] unless [`Gate::with_bound`] sets another): a
//! change that stops the code under test reaching the gated call fails the
//! test with a message instead of hanging it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;
use tokio::sync::Notify;

/// A gate a wrapped call parks on until the test opens it, which a test of
/// cancellation never does.
///
/// `entered` says the caller is parked inside the awaited call, so the test
/// aborts at exactly that point instead of guessing with a sleep.
#[derive(Clone)]
pub struct Gate {
    entered: Arc<AtomicBool>,
    entered_notify: Arc<Notify>,
    open: Arc<AtomicBool>,
    open_notify: Arc<Notify>,
    bound: Duration,
}

impl Default for Gate {
    fn default() -> Self {
        Self::with_bound(Self::DEFAULT_BOUND)
    }
}

impl Gate {
    /// How long [`wait`](Self::wait), [`until_entered`](Self::until_entered)
    /// and [`abort_inside`] wait before they fail the test: ten seconds,
    /// far beyond the milliseconds a caller takes to reach the gate.
    pub const DEFAULT_BOUND: Duration = Duration::from_secs(10);

    /// A gate nobody has entered and nobody has opened, whose waits are
    /// bounded by [`DEFAULT_BOUND`](Self::DEFAULT_BOUND).
    pub fn new() -> Self {
        Self::default()
    }

    /// A gate whose waits fail the test after `bound` instead of
    /// [`DEFAULT_BOUND`](Self::DEFAULT_BOUND).
    pub fn with_bound(bound: Duration) -> Self {
        Self {
            entered: Arc::default(),
            entered_notify: Arc::default(),
            open: Arc::default(),
            open_notify: Arc::default(),
            bound,
        }
    }

    /// How long this gate's waits last before they fail the test.
    pub fn bound(&self) -> Duration {
        self.bound
    }

    /// Park here: mark the gate entered, then wait until [`open`](Self::open)
    /// is called or the caller is cancelled.
    ///
    /// # Panics
    ///
    /// If the gate is neither opened nor its caller cancelled within
    /// [`bound`](Self::bound).
    pub async fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        self.entered_notify.notify_waiters();
        let opened = tokio::time::timeout(self.bound, async {
            loop {
                let opened = self.open_notify.notified();
                if self.open.load(Ordering::SeqCst) {
                    return;
                }
                opened.await;
            }
        })
        .await;
        assert!(
            opened.is_ok(),
            "the gate was neither opened nor its caller cancelled within {:?}",
            self.bound
        );
    }

    /// Whether a caller is parked in [`wait`](Self::wait), or was.
    pub fn is_entered(&self) -> bool {
        self.entered.load(Ordering::SeqCst)
    }

    /// Return once a caller has entered [`wait`](Self::wait).
    ///
    /// # Panics
    ///
    /// If no caller enters within [`bound`](Self::bound).
    pub async fn until_entered(&self) {
        let entered = tokio::time::timeout(self.bound, self.entered()).await;
        assert!(
            entered.is_ok(),
            "no caller entered the gate within {:?}",
            self.bound
        );
    }

    /// Let every parked and future [`wait`](Self::wait) return.
    pub fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
        self.open_notify.notify_waiters();
    }

    async fn entered(&self) {
        loop {
            let entered = self.entered_notify.notified();
            if self.is_entered() {
                return;
            }
            entered.await;
        }
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
/// If the task finished without entering the gate (the code under test never
/// reached the gated call), if it neither entered nor finished within the
/// gate's [`bound`](Gate::bound), or if it finished instead of being
/// cancelled: the gate did not hold it.
pub async fn abort_inside<T: 'static>(gate: &Gate, mut handle: tokio::task::JoinHandle<T>) {
    let reached = tokio::time::timeout(gate.bound(), entered_or_finished(gate, &mut handle)).await;
    match reached {
        Ok(Reached::Entered) => {}
        Ok(Reached::Finished) => {
            panic!("the task finished without entering the gate: it never reached the gated call")
        }
        Err(_) => {
            handle.abort();
            panic!(
                "the task neither entered the gate nor finished within {:?}",
                gate.bound()
            );
        }
    }
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

/// What the task under [`abort_inside`] did first.
enum Reached {
    Entered,
    Finished,
}

/// Wait until a caller enters `gate` or `handle`'s task ends, whichever comes
/// first; entering wins a tie, so a task that entered and then ended still
/// reaches the cancellation check.
async fn entered_or_finished<T>(gate: &Gate, handle: &mut tokio::task::JoinHandle<T>) -> Reached {
    let mut entered = std::pin::pin!(gate.entered());
    std::future::poll_fn(|cx| {
        if entered.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Reached::Entered);
        }
        if handle.is_finished() || Pin::new(&mut *handle).poll(cx).is_ready() {
            return Poll::Ready(Reached::Finished);
        }
        Poll::Pending
    })
    .await
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
