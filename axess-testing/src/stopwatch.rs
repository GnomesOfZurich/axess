//! The real duration of real work, for a test that compares the cost of two
//! code paths or bounds how long a request may take.
//!
//! A test's world runs on a `MockClock`, and nothing in it reads the
//! machine's clock. How long a password hash, a slow identity provider or a
//! timed-out request took is not a time in that world: it is the machine's,
//! and [`Stopwatch`] is the one way a test reads it
//! (`scripts/check-clock-usage.sh` refuses every other). It reads tokio's
//! monotonic clock, so under a paused runtime (`start_paused`) it measures
//! the runtime's time, which the test moves.
//!
//! ```
//! use axess_testing::stopwatch::Stopwatch;
//! use std::time::Duration;
//!
//! let watch = Stopwatch::start();
//! let digest: u64 = (0..10_000u64).map(|n| n.wrapping_mul(31)).sum();
//! assert!(digest > 0);
//! assert!(watch.elapsed() < Duration::from_secs(60), "the work took {:?}", watch.elapsed());
//! ```

use std::time::Duration;

/// A running measurement of real elapsed time, started by
/// [`Stopwatch::start`].
#[derive(Debug, Clone, Copy)]
pub struct Stopwatch {
    started: tokio::time::Instant,
}

impl Stopwatch {
    /// Start measuring now.
    pub fn start() -> Self {
        Self {
            started: tokio::time::Instant::now(),
        }
    }

    /// The time since [`start`](Self::start).
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}
