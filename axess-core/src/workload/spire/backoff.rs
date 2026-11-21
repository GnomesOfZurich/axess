//! How long a watcher waits between two attempts that failed.

use std::time::Duration;

use axess_rng::SecureRng;

/// The waits between failed attempts: the first is about `initial`, each
/// further one twice the last, none longer than `max`.
///
/// Every wait is drawn between half its nominal length and the whole of it,
/// from the client's random source, so that the workloads of a node do not
/// all return to a restarted agent in the same instant.
///
/// ```
/// use axess_core::workload::spire::BackoffPolicy;
/// use std::time::Duration;
///
/// let policy = BackoffPolicy::new(Duration::from_millis(500), Duration::from_secs(20));
/// assert_eq!(policy.initial(), Duration::from_millis(500));
/// // A maximum below the initial wait is raised to it.
/// let flat = BackoffPolicy::new(Duration::from_secs(5), Duration::from_secs(1));
/// assert_eq!(flat.max(), Duration::from_secs(5));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    initial: Duration,
    max: Duration,
}

impl BackoffPolicy {
    /// The shortest initial wait: a watcher that retried faster would spin
    /// on an agent that is down.
    pub const MIN_INITIAL: Duration = Duration::from_millis(10);

    /// A policy starting at `initial` and capped at `max`. An `initial`
    /// below [`MIN_INITIAL`](Self::MIN_INITIAL) is raised to it, and a `max`
    /// below `initial` is raised to `initial`.
    pub fn new(initial: Duration, max: Duration) -> Self {
        let initial = initial.max(Self::MIN_INITIAL);
        Self {
            initial,
            max: max.max(initial),
        }
    }

    /// The nominal first wait.
    pub fn initial(&self) -> Duration {
        self.initial
    }

    /// The longest nominal wait.
    pub fn max(&self) -> Duration {
        self.max
    }
}

impl Default for BackoffPolicy {
    /// One second at first, thirty at most.
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(30))
    }
}

/// One run of waits under a policy: each wait about twice the last, until
/// the run is reset. A watcher keeps two, one for attempts that failed and
/// one for answers that brought nothing newer, so that neither count is
/// taken for the other.
#[derive(Debug, Clone)]
pub(crate) struct Backoff {
    policy: BackoffPolicy,
    steps: u32,
}

impl Backoff {
    pub(crate) fn new(policy: BackoffPolicy) -> Self {
        Self { policy, steps: 0 }
    }

    /// How many waits the run has given since it was last reset.
    pub(crate) fn steps(&self) -> u32 {
        self.steps
    }

    /// End the run: the next wait is the first again.
    pub(crate) fn reset(&mut self) {
        self.steps = 0;
    }

    /// The length the next wait is drawn around: the initial wait doubled
    /// once for each wait already given, and never more than the maximum.
    /// The doubling stops at the maximum, whatever the policy's span.
    fn nominal(&self) -> Duration {
        let mut nominal = self.policy.initial;
        for _ in 0..self.steps {
            if nominal >= self.policy.max {
                break;
            }
            nominal = nominal.saturating_mul(2);
        }
        nominal.min(self.policy.max)
    }

    /// Count one more step of the run and give its wait.
    pub(crate) fn next_wait(&mut self, rng: &dyn SecureRng) -> Duration {
        let nominal = self.nominal();
        self.steps = self.steps.saturating_add(1);
        let half = nominal / 2;
        let spread = u64::try_from((nominal - half).as_nanos()).unwrap_or(u64::MAX);
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        // The modulo bias is of no consequence for a jitter.
        let extra = u64::from_le_bytes(bytes) % spread.saturating_add(1);
        half + Duration::from_nanos(extra)
    }
}

#[cfg(test)]
mod tests;
