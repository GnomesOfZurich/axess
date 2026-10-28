//! Where deliberately slow, CPU-bound work runs.
//!
//! Argon2id takes tens of milliseconds and 19 MiB per run. Done inline in an
//! async handler it holds a runtime worker for that whole time, and a burst of
//! logins starves every other task on the runtime. [`KdfExecutor::run`](crate::blocking::KdfExecutor::run) moves
//! the work onto the blocking pool instead, behind a [`Semaphore`](tokio::sync::Semaphore) sized to the
//! CPU count so a burst queues in the async layer (where waiting is free)
//! rather than filling the blocking pool with memory-hungry jobs.
//!
//! The executor is a value, not a global, so a deterministic test can swap it:
//! [`KdfExecutor::inline`](crate::blocking::KdfExecutor::inline) runs each job on the calling task, in order, and
//! counts them, which makes "how many hashes did this flow run" an assertion.
//! The service holds one and takes a replacement through
//! `AuthnServiceBuilder::with_kdf_executor`.
//!
//! Data moved into a job must be owned (`'static`): clone what the job needs,
//! and wrap secrets in [`zeroize::Zeroizing`] so the copy is wiped when the job
//! ends.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Semaphore;

/// Why a job did not produce a value.
#[derive(Debug, thiserror::Error)]
pub enum KdfError {
    /// The blocking task panicked or was cancelled before it finished.
    #[error("blocking task failed: {0}")]
    Join(String),
    /// The admission semaphore was closed.
    #[error("blocking executor is shut down")]
    Closed,
}

#[derive(Debug)]
enum Mode {
    /// `tokio::task::spawn_blocking`, admitted through the semaphore.
    Pool,
    /// Run on the calling task. For tests.
    Inline,
}

/// Runs slow synchronous jobs off the async executor.
///
/// Cheap to share: hold one in an `Arc`.
#[derive(Debug)]
pub struct KdfExecutor {
    mode: Mode,
    permits: Arc<Semaphore>,
    started: AtomicU64,
}

impl KdfExecutor {
    /// The production executor: the blocking pool, at most one job per CPU at
    /// a time.
    pub fn pool() -> Self {
        let cpus = std::thread::available_parallelism().map_or(1, usize::from);
        Self::pool_with_permits(cpus)
    }

    /// The blocking pool with an explicit concurrency limit (minimum 1).
    pub fn pool_with_permits(permits: usize) -> Self {
        Self {
            mode: Mode::Pool,
            permits: Arc::new(Semaphore::new(permits.max(1))),
            started: AtomicU64::new(0),
        }
    }

    /// Runs every job on the calling task, in call order. For deterministic
    /// tests; it blocks the runtime worker for the job's duration, which is
    /// the thing the pool exists to avoid.
    pub fn inline() -> Self {
        Self {
            mode: Mode::Inline,
            permits: Arc::new(Semaphore::new(Semaphore::MAX_PERMITS)),
            started: AtomicU64::new(0),
        }
    }

    /// How many jobs have been started on this executor.
    pub fn jobs_started(&self) -> u64 {
        self.started.load(Ordering::Relaxed)
    }

    /// Run `job` and return its value.
    ///
    /// A panic inside the job comes back as [`KdfError::Join`] on the pool; on
    /// the inline executor it unwinds into the caller, as any panic would.
    pub async fn run<T, F>(&self, job: F) -> Result<T, KdfError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| KdfError::Closed)?;
        self.started.fetch_add(1, Ordering::Relaxed);
        match self.mode {
            Mode::Inline => {
                let _permit = permit;
                Ok(job())
            }
            // The permit moves into the blocking closure, so it is released
            // when the job ends and not when the caller's future is dropped:
            // a dropped `JoinHandle` detaches the job without stopping it.
            Mode::Pool => tokio::task::spawn_blocking(move || {
                let _permit = permit;
                job()
            })
            .await
            .map_err(|e| KdfError::Join(e.to_string())),
        }
    }
}

impl Default for KdfExecutor {
    fn default() -> Self {
        Self::pool()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn inline_runs_the_job_and_counts_it() {
        let ex = KdfExecutor::inline();
        assert_eq!(ex.run(|| 2 + 2).await.unwrap(), 4);
        assert_eq!(ex.run(|| "x").await.unwrap(), "x");
        assert_eq!(ex.jobs_started(), 2);
    }

    #[tokio::test]
    async fn the_pool_runs_on_a_different_thread_than_the_caller() {
        let ex = KdfExecutor::pool();
        let caller = std::thread::current().id();
        let job = ex.run(|| std::thread::current().id()).await.unwrap();
        assert_ne!(caller, job, "the job ran on the blocking pool");
        assert_eq!(ex.jobs_started(), 1);
    }

    #[tokio::test]
    async fn a_panicking_job_is_an_error_not_a_crash() {
        let ex = KdfExecutor::pool();
        let err = ex
            .run(|| -> u8 { panic!("boom") })
            .await
            .expect_err("a panic is reported");
        assert!(matches!(err, KdfError::Join(_)), "got {err:?}");
    }

    /// The reason the pool exists: while a job runs, the runtime's only
    /// worker is free to run other tasks. Inline, it is not.
    #[tokio::test(flavor = "current_thread")]
    async fn a_pool_job_leaves_the_runtime_free_and_an_inline_one_does_not() {
        async fn ticks_during(ex: KdfExecutor) -> usize {
            let ticks = Arc::new(AtomicUsize::new(0));
            let counter = ticks.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    tokio::task::yield_now().await;
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            });
            ex.run(|| std::thread::sleep(std::time::Duration::from_millis(60)))
                .await
                .unwrap();
            let seen = ticks.load(Ordering::SeqCst);
            ticker.abort();
            seen
        }
        assert!(ticks_during(KdfExecutor::pool()).await > 0);
        assert_eq!(ticks_during(KdfExecutor::inline()).await, 0);
    }

    /// A caller that is dropped mid-job (a client that disconnects) must not
    /// free its permit while the job is still running.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_dropped_caller_keeps_its_permit_until_the_job_ends() {
        let ex = Arc::new(KdfExecutor::pool_with_permits(1));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let job = |running: Arc<AtomicUsize>, peak: Arc<AtomicUsize>| {
            move || {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(200));
                running.fetch_sub(1, Ordering::SeqCst);
            }
        };
        let first = {
            let (ex, r, p) = (ex.clone(), running.clone(), peak.clone());
            tokio::spawn(async move { ex.run(job(r, p)).await })
        };
        while running.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        first.abort();
        let _ = first.await;
        ex.run(job(running.clone(), peak.clone())).await.unwrap();
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "the second job started while the first still ran"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_semaphore_caps_concurrent_jobs() {
        let ex = Arc::new(KdfExecutor::pool_with_permits(2));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (ex, running, peak) = (ex.clone(), running.clone(), peak.clone());
            tasks.push(tokio::spawn(async move {
                ex.run(move || {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    running.fetch_sub(1, Ordering::SeqCst);
                })
                .await
                .unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(ex.jobs_started(), 8);
        assert!(
            peak.load(Ordering::SeqCst) <= 2,
            "peak concurrency {} exceeded the 2 permits",
            peak.load(Ordering::SeqCst)
        );
    }
}
