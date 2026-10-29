//! Long-term archival of authentication audit events.
//!
//! axess's hot audit path lives behind
//! [`IdentityAuthnLog`](crate::authn::store::IdentityAuthnLog): events are
//! persisted to whatever table the adopter's `Backend` chooses. Finance
//! adopters typically need retention measured in years (SOX 7y, MiFID II
//! 5y, Swiss FINMA 10y), but keeping multi-year rows in the hot table
//! hurts query speed and storage cost. This module defines the
//! abstraction for moving aged rows off the hot path while keeping them
//! available for regulator queries.
//!
//! ## Layering
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ AuthnService → IdentityAuthnLog::record_event(...)           │ ← hot path
//! │                                                              │
//! │ Adopter's `Backend` writes to e.g. `authn_hist` table        │
//! └──────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌──────────────────────────────────────────────────────────────┐
//! │ Periodic task (adopter-owned):                               │
//! │  1. SELECT rows older than `policy.archive_after`            │
//! │  2. Batch send to `AuditArchiver::archive_batch(...)`        │
//! │  3. On success, mark rows archived (separate column or       │
//! │     audit_archive_journal table)                             │
//! │  4. After `policy.purge_hot_after_archive`, DELETE archived  │
//! │     rows from the hot table                                  │
//! │  5. Expiry from cold storage is the sink's own job; the      │
//! │     policy has no field for it and axess never deletes       │
//! └──────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌──────────────────────────────────────────────────────────────┐
//! │ AuditArchiver impl: FS / S3 / Glacier / WORM appliance       │ ← cold path
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! axess does **not** drive the loop. The adopter owns the data flow
//! (they own the SQL, the cron schedule, and the "mark archived"
//! semantics); axess just standardises the sink shape so multiple
//! adopters share archiver implementations.
//!
//! ## Why a trait, not a runtime
//!
//! Finance archive sinks vary widely: S3 + Object Lock for cloud-native,
//! NFS-mounted WORM appliances for on-prem banks, hash-chained Postgres
//! tables for adopters who want everything in one place. Pinning a
//! concrete sink in axess would force adopters to pick our choice or
//! reimplement the whole pipeline. The trait keeps the contract
//! ("durably persist these events") narrow enough that any of those
//! shapes can satisfy it.

use crate::authn::event::AuthEvent;
use std::time::Duration;

/// Stable identity of one archive batch.
///
/// Derived from the source id of every event in the batch, so the retention
/// loop hands the same id to the archiver every time it re-sends the same
/// rows after a failed `mark_archived`, whatever order the select returned
/// them in. An archiver that records the ids it has applied can then skip a
/// repeat. Two batches that differ in any row, even one in the middle, have
/// different ids. The value is a lowercase hex digest, safe to use in file
/// names and object keys.
///
/// The id is stable for a re-selection of the same rows. If rows became
/// eligible between two ticks and the retry selects a larger batch, it has
/// a different id and the archiver sees it as new work.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArchiveBatchId(String);

impl ArchiveBatchId {
    /// The id for a batch whose events have the given source ids, which
    /// render as the strings in `ids`. The order they are given in does not
    /// matter.
    pub fn from_ids<I, S>(ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        use sha2::{Digest, Sha256};
        let mut sorted: Vec<S> = ids.into_iter().collect();
        sorted.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
        let mut h = Sha256::new();
        h.update((sorted.len() as u64).to_be_bytes());
        for id in &sorted {
            // Length-prefixed so ("ab","c") and ("a","bc") differ.
            h.update((id.as_ref().len() as u64).to_be_bytes());
            h.update(id.as_ref().as_bytes());
        }
        let mut hex = String::with_capacity(64);
        for b in h.finalize() {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        Self(hex)
    }

    /// The id as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ArchiveBatchId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Long-term archival sink for [`AuthEvent`] records.
///
/// Implementors write batches of events to wherever the adopter's
/// retention policy requires they live for the regulator's lifetime.
/// The trait deliberately exposes only the "write a batch" operation;
/// the loop that decides *when* to archive and *what* to delete from
/// the hot table is adopter-owned.
pub trait AuditArchiver: Send + Sync + 'static {
    /// Backend-specific error type. Most implementations will wrap an
    /// I/O error, an HTTP error, or both.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Write a batch of events to long-term storage.
    ///
    /// Returns `Ok(())` **only** when the batch is durably persisted to
    /// the cold sink. The caller takes this as the green light to mark
    /// the corresponding hot-table rows as archived. If the call
    /// returns `Err(_)`, the rows MUST remain on the hot path; the
    /// caller retries on the next scheduled tick.
    ///
    /// The same events can arrive again after a successful call: marking
    /// the rows archived is a separate step, and when it fails the next
    /// tick re-sends them. A re-sent batch carries the same `batch` id, so
    /// a sink that records the ids it has applied (as
    /// [`FilesystemAuditArchiver`] does) treats a repeat as already done;
    /// a sink that does not leaves duplicates for its consumers to tolerate.
    /// Identical events in different batches have different ids and are
    /// both stored.
    ///
    /// Implementations SHOULD batch internally where it makes sense
    /// (e.g. S3 multipart upload, filesystem fsync coalescing) but
    /// MUST treat the per-call batch as atomic: partial archive is
    /// worse than no archive because adopters then have to reason
    /// about which subset succeeded.
    fn archive_batch(
        &self,
        batch: &ArchiveBatchId,
        events: &[AuthEvent],
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Human-readable name for logs and dashboards. Static so adopters
    /// don't pay a heap allocation per log line.
    fn name(&self) -> &'static str;
}

/// Two-stage retention policy for the audit-archive pipeline.
///
/// The thresholds answer two independent questions:
///
/// 1. **When should the hot table stop carrying this row?**
///    [`archive_after`](Self::archive_after): the row gets shipped to
///    the cold sink at this age. Tunes hot-table size + query speed.
/// 2. **How long after archive do we keep the hot row as a safety
///    window?** [`purge_hot_after_archive`](Self::purge_hot_after_archive)
///    verifies the cold sink really got it before the hot copy
///    disappears.
///
/// The policy says nothing about when the archived copy is deleted:
/// [`AuditArchiver`] has no delete operation, and the cold sink owns its
/// own expiry (object-store lifecycle rules, WORM retention, a scheduled
/// job). Most finance adopters never expire it; deletion gets the firm
/// fined.
///
/// # Finance regimes (informational)
///
/// | Regime | Minimum retention |
/// |---|---|
/// | SOX (US) | 7 years |
/// | MiFID II (EU) | 5 years |
/// | FinCEN / BSA (US) | 5 years |
/// | FINMA (CH) | 10 years for KYC + transactions |
///
/// The defaults below (`archive_after: 90d`, `purge_hot_after_archive: 7d`)
/// are conservative-by-default for finance shops. Override per the
/// regulator your adopter answers to.
#[derive(Debug, Clone)]
pub struct AuditRetentionPolicy {
    /// Move from hot table to archive once an event reaches this age.
    ///
    /// Smaller values keep the hot table fast at the cost of more
    /// frequent archive writes. Typical: 30 to 180 days.
    pub archive_after: Duration,

    /// Wait this long after a successful archive before deleting the
    /// hot row. A safety window for verification: if the cold sink is
    /// later found to be missing the event, the hot copy is still
    /// available to re-archive. Typical: 7 to 30 days.
    pub purge_hot_after_archive: Duration,
}

impl Default for AuditRetentionPolicy {
    fn default() -> Self {
        Self {
            archive_after: Duration::from_secs(90 * 24 * 60 * 60),
            purge_hot_after_archive: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

impl AuditRetentionPolicy {
    /// Fluent: set the hot→archive cutoff age.
    pub fn with_archive_after(mut self, d: Duration) -> Self {
        self.archive_after = d;
        self
    }

    /// Fluent: set the post-archive hot-table purge window.
    pub fn with_purge_hot_after_archive(mut self, d: Duration) -> Self {
        self.purge_hot_after_archive = d;
        self
    }
}

/// No-op archiver. Reports successful archive without persisting
/// anything: useful as a default placeholder during development or
/// when wiring axess into a stack where audit retention is handled by
/// a separate process the adopter manages outside the library.
///
/// **Do not deploy this in production**: events get acknowledged
/// (the adopter's loop will then delete them from the hot table) but
/// no cold copy exists.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditArchiver;

impl AuditArchiver for NoopAuditArchiver {
    type Error = std::convert::Infallible;

    async fn archive_batch(
        &self,
        _batch: &ArchiveBatchId,
        events: &[AuthEvent],
    ) -> Result<(), Self::Error> {
        tracing::trace!(
            target: "axess::audit::archive",
            count = events.len(),
            "NoopAuditArchiver: batch acknowledged, no cold-storage copy made",
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}

// ── Retention loop ───────────────────────────────────────────────────────────
//
// `AuditRetentionLoop<S, A>` drives the hot→cold pipeline on a
// schedule. The adopter implements `AuditRetentionSource` with three
// SQL methods that own the schema; axess owns the scheduling +
// retry + batch sizing. Splits the responsibility along the same
// line as `AuditArchiver` vs `IdentityAuthnLog`: library defines
// the trait, adopter owns the data layer.

/// The instant `age` before `now`, or the earliest representable instant
/// when `age` is too large to subtract.
///
/// A retention age of `Duration::MAX` means "never": it must yield a cutoff
/// that matches no row, not one that falls back to `now` and matches all.
fn cutoff_before(
    now: chrono::DateTime<chrono::Utc>,
    age: Duration,
) -> chrono::DateTime<chrono::Utc> {
    chrono::Duration::from_std(age)
        .ok()
        .and_then(|d| now.checked_sub_signed(d))
        .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC)
}

/// Adopter-implemented data-access primitive for the retention loop.
///
/// Each method maps to one SQL operation against the adopter's
/// `authn_hist` (or equivalent) table:
///
/// - [`select_unarchived_before`](Self::select_unarchived_before):
///   `SELECT … WHERE event_time < ? AND archived_at IS NULL ORDER BY event_time ASC LIMIT ?`
/// - [`mark_archived`](Self::mark_archived):
///   `UPDATE authn_hist SET archived_at = ? WHERE id = ANY(?)`
/// - [`purge_hot_archived_before`](Self::purge_hot_archived_before):
///   `DELETE FROM authn_hist WHERE archived_at IS NOT NULL AND archived_at < ?`
///
/// `EventId` is adopter-typed so the trait works with whatever PK
/// shape the adopter chose: `i64` for `BIGSERIAL`, `uuid::Uuid` for
/// `UUID PRIMARY KEY`, a `String` for adopters mixing schemas.
pub trait AuditRetentionSource: Send + Sync + 'static {
    /// Primary-key type of the adopter's audit row. Used to identify
    /// which rows just got archived so `mark_archived` can target
    /// them precisely.
    ///
    /// It must be `Display`: the ids of a batch name it to the archiver (see
    /// [`ArchiveBatchId`]).
    type EventId: Clone + std::fmt::Display + Send + Sync + 'static;

    /// Backend-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Select up to `limit` events older than `cutoff` that have not
    /// yet been archived. Returns `(id, event)` pairs ordered by
    /// `event_time` ascending so retries make forward progress.
    fn select_unarchived_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> impl std::future::Future<Output = Result<Vec<(Self::EventId, AuthEvent)>, Self::Error>> + Send;

    /// Mark the given rows as archived. Called once per successful
    /// `archive_batch`. Implementations should set the row's
    /// `archived_at` column to `at` (or insert into a journal table).
    fn mark_archived(
        &self,
        ids: &[Self::EventId],
        at: chrono::DateTime<chrono::Utc>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Delete hot-table rows whose `archived_at < cutoff`. Returns
    /// the number of rows deleted.
    fn purge_hot_archived_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> impl std::future::Future<Output = Result<u64, Self::Error>> + Send;
}

/// The most ticks one [`AuditRetentionLoop::drain`] runs before it yields
/// back to the loop's rest interval.
pub const MAX_TICKS_PER_DRAIN: usize = 100;

/// Outcome of one retention-loop tick.
#[derive(Debug, Default, Clone, Copy)]
pub struct RetentionTickReport {
    /// Number of events successfully shipped to the archiver this tick (or,
    /// from `drain`, across all its ticks).
    pub archived: u64,
    /// Number of hot rows deleted post-verification-window this tick.
    pub purged: u64,
}

/// Errors surfaced by [`AuditRetentionLoop::tick`].
#[derive(Debug, thiserror::Error)]
pub enum RetentionError<S, A>
where
    S: std::error::Error + Send + Sync + 'static,
    A: std::error::Error + Send + Sync + 'static,
{
    /// Adopter's [`AuditRetentionSource`] returned an error.
    #[error("retention source: {0}")]
    Source(#[source] S),

    /// [`AuditArchiver::archive_batch`] returned an error.
    #[error("archiver: {0}")]
    Archiver(#[source] A),
}

/// Drives the hot → archive → purge pipeline on a schedule.
///
/// Adopter wiring:
///
/// 1. Implement [`AuditRetentionSource`] against your `authn_hist`
///    table (~30 LOC of SQL).
/// 2. Pick an [`AuditArchiver`] impl
///    ([`NoopAuditArchiver`] for tests, [`FilesystemAuditArchiver`]
///    for prototyping, your own S3 / WORM sink for production).
/// 3. Construct an [`AuditRetentionPolicy`] for your regulatory
///    floor.
/// 4. `AuditRetentionLoop::new(source, archiver, policy).spawn()`:
///    returns a `JoinHandle` for the task running the loop. Dropping the
///    handle detaches the task, which keeps running; abort the handle
///    (tokio's `abort` on it) to stop it.
///
/// The loop wakes once per `tick_interval` (default 1 hour) and ticks back to
/// back while ticks come back full (see [`drain`](Self::drain)), archiving up
/// to `batch_size` events per tick (default 10 000). Override with the fluent
/// setters before `spawn`.
///
/// # Time
///
/// What each tick does is measured against the injected
/// [`Clock`](axess_clock::Clock): the archive and purge cutoffs come from
/// `clock.now()`. The pacing of the ticks themselves is the Tokio runtime's
/// timer (`tokio::time::sleep`), outside the `Clock` seam; drive
/// [`tick`](Self::tick) or [`drain`](Self::drain) from your own scheduler to
/// control it. A drain that overruns the interval is followed by a full
/// interval of rest rather than by catch-up drains for the intervals it missed.
pub struct AuditRetentionLoop<S, A>
where
    S: AuditRetentionSource,
    A: AuditArchiver,
{
    source: std::sync::Arc<S>,
    archiver: std::sync::Arc<A>,
    policy: AuditRetentionPolicy,
    tick_interval: Duration,
    batch_size: usize,
    clock: std::sync::Arc<dyn axess_clock::Clock>,
}

impl<S, A> AuditRetentionLoop<S, A>
where
    S: AuditRetentionSource,
    A: AuditArchiver,
{
    /// Construct a loop with default schedule (1-hour tick, 10 000
    /// events per batch, `SystemClock`).
    pub fn new(source: S, archiver: A, policy: AuditRetentionPolicy) -> Self {
        Self {
            source: std::sync::Arc::new(source),
            archiver: std::sync::Arc::new(archiver),
            policy,
            tick_interval: Duration::from_secs(3600),
            batch_size: 10_000,
            clock: std::sync::Arc::new(axess_clock::SystemClock),
        }
    }

    /// Fluent: override the tick interval. Smaller values make
    /// archive latency shorter at the cost of more frequent SELECT
    /// round-trips. Defaults to 1 hour.
    pub fn with_tick_interval(mut self, d: Duration) -> Self {
        self.tick_interval = d;
        self
    }

    /// Fluent: override the per-tick batch ceiling. Larger values
    /// reduce per-tick overhead; smaller values shrink the failure
    /// blast radius if `archive_batch` rejects the whole batch on
    /// transient I/O. Defaults to 10 000.
    pub fn with_batch_size(mut self, n: usize) -> Self {
        self.batch_size = n.max(1);
        self
    }

    /// Fluent: inject a [`Clock`](axess_clock::Clock) for
    /// deterministic-simulation testing.
    pub fn with_clock(mut self, c: std::sync::Arc<dyn axess_clock::Clock>) -> Self {
        self.clock = c;
        self
    }

    /// Run a single tick. Useful for tests and for adopters who
    /// want to drive the cycle from their own scheduler instead of
    /// spawning the built-in loop.
    pub async fn tick(&self) -> Result<RetentionTickReport, RetentionError<S::Error, A::Error>> {
        let now = self.clock.now();
        let archive_cutoff = cutoff_before(now, self.policy.archive_after);
        let purge_cutoff = cutoff_before(now, self.policy.purge_hot_after_archive);

        let batch = self
            .source
            .select_unarchived_before(archive_cutoff, self.batch_size)
            .await
            .map_err(RetentionError::Source)?;

        let mut report = RetentionTickReport::default();

        if !batch.is_empty() {
            let (ids, events): (Vec<S::EventId>, Vec<AuthEvent>) = batch.into_iter().unzip();
            let batch_id = ArchiveBatchId::from_ids(ids.iter().map(ToString::to_string));
            self.archiver
                .archive_batch(&batch_id, &events)
                .await
                .map_err(RetentionError::Archiver)?;
            self.source
                .mark_archived(&ids, now)
                .await
                .map_err(RetentionError::Source)?;
            report.archived = events.len() as u64;
        }

        let purged = self
            .source
            .purge_hot_archived_before(purge_cutoff)
            .await
            .map_err(RetentionError::Source)?;
        report.purged = purged;

        Ok(report)
    }

    /// Run ticks back to back until the backlog is cleared.
    ///
    /// Calls [`tick`](Self::tick) again while the last one archived a full
    /// batch, and stops at the first short batch (nothing more is eligible),
    /// at the first error, or after [`MAX_TICKS_PER_DRAIN`] ticks, so a
    /// source that never runs dry cannot hold the task forever; the next wake
    /// carries on. The reports are summed. When a later tick fails, the
    /// batches the earlier ones archived stay archived and marked, and the
    /// error is what comes back.
    pub async fn drain(&self) -> Result<RetentionTickReport, RetentionError<S::Error, A::Error>> {
        let mut total = RetentionTickReport::default();
        for _ in 0..MAX_TICKS_PER_DRAIN {
            let report = self.tick().await?;
            total.archived += report.archived;
            total.purged += report.purged;
            if report.archived < self.batch_size as u64 {
                break;
            }
        }
        Ok(total)
    }

    /// Spawn the loop on the current Tokio runtime. Dropping the returned
    /// `JoinHandle` does not stop the loop (the task is detached); call
    /// `abort` on it to stop retention, and keep it for that purpose for
    /// the lifetime of the application.
    ///
    /// The task drains the backlog (see [`drain`](Self::drain)) as soon as
    /// it starts and again after each `tick_interval`, so a process that
    /// restarts more often than the interval still archives, and sustained
    /// volume above one batch per interval does not pile up in the hot table.
    ///
    /// Tick errors are logged at `warn` and the loop keeps running
    /// so a single transient DB / archive blip does not silently
    /// halt retention forever. Persistent failures should surface
    /// via the warn-log volume + external alerting.
    ///
    /// # One runner
    ///
    /// Run this loop in one process at a time. The loop takes no lock and
    /// has no leader election, so every replica that spawns it selects the
    /// same unarchived rows, writes the same batches and purges the same
    /// rows. Nothing is lost or corrupted: a batch id is derived from the
    /// ids of its events, so a sink that records applied ids (as
    /// [`FilesystemAuditArchiver`] does) treats the repeat as done, marking
    /// and purging are idempotent, and the cutoffs come from each replica's
    /// own clock. But the work is repeated on every replica, and a sink that
    /// does not deduplicate stores each batch once per replica. Spawn it on
    /// one designated instance (a singleton job, or a replica chosen by
    /// your orchestrator), or make the source's selection exclusive across
    /// replicas (a Postgres advisory lock held across the tick, or
    /// `SELECT ... FOR UPDATE SKIP LOCKED` in
    /// [`select_unarchived_before`](AuditRetentionSource::select_unarchived_before)).
    /// [`tick`](Self::tick) and [`drain`](Self::drain) let you drive the same
    /// cycle from a scheduler that already guarantees a single runner.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        let interval_dur = self.tick_interval;
        tokio::spawn(async move {
            loop {
                match self.drain().await {
                    Ok(report) if report.archived > 0 || report.purged > 0 => {
                        tracing::debug!(
                            archived = report.archived,
                            purged = report.purged,
                            "audit retention drain",
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "audit retention drain failed; loop continuing");
                    }
                }
                // A full interval of rest after each drain, however long it
                // took: an overrunning drain is not followed by catch-up
                // drains for the intervals it missed.
                tokio::time::sleep(interval_dur).await;
            }
        })
    }
}

// ── Filesystem reference implementation ──────────────────────────────────────

#[cfg(feature = "audit-archive-fs")]
mod filesystem;
#[cfg(feature = "audit-archive-fs")]
pub use filesystem::{FilesystemArchiveError, FilesystemAuditArchiver};

#[cfg(test)]
mod drain;
#[cfg(test)]
mod pacing;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_archiver_accepts_any_batch() {
        let archiver = NoopAuditArchiver;
        let result = archiver
            .archive_batch(&ArchiveBatchId::from_ids(["0"]), &[])
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn default_policy_archives_at_90_days_and_purges_hot_after_7() {
        let p = AuditRetentionPolicy::default();
        assert_eq!(p.archive_after, Duration::from_secs(90 * 24 * 60 * 60));
        assert_eq!(
            p.purge_hot_after_archive,
            Duration::from_secs(7 * 24 * 60 * 60)
        );
    }

    #[test]
    fn policy_builder_chain_overrides_each_threshold() {
        let p = AuditRetentionPolicy::default()
            .with_archive_after(Duration::from_secs(60 * 24 * 60 * 60))
            .with_purge_hot_after_archive(Duration::from_secs(14 * 24 * 60 * 60));

        assert_eq!(p.archive_after.as_secs(), 60 * 24 * 60 * 60);
        assert_eq!(p.purge_hot_after_archive.as_secs(), 14 * 24 * 60 * 60);
    }

    #[test]
    fn maximum_age_yields_a_cutoff_that_matches_nothing() {
        let now = chrono::Utc::now();
        assert_eq!(
            cutoff_before(now, Duration::MAX),
            chrono::DateTime::<chrono::Utc>::MIN_UTC
        );
        let day = Duration::from_secs(24 * 60 * 60);
        assert_eq!(cutoff_before(now, day), now - chrono::Duration::days(1));
    }

    #[derive(Default)]
    struct CutoffSource(std::sync::Mutex<Vec<chrono::DateTime<chrono::Utc>>>);

    impl AuditRetentionSource for CutoffSource {
        type EventId = u64;
        type Error = std::convert::Infallible;

        async fn select_unarchived_before(
            &self,
            cutoff: chrono::DateTime<chrono::Utc>,
            _: usize,
        ) -> Result<Vec<(u64, AuthEvent)>, Self::Error> {
            self.0.lock().unwrap().push(cutoff);
            Ok(vec![])
        }
        async fn mark_archived(
            &self,
            _: &[u64],
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn purge_hot_archived_before(
            &self,
            cutoff: chrono::DateTime<chrono::Utc>,
        ) -> Result<u64, Self::Error> {
            self.0.lock().unwrap().push(cutoff);
            Ok(0)
        }
    }

    #[tokio::test]
    async fn tick_with_maximum_retention_selects_and_purges_nothing() {
        let policy = AuditRetentionPolicy::default()
            .with_archive_after(Duration::MAX)
            .with_purge_hot_after_archive(Duration::MAX);
        let lp = AuditRetentionLoop::new(CutoffSource::default(), NoopAuditArchiver, policy);
        lp.tick().await.unwrap();
        let cutoffs = lp.source.0.lock().unwrap().clone();
        assert_eq!(cutoffs.len(), 2);
        for c in cutoffs {
            assert_eq!(c, chrono::DateTime::<chrono::Utc>::MIN_UTC);
        }
    }
}
