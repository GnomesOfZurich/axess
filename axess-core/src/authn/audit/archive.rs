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
//! │  5. After `policy.delete_archive_after` (if set), delete     │
//! │     from cold storage                                        │
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
    /// Implementations SHOULD batch internally where it makes sense
    /// (e.g. S3 multipart upload, filesystem fsync coalescing) but
    /// MUST treat the per-call batch as atomic: partial archive is
    /// worse than no archive because adopters then have to reason
    /// about which subset succeeded.
    fn archive_batch(
        &self,
        events: &[AuthEvent],
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Human-readable name for logs and dashboards. Static so adopters
    /// don't pay a heap allocation per log line.
    fn name(&self) -> &'static str;
}

/// Three-stage retention policy for the audit-archive pipeline.
///
/// The thresholds answer three independent questions:
///
/// 1. **When should the hot table stop carrying this row?**
///    [`archive_after`](Self::archive_after): the row gets shipped to
///    the cold sink at this age. Tunes hot-table size + query speed.
/// 2. **How long after archive do we keep the hot row as a safety
///    window?** [`purge_hot_after_archive`](Self::purge_hot_after_archive)
///    verifies the cold sink really got it before the hot copy
///    disappears.
/// 3. **When (if ever) should the archived copy be deleted?**
///    [`delete_archive_after`](Self::delete_archive_after): `None`
///    means never (the typical finance default; deletion gets the firm
///    fined). When set, this is the regulator-imposed maximum.
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
/// The defaults below (`archive_after: 90d`, `purge_hot_after_archive: 7d`,
/// `delete_archive_after: None`) are conservative-by-default for
/// finance shops. Override per the regulator your adopter answers to.
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

    /// Total time to keep events in the archive, or `None` for
    /// indefinite retention. `None` is the right default for most
    /// finance adopters: regulators penalise premature deletion far
    /// more harshly than they reward storage savings.
    pub delete_archive_after: Option<Duration>,
}

impl Default for AuditRetentionPolicy {
    fn default() -> Self {
        Self {
            archive_after: Duration::from_secs(90 * 24 * 60 * 60),
            purge_hot_after_archive: Duration::from_secs(7 * 24 * 60 * 60),
            delete_archive_after: None,
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

    /// Fluent: cap total archive retention. Pass `Duration::ZERO` to
    /// explicitly request "delete immediately after the purge window"
    /// (unusual outside dev / test).
    pub fn with_delete_archive_after(mut self, d: Duration) -> Self {
        self.delete_archive_after = Some(d);
        self
    }

    /// Fluent: never delete from the archive. Equivalent to the
    /// default but more explicit at call sites for adopters who want
    /// the intent to read clearly in code review.
    pub fn keep_archive_forever(mut self) -> Self {
        self.delete_archive_after = None;
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

    async fn archive_batch(&self, events: &[AuthEvent]) -> Result<(), Self::Error> {
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
    type EventId: Clone + Send + Sync + 'static;

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

/// Outcome of one retention-loop tick.
#[derive(Debug, Default, Clone, Copy)]
pub struct RetentionTickReport {
    /// Number of events successfully shipped to the archiver this tick.
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
///    returns a `JoinHandle` that runs the loop until dropped.
///
/// The loop runs one tick per `tick_interval` (default 1 hour),
/// archiving up to `batch_size` events per tick (default 10 000).
/// Override with the fluent setters before `spawn`.
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
        let archive_cutoff = now
            - chrono::Duration::from_std(self.policy.archive_after)
                .unwrap_or(chrono::Duration::zero());
        let purge_cutoff = now
            - chrono::Duration::from_std(self.policy.purge_hot_after_archive)
                .unwrap_or(chrono::Duration::zero());

        let batch = self
            .source
            .select_unarchived_before(archive_cutoff, self.batch_size)
            .await
            .map_err(RetentionError::Source)?;

        let mut report = RetentionTickReport::default();

        if !batch.is_empty() {
            let events: Vec<AuthEvent> = batch.iter().map(|(_, e)| e.clone()).collect();
            self.archiver
                .archive_batch(&events)
                .await
                .map_err(RetentionError::Archiver)?;

            let ids: Vec<S::EventId> = batch.into_iter().map(|(id, _)| id).collect();
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

    /// Spawn the loop on the current Tokio runtime. The returned
    /// `JoinHandle` aborts the loop when dropped; keep it for the
    /// lifetime of the application.
    ///
    /// Tick errors are logged at `warn` and the loop keeps running
    /// so a single transient DB / archive blip does not silently
    /// halt retention forever. Persistent failures should surface
    /// via the warn-log volume + external alerting.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        let interval_dur = self.tick_interval;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_dur);
            interval.tick().await; // first tick completes immediately; skip it
            loop {
                interval.tick().await;
                match self.tick().await {
                    Ok(report) if report.archived > 0 || report.purged > 0 => {
                        tracing::debug!(
                            archived = report.archived,
                            purged = report.purged,
                            "audit retention tick",
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "audit retention tick failed; loop continuing");
                    }
                }
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_archiver_accepts_any_batch() {
        let archiver = NoopAuditArchiver;
        let result = archiver.archive_batch(&[]).await;
        assert!(result.is_ok());
    }

    #[test]
    fn default_policy_archives_at_90_days_with_indefinite_retention() {
        let p = AuditRetentionPolicy::default();
        assert_eq!(p.archive_after, Duration::from_secs(90 * 24 * 60 * 60));
        assert_eq!(
            p.purge_hot_after_archive,
            Duration::from_secs(7 * 24 * 60 * 60)
        );
        assert!(p.delete_archive_after.is_none());
    }

    #[test]
    fn policy_builder_chain_overrides_each_threshold() {
        let p = AuditRetentionPolicy::default()
            .with_archive_after(Duration::from_secs(60 * 24 * 60 * 60))
            .with_purge_hot_after_archive(Duration::from_secs(14 * 24 * 60 * 60))
            .with_delete_archive_after(Duration::from_secs(10 * 365 * 24 * 60 * 60));

        assert_eq!(p.archive_after.as_secs(), 60 * 24 * 60 * 60);
        assert_eq!(p.purge_hot_after_archive.as_secs(), 14 * 24 * 60 * 60);
        assert_eq!(
            p.delete_archive_after.map(|d| d.as_secs()),
            Some(10 * 365 * 24 * 60 * 60)
        );
    }

    #[test]
    fn keep_archive_forever_unsets_delete_threshold() {
        let p = AuditRetentionPolicy::default()
            .with_delete_archive_after(Duration::from_secs(60))
            .keep_archive_forever();
        assert!(p.delete_archive_after.is_none());
    }
}
