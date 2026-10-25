//! Filesystem-backed reference implementation of [`AuditArchiver`].
//!
//! Appends JSONL records to a date-partitioned path tree:
//!
//! ```text
//! {root}/{YYYY}/{MM}/{DD}/audit-{YYYY-MM-DD}.jsonl
//! ```
//!
//! Each line is one `AuthEvent` serialised via `serde_json`:
//! human-grepable, append-friendly, and trivially loadable into
//! analytical tools (DuckDB's `read_json_auto`, `jq`, `clickhouse-local`).
//! The day boundary is computed from the event's `event_time` so
//! out-of-order arrivals land in the correct day file.
//!
//! # Durability model
//!
//! Each `archive_batch` call:
//! 1. Groups events by day.
//! 2. Opens every day file in append mode (creates parents if missing)
//!    and records each file's length.
//! 3. Writes every day's events in one buffered write per file.
//! 4. `fsync`s every file before returning.
//!
//! If `fsync` succeeds the call returns `Ok(())`; the adopter then
//! takes that as the green light to mark hot-table rows as archived.
//! If any step fails, every file already touched is truncated back to
//! its recorded length and the call returns `Err`: the batch is
//! all-or-nothing, so the rows stay hot and the next scheduled tick
//! retries the whole batch without duplicating the days that had
//! already been written.
//!
//! # Retried batches
//!
//! The retention loop archives before it marks rows archived, so a
//! failed mark makes the next tick send the same events again, under the
//! same [`ArchiveBatchId`]. Next to each day file the archiver keeps
//! `audit-{YYYY-MM-DD}.jsonl.batches`, one applied batch id per line,
//! written and `fsync`ed in the same all-or-nothing step as the events. A
//! batch whose id is already recorded for any of its days is skipped, so
//! the retry does not duplicate it. Identical events in different batches
//! have different ids and are both appended.
//!
//! The one remaining window is a crash after the event files are durable
//! and before the id is: the retry then appends the batch again, which
//! is at-least-once delivery and never loss. Consumers should still
//! tolerate a repeated line.
//!
//! # Not for production at scale
//!
//! This is a reference implementation. Production finance archives
//! typically want one of:
//!
//! - **S3 with Object Lock**: true WORM, lifecycle to Glacier cold tier.
//! - **NFS-mounted WORM appliance**: bank-grade compliance hardware.
//! - **Hash-chained Postgres table**: same DB, tamper-evident, simpler
//!   ops.
//!
//! The filesystem impl is intended for: on-prem prototyping, single-node
//! deployments where a local mount IS the cold storage, and dev / test
//! pipelines that want a real append-only sink without standing up
//! S3.
//!
//! # Tamper evidence
//!
//! JSONL on a regular filesystem provides *no* tamper evidence: root
//! can rewrite the file. Adopters who need integrity guarantees should
//! either run on a WORM-mounted volume or layer a hash-chain / Merkle-
//! tree wrapper on top of this impl (a separate concern not in scope
//! for the reference shipped here).
//!
//! The extension point is the [`AuditArchiver`] trait itself: a hash-
//! chained wrapper can hold this archiver as `inner` and forward each
//! `archive_batch` call after appending the running head-hash to the
//! batch and persisting the new head to the adopter's anchor of choice
//! (sidecar file, sibling DB row, sigstore transparency log). The
//! anchoring is what makes the chain load-bearing; without it, root
//! can rewrite from any line and recompute. The choice of anchor is
//! tightly coupled to the deployment's compliance regime, so we leave
//! the wrapper to adopters rather than ship a generic stub.

use crate::authn::audit::archive::{ArchiveBatchId, AuditArchiver};
use crate::authn::event::AuthEvent;
use chrono::Datelike;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

/// Errors from the filesystem archiver.
#[derive(Debug, thiserror::Error)]
pub enum FilesystemArchiveError {
    /// `serde_json::to_string` failed on an event.
    #[error("serialise event to JSON: {0}")]
    Serialize(#[from] serde_json::Error),

    /// Filesystem operation failed (open, write, fsync, mkdir).
    #[error("filesystem I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Filesystem reference implementation of [`AuditArchiver`].
///
/// Pass the **root directory** at construction. The archiver creates
/// `{root}/{YYYY}/{MM}/{DD}/` on first write to that day, then appends
/// one JSON object per line to `audit-{YYYY-MM-DD}.jsonl` under that
/// directory.
///
/// Cloneable for use in `tokio::spawn` tasks. The inner mutex
/// serialises writes across clones so concurrent `archive_batch`
/// calls don't interleave bytes inside a single line.
#[derive(Clone)]
pub struct FilesystemAuditArchiver {
    root: PathBuf,
    write_lock: Arc<tokio::sync::Mutex<()>>,
}

impl FilesystemAuditArchiver {
    /// Construct an archiver rooted at `root`. The directory is
    /// created lazily on the first `archive_batch` call; passing a
    /// non-existent path is not an error at construction time.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Borrow the root directory path.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// Compute the on-disk path for events with the given date.
    /// Public so callers writing their own loop can verify whether
    /// archived files exist before deleting hot rows.
    pub fn path_for_date(&self, date: chrono::NaiveDate) -> PathBuf {
        self.root
            .join(format!("{:04}", date.year()))
            .join(format!("{:02}", date.month()))
            .join(format!("{:02}", date.day()))
            .join(format!("audit-{}.jsonl", date.format("%Y-%m-%d")))
    }
}

/// The sidecar that records the batch ids applied to a day file.
fn batches_path(day_file: &std::path::Path) -> PathBuf {
    let mut name = day_file.as_os_str().to_owned();
    name.push(".batches");
    PathBuf::from(name)
}

/// True when `batch_id` is one of the lines of the sidecar at `path`. A
/// missing sidecar records nothing.
fn batch_recorded(path: &std::path::Path, batch_id: &str) -> std::io::Result<bool> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().any(|l| l == batch_id)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Append every buffer to its file, or leave every file as it was.
///
/// Each file's length is recorded before anything is written. All files are
/// opened, written and `fsync`ed; if any step fails, every file already
/// touched is truncated back to its recorded length, so a failed batch
/// leaves no whole or partial line behind and the caller's retry cannot
/// duplicate records. `before_write` runs ahead of each file's write with
/// that file's index and exists so tests can inject a failure mid-batch.
fn append_all_or_none(
    plan: &[(PathBuf, Vec<u8>)],
    before_write: &mut dyn FnMut(usize) -> std::io::Result<()>,
) -> Result<(), FilesystemArchiveError> {
    let mut touched: Vec<(std::fs::File, u64)> = Vec::with_capacity(plan.len());
    let outcome = (|| -> Result<(), FilesystemArchiveError> {
        for (path, _) in plan {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            let original_len = file.metadata()?.len();
            touched.push((file, original_len));
        }
        for (i, (_, buf)) in plan.iter().enumerate() {
            before_write(i)?;
            touched[i].0.write_all(buf)?;
        }
        for (file, _) in &touched {
            file.sync_all()?;
        }
        Ok(())
    })();
    if outcome.is_err() {
        for (file, original_len) in &touched {
            if let Err(e) = file.set_len(*original_len).and_then(|()| file.sync_all()) {
                tracing::error!(
                    error = %e,
                    "could not roll back a partially written audit archive file"
                );
            }
        }
    }
    outcome
}

impl AuditArchiver for FilesystemAuditArchiver {
    type Error = FilesystemArchiveError;

    async fn archive_batch(
        &self,
        batch: &ArchiveBatchId,
        events: &[AuthEvent],
    ) -> Result<(), Self::Error> {
        if events.is_empty() {
            return Ok(());
        }

        // Group events by day (in UTC) so each day file gets one
        // bulk append. `BTreeMap` so iteration order is stable for
        // test determinism + log readability.
        let mut by_day: std::collections::BTreeMap<chrono::NaiveDate, Vec<String>> =
            std::collections::BTreeMap::new();
        for event in events {
            let day = chrono::DateTime::<chrono::Utc>::from_timestamp_micros(event.event_time)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "event_time {} out of range for day bucketing",
                            event.event_time
                        ),
                    )
                })?
                .date_naive();
            let line = serde_json::to_string(event)?;
            by_day.entry(day).or_default().push(line);
        }

        // Serialise concurrent writers across clones so two
        // `archive_batch` calls don't interleave bytes mid-line.
        let write_guard = self.write_lock.lock().await;

        // Spawn-blocking the I/O. `std::fs` doesn't have async
        // primitives, and pulling `tokio::fs` here would still
        // ultimately use a thread-pool; doing it explicitly keeps
        // the async/blocking boundary visible.
        let root = self.root.clone();
        let batch_line = format!("{batch}\n");
        tokio::task::spawn_blocking(move || -> Result<(), FilesystemArchiveError> {
            let day_path = |day: chrono::NaiveDate| {
                root.join(format!("{:04}", day.year()))
                    .join(format!("{:02}", day.month()))
                    .join(format!("{:02}", day.day()))
                    .join(format!("audit-{}.jsonl", day.format("%Y-%m-%d")))
            };
            // A batch is written to every day file or to none, and its id is
            // recorded in the same step, so an id recorded for any of its
            // days means all of its events are already there.
            for day in by_day.keys() {
                if batch_recorded(&batches_path(&day_path(*day)), batch_line.trim_end())? {
                    return Ok(());
                }
            }
            let mut plan: Vec<(PathBuf, Vec<u8>)> = by_day
                .into_iter()
                .map(|(day, lines)| {
                    let path = day_path(day);
                    // Each line ends with `\n` so a file is valid JSONL
                    // whenever its length is a recorded boundary.
                    let mut buf = Vec::with_capacity(lines.iter().map(|s| s.len() + 1).sum());
                    for line in lines {
                        buf.extend_from_slice(line.as_bytes());
                        buf.push(b'\n');
                    }
                    (path, buf)
                })
                .collect();
            let ids: Vec<(PathBuf, Vec<u8>)> = plan
                .iter()
                .map(|(path, _)| (batches_path(path), batch_line.clone().into_bytes()))
                .collect();
            plan.extend(ids);
            append_all_or_none(&plan, &mut |_| Ok(()))
        })
        .await
        .map_err(|join_err| {
            FilesystemArchiveError::Io(std::io::Error::other(format!(
                "spawn_blocking task panicked: {join_err}"
            )))
        })??;

        drop(write_guard);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "filesystem"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authn::event::{AuthEventStatus, AuthEventType, AuthFailureReason};
    use chrono::{TimeZone, Utc};

    pub(super) fn bid(name: &str) -> ArchiveBatchId {
        ArchiveBatchId::from_parts(name, name, 1)
    }

    pub(super) fn make_event(year: i32, month: u32, day: u32) -> AuthEvent {
        use crate::authn::event::AuthEventBuilder;
        AuthEventBuilder::new(
            None,
            None,
            AuthEventType::LoginAttempt,
            AuthEventStatus::Failure,
        )
        .with_ip(
            "203.0.113.1"
                .parse()
                .expect("literal is a valid IPv4 address"),
        )
        .with_error(AuthFailureReason::Other("test event".into()))
        .build_at(Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap())
    }

    #[tokio::test]
    async fn empty_batch_is_noop() {
        let tmp = tempdir();
        let archiver = FilesystemAuditArchiver::new(tmp.path());
        assert!(archiver.archive_batch(&bid("empty"), &[]).await.is_ok());
        // No directory created for an empty batch.
        assert!(!tmp.path().join("2026").exists());
    }

    #[tokio::test]
    async fn batch_writes_jsonl_under_date_partitioned_tree() {
        let tmp = tempdir();
        let archiver = FilesystemAuditArchiver::new(tmp.path());
        let events = vec![make_event(2026, 5, 19), make_event(2026, 5, 19)];

        archiver.archive_batch(&bid("b"), &events).await.unwrap();

        let path = archiver.path_for_date(chrono::NaiveDate::from_ymd_opt(2026, 5, 19).unwrap());
        assert!(path.exists(), "expected day file at {:?}", path);

        let contents = std::fs::read_to_string(&path).unwrap();
        let line_count = contents.lines().count();
        assert_eq!(line_count, 2, "expected 2 JSONL records, got {line_count}");
        for line in contents.lines() {
            let _: AuthEvent = serde_json::from_str(line).expect("each line must be valid JSON");
        }
    }

    #[tokio::test]
    async fn events_across_days_land_in_correct_files() {
        let tmp = tempdir();
        let archiver = FilesystemAuditArchiver::new(tmp.path());
        let events = vec![
            make_event(2026, 5, 18),
            make_event(2026, 5, 19),
            make_event(2026, 5, 19),
        ];

        archiver.archive_batch(&bid("b"), &events).await.unwrap();

        let day1 = archiver.path_for_date(chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap());
        let day2 = archiver.path_for_date(chrono::NaiveDate::from_ymd_opt(2026, 5, 19).unwrap());

        assert_eq!(std::fs::read_to_string(&day1).unwrap().lines().count(), 1);
        assert_eq!(std::fs::read_to_string(&day2).unwrap().lines().count(), 2);
    }

    /// Identical events sent as DIFFERENT batches are different events as
    /// far as the archive is concerned: both are appended.
    #[tokio::test]
    async fn identical_events_in_different_batches_append() {
        let tmp = tempdir();
        let archiver = FilesystemAuditArchiver::new(tmp.path());

        archiver
            .archive_batch(&bid("one"), &[make_event(2026, 5, 19)])
            .await
            .unwrap();
        archiver
            .archive_batch(&bid("two"), &[make_event(2026, 5, 19)])
            .await
            .unwrap();

        let path = archiver.path_for_date(chrono::NaiveDate::from_ymd_opt(2026, 5, 19).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn failure_on_second_file_restores_every_file() {
        let tmp = tempdir();
        let day1 = tmp.path().join("a/audit-1.jsonl");
        let day2 = tmp.path().join("b/audit-2.jsonl");
        std::fs::create_dir_all(day1.parent().unwrap()).unwrap();
        std::fs::write(&day1, b"{\"earlier\":1}\n").unwrap();
        let plan = vec![
            (day1.clone(), b"{\"new\":1}\n{\"new\":2}\n".to_vec()),
            (day2.clone(), b"{\"new\":3}\n".to_vec()),
        ];

        let mut fail_second = |i: usize| {
            if i == 1 {
                Err(std::io::Error::other("injected"))
            } else {
                Ok(())
            }
        };
        let err = append_all_or_none(&plan, &mut fail_second).expect_err("injected failure");
        assert!(matches!(err, FilesystemArchiveError::Io(_)));
        assert_eq!(std::fs::read(&day1).unwrap(), b"{\"earlier\":1}\n");
        assert_eq!(std::fs::read(&day2).unwrap(), b"");

        // The retry of the same batch lands each record exactly once.
        append_all_or_none(&plan, &mut |_| Ok(())).unwrap();
        assert_eq!(
            std::fs::read_to_string(&day1).unwrap(),
            "{\"earlier\":1}\n{\"new\":1}\n{\"new\":2}\n"
        );
        assert_eq!(std::fs::read_to_string(&day2).unwrap(), "{\"new\":3}\n");
    }

    #[tokio::test]
    async fn name_is_stable() {
        let tmp = tempdir();
        let archiver = FilesystemAuditArchiver::new(tmp.path());
        assert_eq!(archiver.name(), "filesystem");
    }

    /// Minimal in-test tempdir without pulling the `tempfile` crate.
    /// Uses the std `temp_dir` + a counter; cleaned up on `Drop`.
    pub(super) fn tempdir() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("axess-archive-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create test tempdir");
        TempDir { path }
    }

    pub(super) struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        pub(super) fn path(&self) -> &std::path::Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod retry;
