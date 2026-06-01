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
//! 2. Opens the day file in append mode (creates parents if missing).
//! 3. Writes every event for that day in one buffered write.
//! 4. `fsync`s the file before returning.
//!
//! If `fsync` succeeds the call returns `Ok(())`; the adopter then
//! takes that as the green light to mark hot-table rows as archived.
//! If any step fails the call returns `Err`, the rows stay hot, and
//! the next scheduled tick retries the whole batch.
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

use crate::authn::audit::archive::AuditArchiver;
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

impl AuditArchiver for FilesystemAuditArchiver {
    type Error = FilesystemArchiveError;

    async fn archive_batch(&self, events: &[AuthEvent]) -> Result<(), Self::Error> {
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
        tokio::task::spawn_blocking(move || -> Result<(), FilesystemArchiveError> {
            for (day, lines) in by_day {
                let path = root
                    .join(format!("{:04}", day.year()))
                    .join(format!("{:02}", day.month()))
                    .join(format!("{:02}", day.day()))
                    .join(format!("audit-{}.jsonl", day.format("%Y-%m-%d")));

                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;

                // One buffered write for the whole day's slice;
                // each line ends with `\n` so the file remains
                // valid JSONL even on partial-flush mid-batch.
                let mut buf = Vec::with_capacity(lines.iter().map(|s| s.len() + 1).sum());
                for line in lines {
                    buf.extend_from_slice(line.as_bytes());
                    buf.push(b'\n');
                }
                file.write_all(&buf)?;
                file.sync_all()?;
            }
            Ok(())
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
    use crate::authn::event::{AuthEventStatus, AuthEventType};
    use chrono::{TimeZone, Utc};

    fn make_event(year: i32, month: u32, day: u32) -> AuthEvent {
        use crate::authn::event::AuthEventBuilder;
        AuthEventBuilder::new(
            None,
            None,
            AuthEventType::LoginAttempt,
            AuthEventStatus::Failure,
        )
        .with_ip("203.0.113.1")
        .with_error("test event")
        .build_at(Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap())
    }

    #[tokio::test]
    async fn empty_batch_is_noop() {
        let tmp = tempdir();
        let archiver = FilesystemAuditArchiver::new(tmp.path());
        assert!(archiver.archive_batch(&[]).await.is_ok());
        // No directory created for an empty batch.
        assert!(!tmp.path().join("2026").exists());
    }

    #[tokio::test]
    async fn batch_writes_jsonl_under_date_partitioned_tree() {
        let tmp = tempdir();
        let archiver = FilesystemAuditArchiver::new(tmp.path());
        let events = vec![make_event(2026, 5, 19), make_event(2026, 5, 19)];

        archiver.archive_batch(&events).await.unwrap();

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

        archiver.archive_batch(&events).await.unwrap();

        let day1 = archiver.path_for_date(chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap());
        let day2 = archiver.path_for_date(chrono::NaiveDate::from_ymd_opt(2026, 5, 19).unwrap());

        assert_eq!(std::fs::read_to_string(&day1).unwrap().lines().count(), 1);
        assert_eq!(std::fs::read_to_string(&day2).unwrap().lines().count(), 2);
    }

    #[tokio::test]
    async fn repeated_batches_append_rather_than_overwrite() {
        let tmp = tempdir();
        let archiver = FilesystemAuditArchiver::new(tmp.path());

        archiver
            .archive_batch(&[make_event(2026, 5, 19)])
            .await
            .unwrap();
        archiver
            .archive_batch(&[make_event(2026, 5, 19)])
            .await
            .unwrap();

        let path = archiver.path_for_date(chrono::NaiveDate::from_ymd_opt(2026, 5, 19).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[tokio::test]
    async fn name_is_stable() {
        let tmp = tempdir();
        let archiver = FilesystemAuditArchiver::new(tmp.path());
        assert_eq!(archiver.name(), "filesystem");
    }

    /// Minimal in-test tempdir without pulling the `tempfile` crate.
    /// Uses the std `temp_dir` + a counter; cleaned up on `Drop`.
    fn tempdir() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("axess-archive-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create test tempdir");
        TempDir { path }
    }

    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
