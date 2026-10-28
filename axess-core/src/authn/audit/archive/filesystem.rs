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
//! 2. Takes an exclusive lock on `{root}/.archive.lock` inside the blocking
//!    task that does the work (see "One root, one lock" below).
//! 3. Opens every day file in append mode (creating missing directories) and
//!    records each file's length.
//! 4. Writes every day's events in one buffered write per file.
//! 5. `fsync`s every file, then every directory it created and the parent of
//!    the topmost one, then the directory of every file, so a crash after
//!    `Ok(())` cannot lose a day file or the folders leading to it.
//!
//! If the last step succeeds the call returns `Ok(())`; the adopter then
//! takes that as the green light to mark hot-table rows as archived.
//! If any step fails, every file already touched is truncated back to
//! its recorded length and the call returns `Err`: the batch is
//! all-or-nothing, so the rows stay hot and the next scheduled tick
//! retries the whole batch without duplicating the days that had
//! already been written. The id sidecars are rolled back first, and the
//! event files only when every sidecar was restored: a sidecar that cannot be
//! restored may still hold the batch id, and truncating the events then would
//! make the retry skip a batch whose events are gone. Leaving the events in
//! place costs at worst a repeated batch, never a lost one.
//!
//! # One root, one lock
//!
//! The lock is held for the dedup check, the writes, the rollback and the
//! `fsync`s, and it is taken by the blocking task itself, not by the async
//! caller. A caller that times out or is aborted therefore cannot release it
//! while the writes are still running: the retry waits for the running task,
//! finds its batch id recorded and returns. Because it is an operating-system
//! lock on a file, it also serialises two archivers on the same root, whether
//! they are two instances in one process or two processes. Give each
//! archiver its own root unless that sharing is intended.
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
/// Cloneable for use in `tokio::spawn` tasks. Concurrent `archive_batch`
/// calls on one root, from clones, other instances or other processes, are
/// serialised by a lock file the blocking task holds, so they never
/// interleave bytes inside a line or race the batch-id check. The inner
/// mutex only queues the callers of one instance without parking a blocking
/// thread each.
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
///
/// The sidecar is read a line at a time and the scan stops at the first
/// match, so memory does not grow with the file. Each line is one 64-character
/// id, so a day holding a thousand batches is about 65 KB.
fn batch_recorded(path: &std::path::Path, batch_id: &str) -> std::io::Result<bool> {
    use std::io::BufRead as _;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    for line in std::io::BufReader::new(file).lines() {
        if line? == batch_id {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Create `dir` and every missing ancestor, returning the directories this
/// call created, outermost first.
fn create_dir_all_tracked(dir: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    let mut missing: Vec<PathBuf> = dir
        .ancestors()
        .take_while(|d| !d.as_os_str().is_empty() && !d.exists())
        .map(PathBuf::from)
        .collect();
    std::fs::create_dir_all(dir)?;
    missing.reverse();
    Ok(missing)
}

/// The directories whose entries must be made durable: each directory this
/// call created, the parent of the outermost one (it gained an entry), and the
/// directory of every file written.
fn dirs_to_sync(
    created: &[PathBuf],
    files: &[&std::path::Path],
) -> std::collections::BTreeSet<PathBuf> {
    let mut dirs = std::collections::BTreeSet::new();
    for dir in created {
        dirs.insert(dir.clone());
    }
    if let Some(parent) = created.first().and_then(|top| top.parent()) {
        dirs.insert(parent.to_path_buf());
    }
    for file in files {
        if let Some(parent) = file.parent() {
            dirs.insert(parent.to_path_buf());
        }
    }
    dirs
}

/// `fsync` a directory so the entries created in it survive a crash. A no-op
/// where a directory cannot be opened for syncing.
fn sync_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Test seams: a failure injected before each file's write, and before each
/// file's rollback. Production passes closures that always succeed.
struct Faults<'a> {
    before_write: Box<dyn FnMut(usize) -> std::io::Result<()> + 'a>,
    before_rollback: Box<dyn FnMut(usize) -> std::io::Result<()> + 'a>,
}

/// Append every buffer to its file, or leave every file as it was.
///
/// `data` is written first, then `markers` (the batch-id sidecars); indexes
/// in [`Faults`] count `data` then `markers`. Each file's length is recorded
/// before anything is written. All files are opened, written and `fsync`ed,
/// then the directories holding them are; if any step fails, the files are
/// truncated back to their recorded lengths, so a failed batch leaves no whole
/// or partial line behind and the caller's retry cannot duplicate records.
///
/// The markers are restored first, and `data` only if every marker was. A
/// marker that cannot be restored may still carry the batch id, and the retry
/// would then skip a batch whose events had been truncated.
fn append_all_or_none(
    data: &[(PathBuf, Vec<u8>)],
    markers: &[(PathBuf, Vec<u8>)],
    faults: &mut Faults<'_>,
) -> Result<(), FilesystemArchiveError> {
    let plan: Vec<&(PathBuf, Vec<u8>)> = data.iter().chain(markers).collect();
    let mut touched: Vec<(std::fs::File, u64)> = Vec::with_capacity(plan.len());
    let outcome = (|| -> Result<(), FilesystemArchiveError> {
        let mut created: Vec<PathBuf> = Vec::new();
        for (path, _) in &plan {
            if let Some(parent) = path.parent() {
                created.extend(create_dir_all_tracked(parent)?);
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            let original_len = file.metadata()?.len();
            touched.push((file, original_len));
        }
        for (i, (_, buf)) in plan.iter().enumerate() {
            (faults.before_write)(i)?;
            touched[i].0.write_all(buf)?;
        }
        for (file, _) in &touched {
            file.sync_all()?;
        }
        let files: Vec<&std::path::Path> = plan.iter().map(|(p, _)| p.as_path()).collect();
        for dir in dirs_to_sync(&created, &files) {
            sync_dir(&dir)?;
        }
        Ok(())
    })();
    if outcome.is_err() {
        let mut restore = |i: usize| -> bool {
            let (file, original_len) = &touched[i];
            let result = (faults.before_rollback)(i)
                .and_then(|()| file.set_len(*original_len))
                .and_then(|()| file.sync_all());
            if let Err(e) = &result {
                tracing::error!(
                    error = %e,
                    file = i,
                    "could not roll back a partially written audit archive file"
                );
            }
            result.is_ok()
        };
        // Every marker is attempted, whatever the others did.
        let marker_results: Vec<bool> = (data.len()..touched.len()).map(&mut restore).collect();
        if marker_results.iter().all(|restored| *restored) {
            for i in 0..data.len().min(touched.len()) {
                restore(i);
            }
        } else {
            tracing::error!(
                "an audit archive batch-id file could not be restored; the event files \
                 were left as written so a retry cannot skip lost events"
            );
        }
    }
    outcome
}

/// The blocking half of `archive_batch`: take the root's lock, skip a batch
/// already recorded, and write the rest all-or-nothing.
fn archive_blocking(
    root: &std::path::Path,
    by_day: std::collections::BTreeMap<chrono::NaiveDate, Vec<String>>,
    batch_line: &str,
    faults: &mut Faults<'_>,
) -> Result<(), FilesystemArchiveError> {
    let _root_lock = lock_root(root)?;
    let day_path = |day: chrono::NaiveDate| {
        root.join(format!("{:04}", day.year()))
            .join(format!("{:02}", day.month()))
            .join(format!("{:02}", day.day()))
            .join(format!("audit-{}.jsonl", day.format("%Y-%m-%d")))
    };
    // A batch is written to every day file or to none, and its id is
    // recorded in the same step, so an id recorded for any of its days means
    // all of its events are already there.
    for day in by_day.keys() {
        if batch_recorded(&batches_path(&day_path(*day)), batch_line.trim_end())? {
            return Ok(());
        }
    }
    let data: Vec<(PathBuf, Vec<u8>)> = by_day
        .into_iter()
        .map(|(day, lines)| {
            let path = day_path(day);
            // Each line ends with `\n` so a file is valid JSONL whenever its
            // length is a recorded boundary.
            let mut buf = Vec::with_capacity(lines.iter().map(|s| s.len() + 1).sum());
            for line in lines {
                buf.extend_from_slice(line.as_bytes());
                buf.push(b'\n');
            }
            (path, buf)
        })
        .collect();
    let markers: Vec<(PathBuf, Vec<u8>)> = data
        .iter()
        .map(|(path, _)| (batches_path(path), batch_line.as_bytes().to_vec()))
        .collect();
    append_all_or_none(&data, &markers, faults)
}

/// Create `root` if needed and take an exclusive lock on `{root}/.archive.lock`,
/// held until the returned file is dropped.
fn lock_root(root: &std::path::Path) -> std::io::Result<std::fs::File> {
    let created = create_dir_all_tracked(root)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(root.join(LOCK_FILE))?;
    lock.lock()?;
    for dir in dirs_to_sync(&created, &[]) {
        sync_dir(&dir)?;
    }
    Ok(lock)
}

/// The lock file inside an archive root.
const LOCK_FILE: &str = ".archive.lock";

/// A failure or delay injected ahead of each file's write, for tests.
type WriteHook = Arc<dyn Fn(usize) -> std::io::Result<()> + Send + Sync>;

impl FilesystemAuditArchiver {
    /// `archive_batch`, with `before_write` run ahead of each file's write
    /// inside the blocking task.
    async fn archive_with_hook(
        &self,
        batch: &ArchiveBatchId,
        events: &[AuthEvent],
        before_write: WriteHook,
    ) -> Result<(), FilesystemArchiveError> {
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

        // Queue the callers of this instance here, where waiting is free.
        // This guard goes when the future is dropped; the file lock taken
        // inside the blocking task does not, so a cancelled call cannot hand
        // the root to a retry while its writes are still in progress.
        let _queue = self.write_lock.lock().await;
        let root = self.root.clone();
        let batch_line = format!("{batch}\n");
        tokio::task::spawn_blocking(move || {
            archive_blocking(
                &root,
                by_day,
                &batch_line,
                &mut Faults {
                    before_write: Box::new(move |i| before_write(i)),
                    before_rollback: Box::new(|_| Ok(())),
                },
            )
        })
        .await
        .map_err(|join_err| {
            FilesystemArchiveError::Io(std::io::Error::other(format!(
                "spawn_blocking task panicked: {join_err}"
            )))
        })?
    }
}

impl AuditArchiver for FilesystemAuditArchiver {
    type Error = FilesystemArchiveError;

    async fn archive_batch(
        &self,
        batch: &ArchiveBatchId,
        events: &[AuthEvent],
    ) -> Result<(), Self::Error> {
        self.archive_with_hook(batch, events, Arc::new(|_| Ok(())))
            .await
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
        ArchiveBatchId::from_ids([name])
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
        let data = vec![
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
        let err = append_all_or_none(
            &data,
            &[],
            &mut Faults {
                before_write: Box::new(&mut fail_second),
                before_rollback: Box::new(|_| Ok(())),
            },
        )
        .expect_err("injected failure");
        assert!(matches!(err, FilesystemArchiveError::Io(_)));
        assert_eq!(std::fs::read(&day1).unwrap(), b"{\"earlier\":1}\n");
        assert_eq!(std::fs::read(&day2).unwrap(), b"");

        // The retry of the same batch lands each record exactly once.
        append_all_or_none(&data, &[], &mut no_faults()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&day1).unwrap(),
            "{\"earlier\":1}\n{\"new\":1}\n{\"new\":2}\n"
        );
        assert_eq!(std::fs::read_to_string(&day2).unwrap(), "{\"new\":3}\n");
    }

    /// `Faults` that never fire.
    pub(super) fn no_faults() -> Faults<'static> {
        Faults {
            before_write: Box::new(|_| Ok(())),
            before_rollback: Box::new(|_| Ok(())),
        }
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
mod locking;
#[cfg(test)]
mod retry;
