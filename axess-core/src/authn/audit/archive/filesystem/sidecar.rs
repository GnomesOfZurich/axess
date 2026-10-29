//! The batch-id sidecars of the filesystem archiver, and a cache over them.
//!
//! Next to each day file the archiver keeps `audit-{YYYY-MM-DD}.jsonl.batches`,
//! one line per applied batch: `{batch id} {content digest}`. The digest is a
//! SHA-256 over the events the batch holds for that archive (every day, in
//! order), so a source that reuses row ids for different events (a recycled
//! rowid, a recreated table, two sources on one root) produces a different
//! line and is appended instead of being skipped as a repeat. A line holding
//! only an id was written by an earlier release and matches on the id alone.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The most day sidecars kept in memory; the cache is dropped when it grows
/// past this, so a long-lived archiver does not hold every day it ever saw.
const MAX_CACHED_DAYS: usize = 400;

/// What the cache knew about one sidecar when it last read or wrote it.
struct Entry {
    lines: HashSet<String>,
    len: u64,
    modified: Option<SystemTime>,
}

/// An in-memory index of the sidecars' lines.
///
/// A sidecar is read from disk once and then answered from memory, instead of
/// being scanned for every batch (time quadratic in the batches of a day). The
/// index is trusted only while the file still has the length and modification
/// time it had when the index was built or last extended by this archiver, so
/// an append, a truncation or a replacement by another process (the root lock
/// lets several share a root) is noticed and the file is read again.
#[derive(Default)]
pub(super) struct SidecarCache {
    days: HashMap<PathBuf, Entry>,
    loads: usize,
}

/// The line recorded for a batch: its id and the digest of its events.
pub(super) fn marker_line(batch_id: &str, content_digest: &str) -> String {
    format!("{batch_id} {content_digest}")
}

impl SidecarCache {
    /// How many times a sidecar has been read from disk.
    #[cfg(test)]
    pub(super) fn loads(&self) -> usize {
        self.loads
    }

    /// True when the sidecar at `path` records this batch: the exact line
    /// `marker`, or (an earlier release's line) the bare `batch_id`. A missing
    /// sidecar records nothing.
    pub(super) fn recorded(
        &mut self,
        path: &Path,
        batch_id: &str,
        marker: &str,
    ) -> std::io::Result<bool> {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.days.remove(path);
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        let fresh = self
            .days
            .get(path)
            .is_some_and(|e| e.len == meta.len() && e.modified == meta.modified().ok());
        if !fresh {
            self.load(path, &meta)?;
        }
        Ok(self
            .days
            .get(path)
            .is_some_and(|e| e.lines.contains(marker) || e.lines.contains(batch_id)))
    }

    /// Read the sidecar into the index, replacing what was there.
    fn load(&mut self, path: &Path, meta: &std::fs::Metadata) -> std::io::Result<()> {
        use std::io::BufRead as _;
        let mut lines = HashSet::new();
        for line in std::io::BufReader::new(std::fs::File::open(path)?).lines() {
            lines.insert(line?);
        }
        self.loads += 1;
        if self.days.len() >= MAX_CACHED_DAYS {
            self.days.clear();
        }
        self.days.insert(
            path.to_path_buf(),
            Entry {
                lines,
                len: meta.len(),
                modified: meta.modified().ok(),
            },
        );
        Ok(())
    }

    /// Record that `marker` was appended to the sidecar at `path`, so the next
    /// check is answered from memory. Called with the root lock held, after
    /// the append is durable.
    pub(super) fn note_appended(&mut self, path: &Path, marker: &str) {
        let Ok(meta) = std::fs::metadata(path) else {
            self.days.remove(path);
            return;
        };
        let known = self.days.get_mut(path);
        match known {
            Some(entry) => {
                entry.lines.insert(marker.to_string());
                entry.len = meta.len();
                entry.modified = meta.modified().ok();
            }
            None => {
                // Only reached for a sidecar that did not exist before this
                // append (the check ran first and found nothing).
                let mut lines = HashSet::new();
                lines.insert(marker.to_string());
                self.days.insert(
                    path.to_path_buf(),
                    Entry {
                        lines,
                        len: meta.len(),
                        modified: meta.modified().ok(),
                    },
                );
            }
        }
    }
}
