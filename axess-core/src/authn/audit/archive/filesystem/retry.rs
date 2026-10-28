//! A batch re-sent after a failed `mark_archived` is stored once, including
//! when the retry comes from the retention loop itself.

use super::tests::{bid, make_event, tempdir};
use super::*;
use crate::authn::audit::archive::{
    AuditRetentionLoop, AuditRetentionPolicy, AuditRetentionSource,
};
use std::sync::Mutex;
use std::time::Duration;

fn lines(archiver: &FilesystemAuditArchiver, day: u32) -> usize {
    let path = archiver.path_for_date(chrono::NaiveDate::from_ymd_opt(2026, 5, day).unwrap());
    std::fs::read_to_string(path).map_or(0, |t| t.lines().count())
}

/// The same batch id is applied once, whether the repeat is immediate or a
/// fresh archiver instance over the same directory (a process restart).
#[tokio::test]
async fn the_same_batch_id_is_not_appended_twice() {
    let tmp = tempdir();
    let archiver = FilesystemAuditArchiver::new(tmp.path());
    let events = [make_event(2026, 5, 19), make_event(2026, 5, 20)];

    archiver.archive_batch(&bid("b"), &events).await.unwrap();
    archiver.archive_batch(&bid("b"), &events).await.unwrap();
    let restarted = FilesystemAuditArchiver::new(tmp.path());
    restarted.archive_batch(&bid("b"), &events).await.unwrap();

    assert_eq!((lines(&archiver, 19), lines(&archiver, 20)), (1, 1));
}

#[test]
fn batch_ids_follow_every_id_and_not_their_order() {
    let id = |ids: &[&str]| ArchiveBatchId::from_ids(ids.iter().copied());
    assert_eq!(id(&["1", "5", "9"]), id(&["9", "1", "5"]));
    assert_ne!(id(&["1", "5", "9"]), id(&["1", "6", "9"]), "a middle row");
    assert_ne!(id(&["1", "9"]), id(&["1", "5", "9"]));
    assert_ne!(
        id(&["ab", "c"]),
        id(&["a", "bc"]),
        "ids are not concatenated"
    );
    assert_eq!(id(&["1"]).as_str().len(), 64);
}

/// A source whose first `mark_archived` fails, as a database blip would.
struct FlakyMark {
    rows: Vec<(u64, AuthEvent)>,
    failures_left: Mutex<u32>,
}

impl AuditRetentionSource for FlakyMark {
    type EventId = u64;
    type Error = std::io::Error;

    async fn select_unarchived_before(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        _: usize,
    ) -> Result<Vec<(u64, AuthEvent)>, Self::Error> {
        Ok(self.rows.clone())
    }
    async fn mark_archived(
        &self,
        _: &[u64],
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Self::Error> {
        let mut left = self.failures_left.lock().unwrap();
        if *left > 0 {
            *left -= 1;
            return Err(std::io::Error::other("mark failed"));
        }
        Ok(())
    }
    async fn purge_hot_archived_before(
        &self,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, Self::Error> {
        Ok(0)
    }
}

#[tokio::test]
async fn a_tick_retried_after_a_failed_mark_archives_each_event_once() {
    let tmp = tempdir();
    let archiver = FilesystemAuditArchiver::new(tmp.path());
    let source = FlakyMark {
        rows: vec![
            (10, make_event(2026, 5, 19)),
            (11, make_event(2026, 5, 19)),
            (12, make_event(2026, 5, 19)),
        ],
        failures_left: Mutex::new(1),
    };
    let policy = AuditRetentionPolicy::default().with_archive_after(Duration::ZERO);
    let retention = AuditRetentionLoop::new(source, archiver.clone(), policy);

    assert!(retention.tick().await.is_err(), "the first mark fails");
    assert_eq!(lines(&archiver, 19), 3, "the batch was archived");
    let report = retention.tick().await.unwrap();
    assert_eq!(report.archived, 3);
    assert_eq!(lines(&archiver, 19), 3, "the retry did not duplicate it");
}
