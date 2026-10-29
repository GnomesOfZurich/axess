//! Marker ordering, directory durability on a retry, the cached sidecar
//! check, and batch ids reused over different events.

use super::tests::{bid, make_event, tempdir};
use super::*;
use std::collections::BTreeMap;

fn day(d: u32) -> chrono::NaiveDate {
    chrono::NaiveDate::from_ymd_opt(2026, 5, d).unwrap()
}

fn line_count(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |t| t.lines().count())
}

fn one_batch(days: &[u32], tag: &str) -> BTreeMap<chrono::NaiveDate, Vec<String>> {
    days.iter()
        .map(|d| (day(*d), vec![format!("{{\"tag\":\"{tag}\",\"day\":{d}}}")]))
        .collect()
}

fn run(
    root: &std::path::Path,
    by_day: BTreeMap<chrono::NaiveDate, Vec<String>>,
    id: &str,
    cache: &std::sync::Mutex<SidecarCache>,
    faults: &mut Faults<'_>,
) -> Result<(), FilesystemArchiveError> {
    archive_blocking(root, by_day, &format!("{id}\n"), cache, faults)
}

/// No marker is written before every event file has been written and synced:
/// the order that stops one day's marker becoming durable ahead of another
/// day's events.
#[test]
fn no_marker_is_written_before_every_data_file_is_synced() {
    let tmp = tempdir();
    let cache = std::sync::Mutex::new(SidecarCache::default());
    let mut steps: Vec<Step> = Vec::new();
    run(
        tmp.path(),
        one_batch(&[18, 19, 20], "a"),
        "batch-a",
        &cache,
        &mut Faults {
            before_write: Box::new(|_| Ok(())),
            before_rollback: Box::new(|_| Ok(())),
            trace: Box::new(|s| steps.push(s)),
        },
    )
    .unwrap();
    // Plan indexes: data 0..3, markers 3..6.
    let first_marker_write = steps
        .iter()
        .position(|s| matches!(s, Step::Write(i) if *i >= 3))
        .expect("markers were written");
    for data_index in 0..3 {
        let synced = steps
            .iter()
            .position(|s| *s == Step::SyncFile(data_index))
            .expect("data file synced");
        assert!(
            synced < first_marker_write,
            "data file {data_index} synced at {synced}, after the first marker write at \
             {first_marker_write}: {steps:?}"
        );
    }
}

/// After a first attempt fails with the day folders already created, the
/// retry syncs the root and every folder down to the day, not only the ones
/// it created itself.
#[test]
fn a_retry_syncs_folders_an_earlier_failed_attempt_created() {
    let tmp = tempdir();
    let cache = std::sync::Mutex::new(SidecarCache::default());
    let failed = run(
        tmp.path(),
        one_batch(&[19], "a"),
        "batch-a",
        &cache,
        &mut Faults {
            before_write: Box::new(|_| Err(std::io::Error::other("first attempt fails"))),
            before_rollback: Box::new(|_| Ok(())),
            trace: Box::new(|_| {}),
        },
    );
    assert!(failed.is_err());
    assert!(
        tmp.path().join("2026/05/19").is_dir(),
        "the failed attempt left the folders behind"
    );

    let mut synced: Vec<PathBuf> = Vec::new();
    run(
        tmp.path(),
        one_batch(&[19], "a"),
        "batch-a",
        &cache,
        &mut Faults {
            before_write: Box::new(|_| Ok(())),
            before_rollback: Box::new(|_| Ok(())),
            trace: Box::new(|s| {
                if let Step::SyncDir(d) = s {
                    synced.push(d);
                }
            }),
        },
    )
    .unwrap();
    for want in [
        tmp.path().to_path_buf(),
        tmp.path().join("2026"),
        tmp.path().join("2026/05"),
        tmp.path().join("2026/05/19"),
    ] {
        assert!(synced.contains(&want), "{want:?} not synced: {synced:?}");
    }
}

/// Archiving many batches into one day reads the day's sidecar once, not once
/// per batch.
#[test]
fn many_batches_into_one_day_read_the_sidecar_once() {
    let tmp = tempdir();
    let cache = std::sync::Mutex::new(SidecarCache::default());
    run(
        tmp.path(),
        one_batch(&[19], "seed"),
        "seed",
        &cache,
        &mut tests::no_faults(),
    )
    .unwrap();
    // A fresh process over the same root: its cache is cold.
    let cold = std::sync::Mutex::new(SidecarCache::default());
    for n in 0..300 {
        run(
            tmp.path(),
            one_batch(&[19], &format!("t{n}")),
            &format!("batch-{n}"),
            &cold,
            &mut tests::no_faults(),
        )
        .unwrap();
    }
    assert_eq!(cold.lock().unwrap().loads(), 1, "one read for 300 batches");
    let sidecar = batches_path(&FilesystemAuditArchiver::new(tmp.path()).path_for_date(day(19)));
    assert_eq!(line_count(&sidecar), 301);
}

/// A second archiver on the same root appends a marker; the first one notices
/// through the file's changed length and still skips that batch.
#[tokio::test]
async fn another_instances_append_is_seen_through_the_cache() {
    let tmp = tempdir();
    let a = FilesystemAuditArchiver::new(tmp.path());
    let b = FilesystemAuditArchiver::new(tmp.path());
    let events = [make_event(2026, 5, 19)];
    a.archive_batch(&bid("one"), &events).await.unwrap();
    b.archive_batch(&bid("two"), &events).await.unwrap();
    a.archive_batch(&bid("two"), &events).await.unwrap();
    assert_eq!(
        line_count(&a.path_for_date(day(19))),
        2,
        "two batches, once each"
    );
}

/// A source that reuses ids for different events is not skipped as a repeat;
/// the same events under the same id still are.
#[tokio::test]
async fn a_reused_batch_id_over_different_events_is_appended() {
    let tmp = tempdir();
    let archiver = FilesystemAuditArchiver::new(tmp.path());
    let id = bid("recycled-rowids");
    archiver
        .archive_batch(&id, &[make_event(2026, 5, 19)])
        .await
        .unwrap();
    let different = [make_event(2026, 5, 19), make_event(2026, 5, 19)];
    archiver.archive_batch(&id, &different).await.unwrap();
    let path = archiver.path_for_date(day(19));
    assert_eq!(line_count(&path), 3, "the second batch was not dropped");

    archiver.archive_batch(&id, &different).await.unwrap();
    assert_eq!(line_count(&path), 3, "an identical retry is still skipped");
}

/// A sidecar line written by an earlier release (the bare id) still marks the
/// batch as recorded.
#[tokio::test]
async fn a_legacy_bare_id_marker_still_skips_the_batch() {
    let tmp = tempdir();
    let archiver = FilesystemAuditArchiver::new(tmp.path());
    let path = archiver.path_for_date(day(19));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let id = bid("old");
    std::fs::write(batches_path(&path), format!("{id}\n")).unwrap();
    archiver
        .archive_batch(&id, &[make_event(2026, 5, 19)])
        .await
        .unwrap();
    assert_eq!(line_count(&path), 0, "skipped: nothing was appended");
}
