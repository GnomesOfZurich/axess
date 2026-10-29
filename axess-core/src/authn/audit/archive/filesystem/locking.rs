//! The root lock, cancellation, rollback order and directory durability.

use super::tests::{bid, make_event, tempdir};
use super::*;
use std::time::Duration;

fn day(day: u32) -> chrono::NaiveDate {
    chrono::NaiveDate::from_ymd_opt(2026, 5, day).unwrap()
}

fn line_count(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |t| t.lines().count())
}

/// Two archivers on one root that are given the same batch at the same time
/// store it once: before the root lock their private mutexes did not meet,
/// so both passed the batch-id check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_instances_on_one_root_store_a_batch_once() {
    for round in 0..100 {
        let tmp = tempdir();
        let a = FilesystemAuditArchiver::new(tmp.path());
        let b = FilesystemAuditArchiver::new(tmp.path());
        let events = vec![make_event(2026, 5, 19), make_event(2026, 5, 20)];
        let id = bid("shared");
        let (ra, rb) = tokio::join!(a.archive_batch(&id, &events), b.archive_batch(&id, &events));
        ra.unwrap();
        rb.unwrap();
        for d in [19, 20] {
            let path = a.path_for_date(day(d));
            assert_eq!(line_count(&path), 1, "round {round}, day {d}");
            assert_eq!(
                line_count(&batches_path(&path)),
                1,
                "round {round}, sidecar"
            );
        }
    }
}

/// A caller blocks while another holder has the root lock, and proceeds when
/// it is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archiving_waits_for_the_root_lock() {
    let tmp = tempdir();
    let archiver = FilesystemAuditArchiver::new(tmp.path());
    std::fs::create_dir_all(tmp.path()).unwrap();
    let held = lock_root(tmp.path()).unwrap();

    let a = archiver.clone();
    let task =
        tokio::spawn(async move { a.archive_batch(&bid("w"), &[make_event(2026, 5, 19)]).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!task.is_finished(), "the write must wait for the lock");
    assert_eq!(line_count(&archiver.path_for_date(day(19))), 0);

    drop(held);
    task.await.unwrap().unwrap();
    assert_eq!(line_count(&archiver.path_for_date(day(19))), 1);
}

/// A call that is aborted mid-write does not free the root for its retry:
/// the blocking task still holds the lock, so the retry waits, sees the id
/// and writes nothing. The lock used to live in the async future, and the
/// retry then ran beside the first call's writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aborted_call_does_not_let_its_retry_interleave() {
    let tmp = tempdir();
    let archiver = FilesystemAuditArchiver::new(tmp.path());
    let events = vec![make_event(2026, 5, 19), make_event(2026, 5, 19)];
    let id = bid("cancelled");

    // The first call stalls inside its blocking task, before its first write.
    let first = {
        let (a, events, id) = (archiver.clone(), events.clone(), id.clone());
        tokio::spawn(async move {
            a.archive_with_hook(
                &id,
                &events,
                Arc::new(|i| {
                    if i == 0 {
                        std::thread::sleep(Duration::from_millis(400));
                    }
                    Ok(())
                }),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    first.abort();
    let _ = first.await;

    // The retry must not slip in beside the stalled task.
    archiver.archive_batch(&id, &events).await.unwrap();
    // Let the detached task finish, in case anything is still writing.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let path = archiver.path_for_date(day(19));
    assert_eq!(line_count(&path), 2, "two events, stored once");
    assert_eq!(line_count(&batches_path(&path)), 1);
}

/// The marker (batch-id) file that cannot be restored keeps the events too:
/// truncating them while the id may remain would make the retry skip lost
/// events.
#[test]
fn an_unrestorable_marker_leaves_the_events_in_place() {
    let tmp = tempdir();
    let d1 = tmp.path().join("a/audit-1.jsonl");
    let d2 = tmp.path().join("b/audit-2.jsonl");
    let m1 = tmp.path().join("a/audit-1.jsonl.batches");
    let m2 = tmp.path().join("b/audit-2.jsonl.batches");
    let data = vec![
        (d1.clone(), b"E1\n".to_vec()),
        (d2.clone(), b"E2\n".to_vec()),
    ];
    let markers = vec![
        (m1.clone(), b"id\n".to_vec()),
        (m2.clone(), b"id\n".to_vec()),
    ];

    let result = append_all_or_none(
        tmp.path(),
        &data,
        &markers,
        &mut Faults {
            // Indexes: d1 0, d2 1, m1 2, m2 3. The second marker's write
            // fails after the first marker holds the id.
            before_write: Box::new(|i| {
                if i == 3 {
                    Err(std::io::Error::other("write failed"))
                } else {
                    Ok(())
                }
            }),
            // The first marker cannot be restored.
            trace: Box::new(|_| {}),
            before_rollback: Box::new(|i| {
                if i == 2 {
                    Err(std::io::Error::other("rollback failed"))
                } else {
                    Ok(())
                }
            }),
        },
    );
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(&m1).unwrap(),
        b"id\n",
        "the id is still there"
    );
    assert_eq!(std::fs::read(&d1).unwrap(), b"E1\n", "so are its events");
    assert_eq!(std::fs::read(&d2).unwrap(), b"E2\n");
}

/// The other half: when every marker is restored but an event file is not,
/// the events stay (a repeated batch, never a lost one) and the id is gone so
/// the retry writes again.
#[test]
fn an_unrestorable_event_file_leaves_a_retryable_batch() {
    let tmp = tempdir();
    let d1 = tmp.path().join("a/audit-1.jsonl");
    let m1 = tmp.path().join("a/audit-1.jsonl.batches");
    let data = vec![(d1.clone(), b"E1\n".to_vec())];
    let markers = vec![(m1.clone(), b"id\n".to_vec())];
    let result = append_all_or_none(
        tmp.path(),
        &data,
        &markers,
        &mut Faults {
            before_write: Box::new(|i| {
                if i == 1 {
                    Err(std::io::Error::other("marker write failed"))
                } else {
                    Ok(())
                }
            }),
            trace: Box::new(|_| {}),
            before_rollback: Box::new(|i| {
                if i == 0 {
                    Err(std::io::Error::other("rollback failed"))
                } else {
                    Ok(())
                }
            }),
        },
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(&m1).unwrap(), b"", "no id: the retry writes");
    assert_eq!(std::fs::read(&d1).unwrap(), b"E1\n");
}

/// Every directory the write created, the parent of the topmost, and the
/// directory of each file are synced.
#[test]
fn new_folders_and_the_root_they_hang_from_are_synced() {
    let root = std::path::PathBuf::from("/archive");
    let created = vec![
        root.join("2026"),
        root.join("2026/05"),
        root.join("2026/05/19"),
    ];
    let file = root.join("2026/05/19/audit-2026-05-19.jsonl");
    let dirs = dirs_to_sync(&root, &created, &[file.as_path()]);
    for want in [
        "/archive",
        "/archive/2026",
        "/archive/2026/05",
        "/archive/2026/05/19",
    ] {
        assert!(
            dirs.contains(std::path::Path::new(want)),
            "{want} not synced: {dirs:?}"
        );
    }
    assert_eq!(dirs.len(), 4);
}

/// `create_dir_all_tracked` reports exactly the directories it made.
#[test]
fn tracked_creation_names_only_what_it_created() {
    let tmp = tempdir();
    std::fs::create_dir_all(tmp.path().join("2026")).unwrap();
    let made = create_dir_all_tracked(&tmp.path().join("2026/05/19")).unwrap();
    assert_eq!(
        made,
        vec![tmp.path().join("2026/05"), tmp.path().join("2026/05/19")]
    );
    assert!(
        create_dir_all_tracked(&tmp.path().join("2026/05/19"))
            .unwrap()
            .is_empty()
    );
}

/// A real archive run syncs without error, including through new folders.
#[tokio::test]
async fn archiving_into_new_folders_succeeds_end_to_end() {
    let tmp = tempdir();
    let archiver = FilesystemAuditArchiver::new(tmp.path().join("fresh/root"));
    archiver
        .archive_batch(&bid("x"), &[make_event(2027, 1, 2)])
        .await
        .unwrap();
    assert!(archiver.root().join(".archive.lock").exists());
}

/// The id check finds an id in a large sidecar, and reads the file once.
#[test]
fn recorded_finds_an_id_in_a_large_sidecar_with_one_read() {
    let tmp = tempdir();
    let path = tmp.path().join("audit.jsonl.batches");
    let mut text = String::new();
    for i in 0..50_000 {
        text.push_str(&format!("{i:064}\n"));
    }
    std::fs::write(&path, text).unwrap();
    let mut cache = sidecar::SidecarCache::default();
    let id = |n: u32| format!("{n:064}");
    assert!(cache.recorded(&path, &id(3), "no-such-marker").unwrap());
    assert!(
        cache
            .recorded(&path, &id(49_999), "no-such-marker")
            .unwrap()
    );
    assert!(
        !cache
            .recorded(&path, &id(50_000), "no-such-marker")
            .unwrap()
    );
    assert!(
        !cache
            .recorded(&tmp.path().join("missing"), "x", "x y")
            .unwrap()
    );
    assert_eq!(cache.loads(), 1, "one read for four questions");
}
