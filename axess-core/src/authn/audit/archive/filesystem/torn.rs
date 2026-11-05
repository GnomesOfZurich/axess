//! A write that a crash cut short leaves a line with no end; the next batch
//! must not be glued onto it.

use super::tests::{bid, make_event, tempdir};
use super::*;

fn day_file(archiver: &FilesystemAuditArchiver) -> PathBuf {
    archiver.path_for_date(chrono::NaiveDate::from_ymd_opt(2026, 5, 19).unwrap())
}

/// Every line of the day file is a whole event, and there are `n` of them.
fn assert_clean(path: &std::path::Path, n: usize) {
    let text = std::fs::read_to_string(path).unwrap();
    assert!(
        text.ends_with('\n'),
        "the file ends in the middle of a line"
    );
    assert_eq!(text.lines().count(), n);
    for line in text.lines() {
        serde_json::from_str::<AuthEvent>(line)
            .unwrap_or_else(|e| panic!("a line is not a whole event ({e}): {line}"));
    }
}

#[tokio::test]
async fn a_torn_last_line_is_cut_before_the_next_batch_is_appended() {
    let tmp = tempdir();
    let archiver = FilesystemAuditArchiver::new(tmp.path());
    archiver
        .archive_batch(&bid("first"), &[make_event(2026, 5, 19)])
        .await
        .unwrap();
    // A crash in the middle of the next batch's write: half a line, no newline.
    let path = day_file(&archiver);
    let line = serde_json::to_string(&make_event(2026, 5, 19)).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut file, &line.as_bytes()[..line.len() / 2]).unwrap();
    drop(file);

    archiver
        .archive_batch(&bid("second"), &[make_event(2026, 5, 19)])
        .await
        .unwrap();

    assert_clean(&path, 2);
}

#[tokio::test]
async fn a_file_that_is_only_a_torn_line_is_emptied_first() {
    let tmp = tempdir();
    let archiver = FilesystemAuditArchiver::new(tmp.path());
    let path = day_file(&archiver);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"{\"event_ti").unwrap();

    archiver
        .archive_batch(&bid("only"), &[make_event(2026, 5, 19)])
        .await
        .unwrap();

    assert_clean(&path, 1);
}
