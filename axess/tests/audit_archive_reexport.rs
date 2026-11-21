//! With `audit-archive-fs`, the facade re-exports the filesystem archiver
//! beside the archive types it is wired with, so an application runs the
//! audit retention loop into it without a direct dependency on `axess-core`.

#![cfg(feature = "audit-archive-fs")]

use axess::authn::{
    ArchiveBatchId, AuditArchiver, AuditRetentionPolicy, FilesystemArchiveError,
    FilesystemAuditArchiver,
};
use std::path::Path;

fn archives_with<A: AuditArchiver<Error = FilesystemArchiveError>>(archiver: &A) -> &A {
    archiver
}

#[test]
fn the_filesystem_archiver_is_reachable_from_the_facade() {
    let archiver = FilesystemAuditArchiver::new("/var/lib/axess/audit");
    let date = axess::UtcDate::new(2026, 1, 2).expect("a date");
    assert_eq!(
        archives_with(&archiver).path_for_date(date),
        Path::new("/var/lib/axess/audit/2026/01/02/audit-2026-01-02.jsonl")
    );
}

#[test]
fn the_archive_types_it_is_wired_with_are_reachable_from_the_facade() {
    let policy = AuditRetentionPolicy::default();
    assert!(policy.purge_hot_after_archive < policy.archive_after);
    assert_eq!(
        ArchiveBatchId::from_ids(["b", "a"]),
        ArchiveBatchId::from_ids(["a", "b"])
    );
}
