//! The MySQL DDL, checked as text (no server is needed).

use super::SESSIONS_DDL;

/// `TEXT` holds 64 KiB; a session near its own size limit, base64-encoded
/// and optionally encrypted, does not fit, and strict mode rejects the write.
#[test]
fn the_data_column_holds_more_than_64_kib() {
    let line = SESSIONS_DDL
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("data "))
        .expect("data column");
    assert!(line.contains("MEDIUMTEXT"), "{line}");
}

/// New rows live in the binary column; it must exist in a fresh table and be
/// nullable so rows an earlier release wrote (which have none) stay valid.
#[test]
fn the_binary_column_is_a_nullable_longblob() {
    let line = SESSIONS_DDL
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("data_bin "))
        .expect("data_bin column");
    assert!(line.contains("LONGBLOB"), "{line}");
    assert!(!line.contains("NOT NULL"), "{line}");
}

/// The `id` column holds a session's key, which is 64 characters: a narrower
/// column cuts the key or refuses the row.
#[test]
fn the_id_column_holds_the_64_characters_of_a_key() {
    let line = SESSIONS_DDL
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("id "))
        .expect("id column");
    assert!(line.contains("VARCHAR(64)"), "{line}");
    assert_eq!(crate::session::id::SessionKey::HEX_LEN, 64);
}
