//! The MySQL DDL, checked as text (no server is needed).

use crate::device::storage::mysql::schema::{DEVICE_BINDINGS_REFRESH_DDL, DEVICES_DDL};

const BIN: &str = "VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin";

/// The definition line of `column` in `ddl`.
fn column<'a>(ddl: &'a str, column: &str) -> &'a str {
    ddl.lines()
        .map(str::trim)
        .find(|l| l.split_whitespace().next() == Some(column))
        .unwrap_or_else(|| panic!("no column {column}"))
}

/// Ids compare byte for byte. Without the binary collation `Ab` and `aB`
/// are the same device (and the same primary key).
#[test]
fn id_columns_use_a_binary_collation() {
    for col in ["tenant_id", "id", "user_id"] {
        assert!(column(DEVICES_DDL, col).contains(BIN), "devices.{col}");
    }
    for col in ["tenant_id", "device_id", "family_id"] {
        assert!(
            column(DEVICE_BINDINGS_REFRESH_DDL, col).contains(BIN),
            "device_bindings_refresh.{col}"
        );
    }
}

/// A foreign key needs the referencing columns to match the referenced
/// ones' type, charset and collation.
#[test]
fn the_foreign_key_columns_match_the_referenced_columns() {
    let def = |ddl, col| {
        let line = column(ddl, col);
        line.split_whitespace()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ")
    };
    let strip = |s: String| s.trim_end_matches(',').to_owned();
    assert_eq!(
        strip(def(DEVICES_DDL, "tenant_id")),
        strip(def(DEVICE_BINDINGS_REFRESH_DDL, "tenant_id"))
    );
    assert_eq!(
        strip(def(DEVICES_DDL, "id")),
        strip(def(DEVICE_BINDINGS_REFRESH_DDL, "device_id"))
    );
}

/// Every index that serves an `ORDER BY last_seen_at DESC, id ASC` lookup
/// is declared in that order, so MySQL 8 reads the newest sighting from the
/// index instead of sorting every row that shares the prefix.
#[test]
fn the_sighting_indexes_are_declared_newest_first() {
    for index in [
        "idx_devices_fingerprint_seen",
        "idx_devices_user",
        "idx_devices_user_fingerprint",
    ] {
        let line = DEVICES_DDL
            .lines()
            .map(str::trim)
            .find(|l| l.contains(index))
            .unwrap_or_else(|| panic!("no index {index}"));
        assert!(
            line.ends_with("last_seen_at DESC, id ASC),")
                || line.ends_with("last_seen_at DESC, id ASC)"),
            "{index} must end in `last_seen_at DESC, id ASC`: {line}"
        );
    }
}
