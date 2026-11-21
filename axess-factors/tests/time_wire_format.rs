//! The bytes a stored factor's timestamps are written as, and the stored
//! forms that still read back: an HOTP lock, a pending email code and a used
//! recovery code keep the text an earlier release wrote, an RFC 3339 instant
//! in UTC with a `Z` and the fewest fraction digits (none, three, six or
//! nine) that hold it. No case names a time type: every instant comes from a
//! stored row.

#![cfg(all(feature = "hotp", feature = "email_otp", feature = "recovery_code"))]

use axess_factors::{EmailOtpConfig, HotpConfig, StoredRecoveryCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const STAMPS: [&str; 6] = [
    "2026-01-01T00:00:00Z",
    "2026-01-01T00:00:00.500Z",
    "2026-01-01T00:00:00.123456Z",
    "2026-01-01T00:00:00.123456789Z",
    "1969-12-31T23:59:59.999999999Z",
    "+262142-12-31T23:59:59.999999999Z",
];

/// `base` with `field` set to `stamp`, read and written again: the written
/// field is the stored text, and the whole row writes as it was read (as a
/// JSON value, whose keys have no order).
fn reads_back<T: Serialize + DeserializeOwned>(base: &T, field: &str, stamp: Value) -> T {
    let mut row = serde_json::to_value(base).expect("serialises");
    row[field] = stamp.clone();
    let value: T = serde_json::from_value(row.clone()).expect("the stored row reads");
    let written = serde_json::to_value(&value).expect("serialises");
    assert_eq!(written, row, "the row writes as it was read");
    assert_eq!(written[field], stamp);
    value
}

#[test]
fn an_hotp_lock_keeps_its_end() {
    let base = HotpConfig::default();
    for stamp in STAMPS {
        let read = reads_back(&base, "locked_until", json!(stamp));
        assert!(read.locked_until().is_some());
    }
    assert!(
        reads_back(&base, "locked_until", Value::Null)
            .locked_until()
            .is_none()
    );
    // A row written before the lock existed reads unlocked.
    let mut row = serde_json::to_value(&base).expect("serialises");
    row.as_object_mut()
        .expect("an object")
        .remove("locked_until");
    let read: HotpConfig = serde_json::from_value(row).expect("a row without a lock reads");
    assert!(read.locked_until().is_none());
}

#[test]
fn a_pending_email_code_keeps_its_end() {
    let base: EmailOtpConfig = serde_json::from_value(json!({
        "email": "alice@example.com",
        "code_length": 6,
        "ttl_secs": 300,
        "pending_hash": null,
        "pending_until": null,
    }))
    .expect("a stored email factor reads");
    for stamp in STAMPS {
        let read = reads_back(&base, "pending_until", json!(stamp));
        assert!(read.pending_until.is_some());
    }
    assert!(
        reads_back(&base, "pending_until", Value::Null)
            .pending_until
            .is_none()
    );
    let mut row = serde_json::to_value(&base).expect("serialises");
    row.as_object_mut()
        .expect("an object")
        .remove("pending_until");
    let read: EmailOtpConfig =
        serde_json::from_value(row).expect("a row without pending_until reads");
    assert!(read.pending_until.is_none());
}

#[test]
fn a_used_recovery_code_keeps_when_it_was_used() {
    let base = StoredRecoveryCode {
        hash: "stored-hash".into(),
        used_at: None,
    };
    assert_eq!(
        serde_json::to_string(&base).expect("serialises"),
        r#"{"hash":"stored-hash","used_at":null}"#
    );
    for stamp in STAMPS {
        let read = reads_back(&base, "used_at", json!(stamp));
        assert!(read.used_at.is_some());
    }
    let read: StoredRecoveryCode =
        serde_json::from_str(r#"{"hash":"h"}"#).expect("a row without used_at reads");
    assert_eq!(read.used_at, None);
    // The other forms an earlier release read still read, as the instant
    // the canonical form names.
    let canonical = reads_back(&base, "used_at", json!("2026-01-01T00:00:00Z"));
    for other in [
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T01:00:00+01:00",
        "2026-01-01 00:00:00Z",
    ] {
        let read: StoredRecoveryCode =
            serde_json::from_value(json!({ "hash": "stored-hash", "used_at": other }))
                .expect("an earlier form reads");
        assert_eq!(read, canonical, "{other}");
    }
}
