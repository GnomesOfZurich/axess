//! A stored time with a second of 60, read through the row form.
//!
//! RFC 3339 writes a leap second as `:60`, and an earlier release kept such
//! a text: its Unix second was that of second 59 of the minute. A row that
//! holds one still reads, as the last nanosecond of that second 59: the Unix
//! second is the one the earlier release gave it, it orders after every
//! other reading of that second and before the next second, and it is
//! written back as `:59.999999999`. A second of 61 is refused, as it was.
//!
//! Each case reads a row the way a store's row is read, through the serde
//! of a type that holds a stored time.

use axess_core::authn::ids::UserId;
use axess_core::authn::types::{StatusCause, StatusDetail};
use axess_core::session::data::Impersonation;

const ADMIN: &str = "01010101-0101-0101-0101-010101010101";

/// The row of an impersonation that began at `since`.
fn row(since: &str) -> String {
    format!(r#"{{"admin":"{ADMIN}","since":"{since}"}}"#)
}

/// The row read the way a store reads it.
fn read(since: &str) -> Result<Impersonation, serde_json::Error> {
    serde_json::from_str(&row(since))
}

/// The row a value is written as.
fn written(stored: &Impersonation) -> String {
    serde_json::to_string(stored).expect("serialises")
}

#[test]
fn a_second_of_60_reads_as_the_last_nanosecond_of_second_59() {
    // The stored text, the Unix second it has, and the text it is written
    // back as.
    let cases = [
        (
            "2016-12-31T23:59:60Z",
            1_483_228_799,
            "2016-12-31T23:59:59.999999999Z",
        ),
        (
            "2026-01-01T00:00:60Z",
            1_767_225_659,
            "2026-01-01T00:00:59.999999999Z",
        ),
        // A second of 60 in any minute, not only the last of a day.
        (
            "2026-01-01T12:34:60Z",
            1_767_270_899,
            "2026-01-01T12:34:59.999999999Z",
        ),
        // Whatever fraction it carries.
        (
            "2026-01-01T00:00:60.5Z",
            1_767_225_659,
            "2026-01-01T00:00:59.999999999Z",
        ),
        (
            "2026-01-01T00:00:60.000000001Z",
            1_767_225_659,
            "2026-01-01T00:00:59.999999999Z",
        ),
        (
            "2026-01-01T00:00:60.999999999Z",
            1_767_225_659,
            "2026-01-01T00:00:59.999999999Z",
        ),
        // In the other forms a stored time may have.
        (
            "2026-01-01T01:00:60+01:00",
            1_767_225_659,
            "2026-01-01T00:00:59.999999999Z",
        ),
        (
            "2026-01-01T00:00:60+00:00",
            1_767_225_659,
            "2026-01-01T00:00:59.999999999Z",
        ),
        (
            "2026-01-01 00:00:60z",
            1_767_225_659,
            "2026-01-01T00:00:59.999999999Z",
        ),
    ];
    for (stored, unix_second, back) in cases {
        let since = read(stored)
            .unwrap_or_else(|error| panic!("{stored} does not read: {error}"))
            .since;
        assert_eq!(since.unix_seconds(), unix_second, "{stored}");
        assert_eq!(since.subsec_nanos(), 999_999_999, "{stored}");
        let again = Impersonation {
            admin: UserId::from_bytes([1; 16]),
            since,
        };
        assert_eq!(written(&again), row(back), "{stored}");
        // What was written reads back as the same reading, and is written
        // the same way again.
        let reread = read(back).expect("the written text reads");
        assert_eq!(reread.since, since, "{stored}");
        assert_eq!(written(&reread), row(back), "{stored}");
    }
}

#[test]
fn a_second_of_60_orders_between_second_59_and_the_next_minute() {
    let at = |stored: &str| read(stored).expect("reads").since;
    let leap = at("2016-12-31T23:59:60Z");
    assert!(at("2016-12-31T23:59:59Z") < leap);
    assert!(at("2016-12-31T23:59:59.999999998Z") < leap);
    assert_eq!(at("2016-12-31T23:59:59.999999999Z"), leap);
    assert!(leap < at("2017-01-01T00:00:00Z"));
    // Two texts of the same second of 60 are one reading.
    assert_eq!(at("2016-12-31T23:59:60.25Z"), leap);
    assert_eq!(at("2017-01-01T00:59:60+01:00"), leap);
}

#[test]
fn a_second_of_60_at_the_end_of_the_range_is_the_latest_reading() {
    let stored = "+262142-12-31T23:59:60Z";
    let since = read(stored).expect("reads").since;
    assert_eq!(since.unix_seconds(), 8_210_266_876_799);
    let again = Impersonation {
        admin: UserId::from_bytes([1; 16]),
        since,
    };
    assert_eq!(written(&again), row("+262142-12-31T23:59:59.999999999Z"));
}

#[test]
fn a_second_past_60_is_refused() {
    for stored in [
        "2016-12-31T23:59:61Z",
        "2016-12-31T23:59:99Z",
        "2016-12-31T23:60:00Z",
        "2016-12-31T24:00:60Z",
    ] {
        assert!(read(stored).is_err(), "{stored:?} read as a time");
    }
}

/// The same reading through another stored type: the start and the end of
/// an account's status.
#[test]
fn a_status_row_reads_a_second_of_60_in_its_since_and_its_until() {
    let stored = r#"{"cause":"Lockout","reason":"r","since":"2016-12-31T23:59:60Z","until":"2017-01-01T00:14:60Z"}"#;
    let detail: StatusDetail = serde_json::from_str(stored).expect("the row reads");
    assert_eq!(detail.cause, StatusCause::Lockout);
    assert_eq!(detail.since.unix_seconds(), 1_483_228_799);
    assert_eq!(
        serde_json::to_string(&detail).expect("serialises"),
        r#"{"cause":"Lockout","reason":"r","since":"2016-12-31T23:59:59.999999999Z","until":"2017-01-01T00:14:59.999999999Z"}"#
    );
}
