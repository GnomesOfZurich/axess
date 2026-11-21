//! How code that keeps another time library converts at its boundary with
//! this crate's types, and how it implements `Clock` over a source of its
//! own. The migration page for 0.20.0 quotes these cases.
//!
//! No conversion to or from a third-party type is part of the public API.
//! An adopter converts through what both sides hold: Unix seconds and
//! nanoseconds, `std::time::SystemTime`, or RFC 3339 text. The standard
//! library's cases come first; chrono's follow, since chrono is the one
//! other library these tests build (it is the oracle of
//! `tests/chrono_agreement.rs`). Another library converts by the same rule,
//! through whichever of the three it reads and writes.

use axess_clock::{Clock, SignedDuration, Timestamp};
use std::time::{Duration, SystemTime};

const NEW_YEAR: Timestamp = Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap();

/// Unix seconds and nanoseconds: the reading as two numbers, and back. Each
/// constructor answers `None` outside the range of a `Timestamp`.
#[test]
fn through_unix_seconds_and_nanoseconds() {
    let at = NEW_YEAR
        .checked_add(SignedDuration::milliseconds(250))
        .expect("inside the range");
    let (secs, nanos) = (at.unix_seconds(), at.subsec_nanos());
    assert_eq!((secs, nanos), (1_767_225_600, 250_000_000));
    assert_eq!(Timestamp::new(secs, nanos), Some(at));
    assert_eq!(Timestamp::from_unix_nanos(at.unix_nanos()), Some(at));
    assert_eq!(Timestamp::from_unix_seconds(i64::MAX), None);
}

/// `std::time::SystemTime`, both ways fallible: on some platforms it starts
/// later or ends sooner than a `Timestamp`. `Timestamp::from_system_time`
/// takes the nearer end of the range instead of refusing.
#[test]
fn through_system_time() {
    let system = SystemTime::try_from(NEW_YEAR).expect("a system time on this platform");
    assert_eq!(Timestamp::try_from(system), Ok(NEW_YEAR));
    assert_eq!(Timestamp::from_system_time(system), NEW_YEAR);
}

/// RFC 3339 text: `to_rfc3339` writes the `Z` form, `parse_rfc3339` reads
/// any offset and gives the reading in UTC.
#[test]
fn through_rfc3339_text() {
    assert_eq!(NEW_YEAR.to_rfc3339(), "2026-01-01T00:00:00Z");
    assert_eq!(
        Timestamp::parse_rfc3339("2026-01-01T01:00:00+01:00"),
        Ok(NEW_YEAR)
    );
}

/// A configured lifetime is the standard library's `Duration`; a difference
/// of two readings is a `SignedDuration`. Between the two, a negative span
/// is refused.
#[test]
fn spans_through_the_standard_library() {
    let lifetime = Duration::from_secs(900);
    let span = SignedDuration::try_from(lifetime).expect("fits a signed span");
    assert_eq!(span, SignedDuration::minutes(15));
    assert_eq!(Duration::try_from(span), Ok(lifetime));
    assert!(Duration::try_from(SignedDuration::seconds(-1)).is_err());
}

/// chrono, through Unix seconds and nanoseconds. chrono keeps a leap second
/// as a fraction of a whole second or more, which a `Timestamp` does not
/// have: it is read as the last nanosecond of second 59, as
/// `Timestamp::parse_rfc3339` reads a second of 60.
fn from_chrono(at: chrono::DateTime<chrono::Utc>) -> Option<Timestamp> {
    Timestamp::new(at.timestamp(), at.timestamp_subsec_nanos().min(999_999_999))
}

fn to_chrono(at: Timestamp) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(at.unix_seconds(), at.subsec_nanos())
}

#[test]
fn chrono_through_unix_seconds_and_nanoseconds() {
    let at = NEW_YEAR
        .checked_add(SignedDuration::nanoseconds(1))
        .expect("inside the range");
    let theirs = to_chrono(at).expect("chrono holds the reading");
    assert_eq!(theirs.to_rfc3339(), "2026-01-01T00:00:00.000000001+00:00");
    assert_eq!(from_chrono(theirs), Some(at));
}

/// chrono, through RFC 3339 text.
#[test]
fn chrono_through_rfc3339_text() {
    let theirs: chrono::DateTime<chrono::Utc> =
        NEW_YEAR.to_rfc3339().parse().expect("chrono reads it");
    assert_eq!(Timestamp::parse_rfc3339(&theirs.to_rfc3339()), Ok(NEW_YEAR));
}

/// A `Clock` over a source of the adopter's own: here a function that
/// returns chrono readings, converted through `SystemTime`, which never
/// fails. In production the source is `chrono::Utc::now`; a test hands it a
/// fixed reading.
struct SourceClock(fn() -> chrono::DateTime<chrono::Utc>);

impl Clock for SourceClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_system_time(SystemTime::from((self.0)()))
    }
}

#[test]
fn a_clock_over_another_source() {
    let clock = SourceClock(|| chrono::DateTime::from_timestamp(1_767_225_600, 0).expect("a date"));
    assert_eq!(clock.now(), NEW_YEAR);
}
