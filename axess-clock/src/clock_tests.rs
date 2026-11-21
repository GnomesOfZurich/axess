//! Tests of the clock itself: the system clock's reading, a shared clock,
//! and the helper functions over a clock.

use super::*;
use crate::testing::MockClock;
use std::sync::Arc;
use std::time::Duration;

/// 2024-01-01T00:00:00Z: any run of these tests is later.
const FLOOR: Timestamp = Timestamp::from_utc(2024, 1, 1, 0, 0, 0).unwrap();

/// The reference time and a quarter of a second.
fn reference_and_a_quarter() -> Timestamp {
    Timestamp::new(1_767_225_600, 250_000_000).expect("inside the range")
}

/// `SystemClock::now()` returns the wall-clock time, distinct from the Unix
/// epoch and from either end of the range: a body that returned a fixed
/// reading would silently break every consumer that relies on it (token
/// issuance, audit timestamps, replay caches).
#[test]
#[cfg_attr(
    miri,
    ignore = "reads the host's clock, which Miri's isolation refuses"
)]
fn system_clock_now_returns_recent_wall_clock_time() {
    let now = SystemClock.now();
    assert!(
        now > FLOOR,
        "SystemClock::now() must return wall-clock time (got {now})"
    );
    assert!(now < Timestamp::MAX);
    // The reading is the one the standard library gives at that moment. A
    // step of the host's clock between the reads could break their order,
    // so the three are held to a minute of each other.
    let before = Timestamp::try_from(SystemTime::now()).expect("inside the range");
    let read = SystemClock.now();
    let after = Timestamp::try_from(SystemTime::now()).expect("inside the range");
    let minute = Duration::from_secs(60);
    assert!(
        read.since(before).unsigned_abs() < minute,
        "{before} {read}"
    );
    assert!(after.since(read).unsigned_abs() < minute, "{read} {after}");
}

#[test]
fn a_system_time_inside_the_range_reads_as_itself() {
    let epoch = SystemTime::UNIX_EPOCH;
    assert_eq!(Timestamp::from_system_time(epoch), Timestamp::UNIX_EPOCH);
    assert_eq!(
        Timestamp::from_system_time(epoch + Duration::new(1_767_225_600, 250_000_000)),
        reference_and_a_quarter()
    );
    assert_eq!(
        Timestamp::from_system_time(epoch - Duration::from_millis(1_250)),
        Timestamp::new(-2, 750_000_000).expect("inside the range")
    );
}

#[test]
fn a_system_time_outside_the_range_reads_as_the_nearer_end() {
    // Ten million years either side of 1970, where the platform's clock
    // type can hold it (it cannot on every platform).
    let far = Duration::from_secs(10_000_000 * 366 * 86_400);
    if let Some(after) = SystemTime::UNIX_EPOCH.checked_add(far) {
        assert_eq!(Timestamp::from_system_time(after), Timestamp::MAX);
    }
    if let Some(before) = SystemTime::UNIX_EPOCH.checked_sub(far) {
        assert_eq!(Timestamp::from_system_time(before), Timestamp::MIN);
    }
    // The last second a `Timestamp` holds, and the one after it.
    let last = Duration::from_secs(8_210_266_876_799);
    if let Some(inside) = SystemTime::UNIX_EPOCH.checked_add(last) {
        assert_eq!(
            Timestamp::from_system_time(inside),
            Timestamp::from_unix_seconds(8_210_266_876_799).expect("the last second")
        );
    }
    if let Some(outside) = SystemTime::UNIX_EPOCH.checked_add(last + Duration::from_secs(1)) {
        assert_eq!(Timestamp::from_system_time(outside), Timestamp::MAX);
    }
    // The latest reading itself, the last nanosecond of that second, where
    // the platform's clock type counts nanoseconds.
    if let Some(latest) = SystemTime::UNIX_EPOCH.checked_add(last + Duration::new(0, 999_999_999))
        && Timestamp::try_from(latest) == Ok(Timestamp::MAX)
    {
        assert_eq!(Timestamp::from_system_time(latest), Timestamp::MAX);
    }
    // The first second a `Timestamp` holds, a nanosecond into it, and the
    // nanosecond before it.
    let first = Duration::from_secs(8_334_601_228_800);
    if let Some(inside) = SystemTime::UNIX_EPOCH.checked_sub(first) {
        assert_eq!(Timestamp::from_system_time(inside), Timestamp::MIN);
        assert_eq!(
            Timestamp::from_system_time(inside + Duration::from_secs(1)),
            Timestamp::from_unix_seconds(-8_334_601_228_799).expect("the second second")
        );
    }
    if let Some(outside) = SystemTime::UNIX_EPOCH.checked_sub(first + Duration::from_secs(1)) {
        assert_eq!(Timestamp::from_system_time(outside), Timestamp::MIN);
    }
}

/// The conversion that refuses and the one that takes the nearer end agree
/// wherever the first one answers.
#[test]
fn the_two_conversions_of_a_system_time_agree_inside_the_range() {
    for seconds in [0, 1, 59, 1_767_225_600, 8_210_266_876_799] {
        for nanos in [0, 1, 999_999_000] {
            let span = Duration::new(seconds, nanos);
            for time in [
                SystemTime::UNIX_EPOCH.checked_add(span),
                SystemTime::UNIX_EPOCH.checked_sub(span),
            ]
            .into_iter()
            .flatten()
            {
                assert_eq!(
                    Ok(Timestamp::from_system_time(time)),
                    Timestamp::try_from(time),
                    "{span:?}"
                );
            }
        }
    }
}

#[test]
fn a_shared_clock_reads_the_clock_it_shares() {
    fn read(clock: impl Clock) -> Timestamp {
        clock.now()
    }
    let mock = MockClock::at_reference();
    let shared: Arc<dyn Clock> = Arc::new(mock.clone());
    assert_eq!(shared.now(), MockClock::reference_time());
    mock.advance_secs(90);
    assert_eq!(read(shared).unix_seconds(), 1_767_225_690);
    assert_eq!(read(Arc::new(mock)).unix_seconds(), 1_767_225_690);
}

/// `now_rfc3339` writes the clock's reading with the numeric offset: the
/// text earlier releases returned from it.
#[test]
fn now_rfc3339_writes_the_reading_with_the_numeric_offset() {
    let clock = MockClock::at_reference();
    assert_eq!(now_rfc3339(&clock), "2026-01-01T00:00:00+00:00");
    clock.set(reference_and_a_quarter());
    assert_eq!(now_rfc3339(&clock), "2026-01-01T00:00:00.250+00:00");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "reads the host's clock, which Miri's isolation refuses"
)]
fn now_rfc3339_returns_parseable_recent_timestamp() {
    let s = now_rfc3339(&SystemClock);
    let parsed = Timestamp::parse_rfc3339(&s).expect("now_rfc3339 must produce RFC 3339 text");
    assert!(
        parsed > FLOOR,
        "now_rfc3339 must reflect wall-clock time (got {s})"
    );
}

/// `now_epoch` returns the clock's Unix second, rounded down.
#[test]
fn now_epoch_returns_the_unix_second() {
    let clock = MockClock::at_reference();
    assert_eq!(now_epoch(&clock), 1_767_225_600);
    clock.set(reference_and_a_quarter());
    assert_eq!(now_epoch(&clock), 1_767_225_600);
    clock.set(Timestamp::new(-2, 750_000_000).expect("inside the range"));
    assert_eq!(now_epoch(&clock), -2);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "reads the host's clock, which Miri's isolation refuses"
)]
fn now_epoch_returns_recent_timestamp() {
    let t = now_epoch(&SystemClock);
    assert!(
        t > 1_700_000_000,
        "now_epoch must return wall-clock seconds (got {t})"
    );
}

/// `parse_datetime_flexible` exercises every branch of `(txt, secs)`:
/// - txt valid → returns parsed (uses txt path),
/// - txt invalid + secs Some → falls through to secs,
/// - txt valid + secs Some → txt wins (precedence),
/// - txt invalid + secs None → None,
/// - both None → None.
///
/// Pins the body replacements, and the `&& → ||` mutation on the let-chain
/// (which would short-circuit to "valid txt" on any non-None txt regardless
/// of parse success).
#[test]
fn parse_datetime_flexible_branches() {
    let valid_rfc3339 = "2026-04-01T12:00:00Z";
    let named = Timestamp::from_utc(2026, 4, 1, 12, 0, 0).expect("a day of the calendar");
    assert_eq!(
        parse_datetime_flexible(Some(valid_rfc3339), None),
        Some(named)
    );

    // txt invalid → falls through to secs.
    let from_secs = parse_datetime_flexible(Some("not-a-date"), Some(1_700_000_000))
        .expect("invalid txt with valid secs must fall through to secs");
    assert_eq!(from_secs.unix_seconds(), 1_700_000_000);

    // txt valid + secs present → txt wins (precedence).
    assert_eq!(
        parse_datetime_flexible(Some(valid_rfc3339), Some(1)),
        Some(named),
        "&& → || would have used the secs fallback"
    );

    // txt missing → use secs.
    assert_eq!(
        parse_datetime_flexible(None, Some(0)),
        Some(Timestamp::UNIX_EPOCH)
    );

    // txt invalid and no secs, and both None → None.
    assert_eq!(parse_datetime_flexible(Some("not-a-date"), None), None);
    assert_eq!(parse_datetime_flexible(None, None), None);

    // A count of seconds outside the range is no reading.
    assert_eq!(parse_datetime_flexible(None, Some(i64::MAX)), None);
    assert_eq!(
        parse_datetime_flexible(Some("not-a-date"), Some(8_210_266_876_800)),
        None
    );

    // The text is read by the one reader, so its other forms read too.
    assert_eq!(
        parse_datetime_flexible(Some("2026-04-01T14:00:00+02:00"), None),
        Some(named)
    );
}

/// `epoch_to_rfc3339` writes the second with the numeric offset, and has no
/// text for a second outside the range.
#[test]
fn epoch_to_rfc3339_writes_the_second_with_the_numeric_offset() {
    assert_eq!(
        epoch_to_rfc3339(1_700_000_000).as_deref(),
        Some("2023-11-14T22:13:20+00:00")
    );
    assert_eq!(
        epoch_to_rfc3339(0).as_deref(),
        Some("1970-01-01T00:00:00+00:00")
    );
    assert_eq!(
        epoch_to_rfc3339(8_210_266_876_799).as_deref(),
        Some("+262142-12-31T23:59:59+00:00")
    );
    assert_eq!(epoch_to_rfc3339(8_210_266_876_800), None);
    assert_eq!(epoch_to_rfc3339(i64::MIN), None);
}
