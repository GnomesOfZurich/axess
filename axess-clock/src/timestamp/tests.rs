use super::{MAX_SECONDS, MIN_SECONDS, Timestamp};
use crate::date::UtcDate;
use crate::duration::SignedDuration;
use crate::error::TimeError;
use crate::sample::Generator;
use std::collections::HashSet;
use std::time::{Duration, SystemTime};

/// 2026-01-01T00:00:00Z as Unix seconds.
const REFERENCE: i64 = 1_767_225_600;

fn at(secs: i64, nanos: u32) -> Timestamp {
    Timestamp::new(secs, nanos).expect("a reading inside the range")
}

fn parts(at: Timestamp) -> (i64, u32) {
    (at.unix_seconds(), at.subsec_nanos())
}

fn span(secs: i64, nanos: i32) -> SignedDuration {
    SignedDuration::from_mixed(secs, nanos)
}

#[test]
fn the_range_is_the_one_earlier_releases_stored() {
    assert_eq!(MIN_SECONDS, -8_334_601_228_800);
    assert_eq!(MAX_SECONDS, 8_210_266_876_799);
    assert_eq!(parts(Timestamp::MIN), (-8_334_601_228_800, 0));
    assert_eq!(parts(Timestamp::MAX), (8_210_266_876_799, 999_999_999));
    assert_eq!(parts(Timestamp::UNIX_EPOCH), (0, 0));
    assert_eq!(
        Timestamp::from_utc(-262_143, 1, 1, 0, 0, 0),
        Some(Timestamp::MIN)
    );
    assert_eq!(
        Timestamp::from_utc(262_142, 12, 31, 23, 59, 59),
        Some(at(8_210_266_876_799, 0))
    );
    assert_eq!(size_of::<Timestamp>(), 16);
}

#[test]
fn a_reading_outside_the_range_is_refused_by_every_constructor() {
    assert_eq!(Timestamp::new(MIN_SECONDS, 0), Some(Timestamp::MIN));
    assert_eq!(
        Timestamp::new(MAX_SECONDS, 999_999_999),
        Some(Timestamp::MAX)
    );
    assert_eq!(Timestamp::new(MIN_SECONDS - 1, 999_999_999), None);
    assert_eq!(Timestamp::new(MAX_SECONDS + 1, 0), None);
    assert_eq!(Timestamp::new(i64::MIN, 0), None);
    assert_eq!(Timestamp::new(i64::MAX, 0), None);
    assert_eq!(Timestamp::new(0, 1_000_000_000), None);
    assert_eq!(Timestamp::new(0, u32::MAX), None);
    assert_eq!(parts(at(0, 999_999_999)), (0, 999_999_999));

    assert_eq!(
        Timestamp::from_unix_seconds(MIN_SECONDS),
        Some(Timestamp::MIN)
    );
    assert_eq!(
        Timestamp::from_unix_seconds(MAX_SECONDS).map(parts),
        Some((MAX_SECONDS, 0))
    );
    assert_eq!(Timestamp::from_unix_seconds(MIN_SECONDS - 1), None);
    assert_eq!(Timestamp::from_unix_seconds(MAX_SECONDS + 1), None);
    assert_eq!(Timestamp::from_unix_seconds(i64::MIN), None);
    assert_eq!(Timestamp::from_unix_seconds(i64::MAX), None);

    assert_eq!(
        Timestamp::from_unix_millis(MIN_SECONDS * 1_000),
        Some(Timestamp::MIN)
    );
    assert_eq!(Timestamp::from_unix_millis(MIN_SECONDS * 1_000 - 1), None);
    assert_eq!(
        Timestamp::from_unix_millis(MAX_SECONDS * 1_000 + 999).map(parts),
        Some((MAX_SECONDS, 999_000_000))
    );
    assert_eq!(
        Timestamp::from_unix_millis(MAX_SECONDS * 1_000 + 1_000),
        None
    );
    assert_eq!(Timestamp::from_unix_millis(i64::MIN), None);
    assert_eq!(Timestamp::from_unix_millis(i64::MAX), None);

    assert_eq!(
        Timestamp::from_unix_micros(MIN_SECONDS * 1_000_000),
        Some(Timestamp::MIN)
    );
    assert_eq!(
        Timestamp::from_unix_micros(MIN_SECONDS * 1_000_000 - 1),
        None
    );
    assert_eq!(
        Timestamp::from_unix_micros(MAX_SECONDS * 1_000_000 + 999_999).map(parts),
        Some((MAX_SECONDS, 999_999_000))
    );
    assert_eq!(
        Timestamp::from_unix_micros(MAX_SECONDS * 1_000_000 + 1_000_000),
        None
    );
    assert_eq!(Timestamp::from_unix_micros(i64::MIN), None);
    assert_eq!(Timestamp::from_unix_micros(i64::MAX), None);

    let first = i128::from(MIN_SECONDS) * 1_000_000_000;
    let last = i128::from(MAX_SECONDS) * 1_000_000_000 + 999_999_999;
    assert_eq!(Timestamp::from_unix_nanos(first), Some(Timestamp::MIN));
    assert_eq!(Timestamp::from_unix_nanos(first - 1), None);
    assert_eq!(Timestamp::from_unix_nanos(last), Some(Timestamp::MAX));
    assert_eq!(Timestamp::from_unix_nanos(last + 1), None);
    assert_eq!(Timestamp::from_unix_nanos(i128::MIN), None);
    assert_eq!(Timestamp::from_unix_nanos(i128::MAX), None);
    // One nanosecond past an `i64` of nanoseconds is a reading in 2262.
    assert_eq!(
        Timestamp::from_unix_nanos(i128::from(i64::MAX) + 1).map(parts),
        Some((9_223_372_036, 854_775_808))
    );
}

#[test]
fn counts_since_the_epoch_split_into_a_second_and_a_fraction() {
    let cases: [(Option<Timestamp>, (i64, u32)); 22] = [
        (Timestamp::from_unix_seconds(0), (0, 0)),
        (Timestamp::from_unix_seconds(REFERENCE), (REFERENCE, 0)),
        (Timestamp::from_unix_seconds(-1), (-1, 0)),
        (Timestamp::from_unix_millis(0), (0, 0)),
        (Timestamp::from_unix_millis(1), (0, 1_000_000)),
        (Timestamp::from_unix_millis(999), (0, 999_000_000)),
        (Timestamp::from_unix_millis(1_500), (1, 500_000_000)),
        (Timestamp::from_unix_millis(-1), (-1, 999_000_000)),
        (Timestamp::from_unix_millis(-1_000), (-1, 0)),
        (Timestamp::from_unix_millis(-1_001), (-2, 999_000_000)),
        (
            Timestamp::from_unix_millis(REFERENCE * 1_000 + 250),
            (REFERENCE, 250_000_000),
        ),
        (Timestamp::from_unix_micros(1), (0, 1_000)),
        (Timestamp::from_unix_micros(1_000_000), (1, 0)),
        (Timestamp::from_unix_micros(-1), (-1, 999_999_000)),
        (Timestamp::from_unix_micros(-1_000_000), (-1, 0)),
        (Timestamp::from_unix_micros(-1_000_001), (-2, 999_999_000)),
        (
            Timestamp::from_unix_micros(REFERENCE * 1_000_000 + 123_456),
            (REFERENCE, 123_456_000),
        ),
        (Timestamp::from_unix_nanos(1), (0, 1)),
        (Timestamp::from_unix_nanos(1_000_000_000), (1, 0)),
        (Timestamp::from_unix_nanos(-1), (-1, 999_999_999)),
        (Timestamp::from_unix_nanos(-1_000_000_000), (-1, 0)),
        (
            Timestamp::from_unix_nanos(-1_000_000_001),
            (-2, 999_999_999),
        ),
    ];
    for (index, (read, expected)) in cases.into_iter().enumerate() {
        assert_eq!(read.map(parts), Some(expected), "case {index}");
    }
}

#[test]
fn counts_round_down_before_the_epoch_too() {
    // (second, fraction), then the counts in seconds, milliseconds,
    // microseconds and nanoseconds.
    let cases = [
        ((0, 0), 0, 0, 0, 0),
        ((0, 999_999_999), 0, 999, 999_999, 999_999_999),
        ((1, 500_000_000), 1, 1_500, 1_500_000, 1_500_000_000),
        ((-1, 999_999_999), -1, -1, -1, -1),
        ((-1, 999_999_500), -1, -1, -1, -500),
        ((-1, 999_000_000), -1, -1, -1_000, -1_000_000),
        ((-1, 998_999_999), -1, -2, -1_001, -1_000_001),
        ((-1, 500_000_000), -1, -500, -500_000, -500_000_000),
        ((-1, 1), -1, -1_000, -1_000_000, -999_999_999),
        ((-1, 0), -1, -1_000, -1_000_000, -1_000_000_000),
        ((-2, 1), -2, -2_000, -2_000_000, -1_999_999_999),
        (
            (REFERENCE, 123_456_789),
            REFERENCE,
            1_767_225_600_123,
            1_767_225_600_123_456,
            1_767_225_600_123_456_789,
        ),
        (
            (MAX_SECONDS, 999_999_999),
            8_210_266_876_799,
            8_210_266_876_799_999,
            8_210_266_876_799_999_999,
            8_210_266_876_799_999_999_999,
        ),
        (
            (MIN_SECONDS, 0),
            -8_334_601_228_800,
            -8_334_601_228_800_000,
            -8_334_601_228_800_000_000,
            -8_334_601_228_800_000_000_000,
        ),
        (
            (MIN_SECONDS, 1),
            -8_334_601_228_800,
            -8_334_601_228_800_000,
            -8_334_601_228_800_000_000,
            -8_334_601_228_799_999_999_999,
        ),
    ];
    for ((secs, nanos), seconds, millis, micros, nanoseconds) in cases {
        let at = at(secs, nanos);
        assert_eq!(at.unix_seconds(), seconds, "{at}");
        assert_eq!(at.unix_millis(), millis, "{at}");
        assert_eq!(at.unix_micros(), micros, "{at}");
        assert_eq!(at.unix_nanos(), nanoseconds, "{at}");
        assert_eq!(at.subsec_nanos(), nanos, "{at}");
        assert_eq!(Timestamp::from_unix_nanos(nanoseconds), Some(at));
    }
}

#[test]
fn a_date_and_a_time_of_day_give_their_reading() {
    const NEW_YEAR: Timestamp = Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap();
    const NO_SUCH_DAY: Option<Timestamp> = Timestamp::from_utc(2026, 2, 30, 0, 0, 0);
    assert_eq!(parts(NEW_YEAR), (REFERENCE, 0));
    assert_eq!(NO_SUCH_DAY, None);

    let cases = [
        ((1970, 1, 1, 0, 0, 0), 0),
        ((1970, 1, 1, 0, 0, 1), 1),
        ((1970, 1, 1, 0, 1, 0), 60),
        ((1970, 1, 1, 1, 0, 0), 3_600),
        ((1970, 1, 1, 23, 59, 59), 86_399),
        ((1970, 1, 2, 0, 0, 0), 86_400),
        ((1969, 12, 31, 23, 59, 59), -1),
        ((1969, 12, 31, 0, 0, 0), -86_400),
        ((2026, 1, 1, 0, 0, 0), REFERENCE),
        ((2026, 7, 4, 12, 34, 56), 1_783_168_496),
        ((2000, 2, 29, 12, 0, 0), 951_825_600),
        ((1, 1, 1, 0, 0, 0), -62_135_596_800),
        ((0, 1, 1, 0, 0, 0), -62_167_219_200),
        ((-1, 12, 31, 23, 59, 59), -62_167_219_201),
        ((9999, 12, 31, 23, 59, 59), 253_402_300_799),
        ((10_000, 1, 1, 0, 0, 0), 253_402_300_800),
        ((262_142, 12, 31, 23, 59, 59), MAX_SECONDS),
        ((-262_143, 1, 1, 0, 0, 0), MIN_SECONDS),
    ];
    for ((year, month, day, hour, minute, second), secs) in cases {
        let read = Timestamp::from_utc(year, month, day, hour, minute, second);
        assert_eq!(
            read.map(parts),
            Some((secs, 0)),
            "{year}-{month}-{day} {hour}:{minute}:{second}"
        );
        let date = UtcDate::new(year, month, day).expect("a day of the calendar");
        assert_eq!(at(secs, 7).to_utc(), (date, hour, minute, second, 7));
        assert_eq!(at(secs, 7).utc_date(), date);
    }
}

#[test]
fn a_date_or_a_time_of_day_that_does_not_exist_gives_no_reading() {
    for (year, month, day, hour, minute, second) in [
        (2026, 1, 1, 24, 0, 0),
        (2026, 1, 1, 0, 60, 0),
        (2026, 1, 1, 0, 0, 60),
        (2026, 1, 1, u8::MAX, 0, 0),
        (2026, 1, 1, 0, u8::MAX, 0),
        (2026, 1, 1, 0, 0, u8::MAX),
        (2026, 2, 29, 0, 0, 0),
        (2026, 2, 30, 0, 0, 0),
        (2026, 13, 1, 0, 0, 0),
        (2026, 0, 1, 0, 0, 0),
        (2026, 1, 0, 0, 0, 0),
        (2026, 1, 32, 0, 0, 0),
        (262_143, 1, 1, 0, 0, 0),
        (-262_144, 12, 31, 23, 59, 59),
        (i32::MAX, 1, 1, 0, 0, 0),
        (i32::MIN, 1, 1, 0, 0, 0),
    ] {
        assert_eq!(
            Timestamp::from_utc(year, month, day, hour, minute, second),
            None,
            "{year}-{month}-{day} {hour}:{minute}:{second}"
        );
    }
    assert!(Timestamp::from_utc(2026, 1, 1, 23, 59, 59).is_some());
    assert!(Timestamp::from_utc(2024, 2, 29, 0, 0, 0).is_some());
}

#[test]
fn a_reading_breaks_down_into_its_date_and_time_of_day() {
    let day = |year, month, day| UtcDate::new(year, month, day).expect("a day of the calendar");
    let cases = [
        (at(0, 0), (day(1970, 1, 1), 0, 0, 0, 0)),
        (
            at(-1, 999_999_999),
            (day(1969, 12, 31), 23, 59, 59, 999_999_999),
        ),
        (at(-86_400, 0), (day(1969, 12, 31), 0, 0, 0, 0)),
        (at(-86_401, 5), (day(1969, 12, 30), 23, 59, 59, 5)),
        (at(86_399, 1), (day(1970, 1, 1), 23, 59, 59, 1)),
        (at(3_661, 0), (day(1970, 1, 1), 1, 1, 1, 0)),
        (
            at(REFERENCE, 250_000_000),
            (day(2026, 1, 1), 0, 0, 0, 250_000_000),
        ),
        (
            at(1_783_168_496, 789_000_000),
            (day(2026, 7, 4), 12, 34, 56, 789_000_000),
        ),
        (Timestamp::MIN, (UtcDate::MIN, 0, 0, 0, 0)),
        (Timestamp::MAX, (UtcDate::MAX, 23, 59, 59, 999_999_999)),
    ];
    for (at, expected) in cases {
        assert_eq!(at.to_utc(), expected, "{at}");
        assert_eq!(at.utc_date(), expected.0, "{at}");
    }
}

#[test]
fn readings_order_in_time() {
    let ordered = [
        Timestamp::MIN,
        at(MIN_SECONDS, 1),
        at(MIN_SECONDS + 1, 0),
        at(-2, 999_999_999),
        at(-1, 0),
        at(-1, 1),
        at(-1, 999_999_999),
        Timestamp::UNIX_EPOCH,
        at(0, 1),
        at(0, 999_999_999),
        at(1, 0),
        at(REFERENCE, 0),
        at(REFERENCE, 1),
        at(MAX_SECONDS, 0),
        at(MAX_SECONDS, 999_999_998),
        Timestamp::MAX,
    ];
    for (index, earlier) in ordered.iter().enumerate() {
        for later in &ordered[index + 1..] {
            assert!(earlier < later, "{earlier} is before {later}");
            assert!(earlier.unix_nanos() < later.unix_nanos());
            assert!(!later.since(*earlier).is_negative());
            assert!(earlier.since(*later).is_negative());
        }
        assert_eq!(earlier.cmp(earlier), std::cmp::Ordering::Equal);
    }
    let seen: HashSet<Timestamp> = [at(1, 2), at(1, 2), at(2, 1)].into_iter().collect();
    assert_eq!(seen.len(), 2);
}

#[test]
fn a_span_moves_a_reading_and_carries_through_the_fraction() {
    let cases = [
        ((10, 0), span(5, 0), Some((15, 0))),
        ((10, 0), span(-5, 0), Some((5, 0))),
        (
            (10, 600_000_000),
            span(0, 600_000_000),
            Some((11, 200_000_000)),
        ),
        ((10, 500_000_000), span(0, 500_000_000), Some((11, 0))),
        ((10, 999_999_999), span(0, 1), Some((11, 0))),
        (
            (10, 999_999_999),
            span(0, 999_999_999),
            Some((11, 999_999_998)),
        ),
        (
            (10, 200_000_000),
            span(0, -600_000_000),
            Some((9, 600_000_000)),
        ),
        ((10, 0), span(0, -1), Some((9, 999_999_999))),
        ((10, 0), span(0, -999_999_999), Some((9, 1))),
        (
            (10, 250_000_000),
            span(-1, -500_000_000),
            Some((8, 750_000_000)),
        ),
        ((0, 0), span(0, -500_000_000), Some((-1, 500_000_000))),
        ((-1, 500_000_000), span(0, 500_000_000), Some((0, 0))),
        ((-1, 500_000_000), span(0, -500_000_000), Some((-1, 0))),
        ((0, 0), SignedDuration::ZERO, Some((0, 0))),
    ];
    for ((secs, nanos), by, expected) in cases {
        let start = at(secs, nanos);
        let moved = start.checked_add(by);
        assert_eq!(moved.map(parts), expected, "{start} + {by:?}");
        if let Some(moved) = moved {
            assert_eq!(moved.checked_sub(by), Some(start), "{moved} - {by:?}");
            assert_eq!(moved.since(start), by);
        }
    }
}

#[test]
fn arithmetic_stops_at_the_ends_of_the_range() {
    let whole = Timestamp::MAX.since(Timestamp::MIN);
    assert_eq!(
        (whole.whole_seconds(), whole.subsec_nanos()),
        (16_544_868_105_599, 999_999_999)
    );
    let back = Timestamp::MIN.since(Timestamp::MAX);
    assert_eq!(
        (back.whole_seconds(), back.subsec_nanos()),
        (-16_544_868_105_599, -999_999_999)
    );
    assert_eq!(Timestamp::MIN.checked_add(whole), Some(Timestamp::MAX));
    assert_eq!(Timestamp::MAX.checked_sub(whole), Some(Timestamp::MIN));
    assert_eq!(Timestamp::MAX.checked_add(back), Some(Timestamp::MIN));
    assert_eq!(Timestamp::MIN.checked_sub(back), Some(Timestamp::MAX));

    let nanosecond = span(0, 1);
    let cases = [
        (
            Timestamp::MAX,
            SignedDuration::ZERO,
            Some(Timestamp::MAX),
            Some(Timestamp::MAX),
        ),
        (
            Timestamp::MIN,
            SignedDuration::ZERO,
            Some(Timestamp::MIN),
            Some(Timestamp::MIN),
        ),
        (
            Timestamp::MAX,
            nanosecond,
            None,
            Some(at(MAX_SECONDS, 999_999_998)),
        ),
        (Timestamp::MIN, nanosecond, Some(at(MIN_SECONDS, 1)), None),
        (
            Timestamp::MAX,
            span(0, -1),
            Some(at(MAX_SECONDS, 999_999_998)),
            None,
        ),
        (Timestamp::MIN, span(0, -1), None, Some(at(MIN_SECONDS, 1))),
        (
            at(MAX_SECONDS, 0),
            span(0, 999_999_999),
            Some(Timestamp::MAX),
            Some(at(MAX_SECONDS - 1, 1)),
        ),
        (
            at(MAX_SECONDS, 1),
            span(0, 999_999_999),
            None,
            Some(at(MAX_SECONDS - 1, 2)),
        ),
        (
            at(MAX_SECONDS, 0),
            span(1, 0),
            None,
            Some(at(MAX_SECONDS - 1, 0)),
        ),
        (
            at(MIN_SECONDS, 999_999_999),
            span(0, 999_999_999),
            Some(at(MIN_SECONDS + 1, 999_999_998)),
            Some(Timestamp::MIN),
        ),
        (
            at(MIN_SECONDS, 999_999_998),
            span(0, 999_999_999),
            Some(at(MIN_SECONDS + 1, 999_999_997)),
            None,
        ),
        (
            at(MIN_SECONDS, 0),
            span(1, 0),
            Some(at(MIN_SECONDS + 1, 0)),
            None,
        ),
        (Timestamp::MAX, whole, None, Some(Timestamp::MIN)),
        (Timestamp::MIN, whole, Some(Timestamp::MAX), None),
        (Timestamp::UNIX_EPOCH, whole, None, None),
        // Spans wider than the range, and sums of seconds past an `i64`.
        (Timestamp::UNIX_EPOCH, SignedDuration::MAX, None, None),
        (Timestamp::UNIX_EPOCH, SignedDuration::MIN, None, None),
        (at(0, 1), SignedDuration::MAX, None, None),
        (at(-1, 0), SignedDuration::MAX, None, None),
        (at(-1, 999_999_999), SignedDuration::MIN, None, None),
        (at(-1, 0), SignedDuration::MIN, None, None),
        (Timestamp::MAX, SignedDuration::MAX, None, None),
        (Timestamp::MIN, SignedDuration::MIN, None, None),
        (Timestamp::MIN, SignedDuration::MAX, None, None),
        (Timestamp::MAX, SignedDuration::MIN, None, None),
        (
            Timestamp::UNIX_EPOCH,
            SignedDuration::seconds(i64::MAX),
            None,
            None,
        ),
        (
            Timestamp::UNIX_EPOCH,
            SignedDuration::seconds(i64::MIN),
            None,
            None,
        ),
        (
            Timestamp::UNIX_EPOCH,
            SignedDuration::seconds(MAX_SECONDS),
            Some(at(MAX_SECONDS, 0)),
            Some(at(-MAX_SECONDS, 0)),
        ),
        (
            Timestamp::UNIX_EPOCH,
            SignedDuration::seconds(MIN_SECONDS),
            Some(Timestamp::MIN),
            None,
        ),
        (
            Timestamp::UNIX_EPOCH,
            SignedDuration::seconds(MAX_SECONDS + 1),
            None,
            Some(at(-MAX_SECONDS - 1, 0)),
        ),
        (
            Timestamp::UNIX_EPOCH,
            SignedDuration::seconds(MIN_SECONDS - 1),
            None,
            None,
        ),
        (
            Timestamp::UNIX_EPOCH,
            SignedDuration::seconds(-MAX_SECONDS),
            Some(at(-MAX_SECONDS, 0)),
            Some(at(MAX_SECONDS, 0)),
        ),
    ];
    for (index, (start, by, added, subtracted)) in cases.into_iter().enumerate() {
        assert_eq!(
            start.checked_add(by),
            added,
            "case {index}: {start} + {by:?}"
        );
        assert_eq!(
            start.checked_sub(by),
            subtracted,
            "case {index}: {start} - {by:?}"
        );
    }
}

#[test]
fn the_span_between_two_readings_has_one_sign() {
    let cases = [
        ((10, 200_000_000), (9, 700_000_000), (0, 500_000_000)),
        ((9, 700_000_000), (10, 200_000_000), (0, -500_000_000)),
        ((10, 700_000_000), (9, 200_000_000), (1, 500_000_000)),
        ((9, 200_000_000), (10, 700_000_000), (-1, -500_000_000)),
        ((10, 0), (10, 0), (0, 0)),
        ((10, 1), (10, 0), (0, 1)),
        ((10, 0), (10, 1), (0, -1)),
        ((0, 0), (-1, 500_000_000), (0, 500_000_000)),
        ((-1, 500_000_000), (0, 0), (0, -500_000_000)),
        ((5, 0), (-5, 0), (10, 0)),
        ((-5, 0), (5, 0), (-10, 0)),
        ((12, 1), (10, 999_999_999), (1, 2)),
        ((10, 999_999_999), (12, 1), (-1, -2)),
    ];
    for (later, earlier, expected) in cases {
        let (later, earlier) = (at(later.0, later.1), at(earlier.0, earlier.1));
        let between = later.since(earlier);
        assert_eq!(
            (between.whole_seconds(), between.subsec_nanos()),
            expected,
            "{later} since {earlier}"
        );
    }
}

#[test]
fn arithmetic_is_checked_in_constant_code() {
    const START: Timestamp = Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap();
    const LATER: Option<Timestamp> = START.checked_add(SignedDuration::minutes(5));
    const PAST: Option<Timestamp> = Timestamp::MAX.checked_add(SignedDuration::seconds(1));
    const BETWEEN: SignedDuration = Timestamp::MAX.since(START);
    assert_eq!(LATER.map(parts), Some((REFERENCE + 300, 0)));
    assert_eq!(PAST, None);
    assert_eq!(BETWEEN.whole_seconds(), MAX_SECONDS - REFERENCE);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the tables of this module cover the same code under Miri"
)]
fn generated_readings_hold_the_laws_of_the_arithmetic() {
    let mut generator = Generator::new(0x5EED_0002);
    for _ in 0..300_000 {
        let (a, b) = (generator.timestamp(), generator.timestamp());
        let between = b.since(a);
        // The span between two readings brings one to the other.
        assert_eq!(a.checked_add(between), Some(b), "{a} + {between:?}");
        assert_eq!(b.checked_sub(between), Some(a), "{b} - {between:?}");
        assert_eq!(
            i128::from(between.whole_seconds()) * 1_000_000_000
                + i128::from(between.subsec_nanos()),
            b.unix_nanos() - a.unix_nanos()
        );
        assert_eq!(a.cmp(&b), a.unix_nanos().cmp(&b.unix_nanos()));
        assert_eq!(between.is_negative(), b < a);

        // Each count reads back, to its own precision, rounded down.
        assert_eq!(Timestamp::from_unix_nanos(a.unix_nanos()), Some(a));
        assert_eq!(
            Timestamp::from_unix_seconds(a.unix_seconds()).map(parts),
            Some((a.unix_seconds(), 0))
        );
        assert_eq!(
            Timestamp::from_unix_millis(a.unix_millis()).map(parts),
            Some((a.unix_seconds(), a.subsec_nanos() / 1_000_000 * 1_000_000))
        );
        assert_eq!(
            Timestamp::from_unix_micros(a.unix_micros()).map(parts),
            Some((a.unix_seconds(), a.subsec_nanos() / 1_000 * 1_000))
        );
        assert_eq!(
            i128::from(a.unix_millis()),
            a.unix_nanos().div_euclid(1_000_000)
        );
        assert_eq!(
            i128::from(a.unix_micros()),
            a.unix_nanos().div_euclid(1_000)
        );

        // The breakdown reads back as the reading.
        let (date, hour, minute, second, nanos) = a.to_utc();
        assert!(hour < 24 && minute < 60 && second < 60);
        let whole =
            Timestamp::from_utc(date.year(), date.month(), date.day(), hour, minute, second)
                .expect("the breakdown of a reading is a date and a time of day");
        assert_eq!(parts(whole), (a.unix_seconds(), 0));
        assert_eq!(nanos, a.subsec_nanos());
        assert_eq!(a.utc_date(), date);

        // A generated span moves a reading as a count of nanoseconds does.
        let by = generator.span();
        let moved = i128::from(by.whole_seconds()) * 1_000_000_000 + i128::from(by.subsec_nanos());
        assert_eq!(
            a.checked_add(by),
            Timestamp::from_unix_nanos(a.unix_nanos() + moved),
            "{a} + {by:?}"
        );
        assert_eq!(
            a.checked_sub(by),
            Timestamp::from_unix_nanos(a.unix_nanos() - moved),
            "{a} - {by:?}"
        );
    }
}

#[test]
fn the_system_clock_type_converts_both_ways() {
    let epoch = SystemTime::UNIX_EPOCH;
    let cases = [
        (epoch, (0, 0)),
        (epoch + Duration::new(1, 500_000_000), (1, 500_000_000)),
        (epoch + Duration::from_secs(1_767_225_600), (REFERENCE, 0)),
        (epoch + Duration::from_micros(1), (0, 1_000)),
        (epoch - Duration::from_millis(500), (-1, 500_000_000)),
        (epoch - Duration::from_secs(1), (-1, 0)),
        (epoch - Duration::from_millis(1_250), (-2, 750_000_000)),
        (epoch - Duration::from_micros(1), (-1, 999_999_000)),
        (
            epoch - Duration::from_secs(86_400 * 365 * 200),
            (-6_307_200_000, 0),
        ),
    ];
    for (time, expected) in cases {
        let read = Timestamp::try_from(time);
        assert_eq!(read.map(parts), Ok(expected), "{time:?}");
        assert_eq!(read.and_then(SystemTime::try_from), Ok(time), "{time:?}");
    }
}

#[test]
fn a_system_time_outside_the_range_is_refused() {
    let epoch = SystemTime::UNIX_EPOCH;
    // The platform's clock type may not reach this far; where it does, the
    // reading is refused or is the end of the range.
    let past_the_end = epoch.checked_add(Duration::from_secs(MAX_SECONDS.unsigned_abs() + 1));
    if let Some(time) = past_the_end {
        assert_eq!(Timestamp::try_from(time), Err(TimeError::OutOfRange));
    }
    let before_the_start = epoch
        .checked_sub(Duration::from_secs(MIN_SECONDS.unsigned_abs()))
        .and_then(|time| time.checked_sub(Duration::from_nanos(1_000)));
    if let Some(time) = before_the_start {
        assert_eq!(Timestamp::try_from(time), Err(TimeError::OutOfRange));
    }
    if let Some(time) = epoch.checked_add(Duration::from_secs(u64::MAX)) {
        assert_eq!(Timestamp::try_from(time), Err(TimeError::OutOfRange));
    }
    for end in [Timestamp::MIN, Timestamp::MAX] {
        match SystemTime::try_from(end) {
            Ok(time) => {
                let back = Timestamp::try_from(time).expect("a reading inside the range");
                // Equal, or rounded down to the platform's step.
                assert!(back <= end && end.since(back) < SignedDuration::microseconds(1));
            }
            Err(error) => assert_eq!(error, TimeError::OutOfRange),
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the tables of this module cover the same code under Miri"
)]
fn generated_readings_near_the_present_round_trip_through_the_system_clock_type() {
    let mut generator = Generator::new(0x5EED_0003);
    for _ in 0..50_000 {
        // The years 1700 to 2300, which every platform's clock type holds,
        // in whole microseconds, which every platform's clock type counts.
        let secs = generator.between(-8_520_336_000, 10_413_792_000);
        let nanos = generator.between(0, 999_999) as u32 * 1_000;
        let reading = at(secs, nanos);
        let time = SystemTime::try_from(reading).expect("a time the platform holds");
        assert_eq!(Timestamp::try_from(time), Ok(reading));
        let from_epoch = if secs >= 0 {
            SystemTime::UNIX_EPOCH + Duration::new(secs.unsigned_abs(), nanos)
        } else {
            SystemTime::UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
                + Duration::new(0, nanos)
        };
        assert_eq!(time, from_epoch);
    }
}
