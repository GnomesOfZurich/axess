use super::{MAX_DAYS, MAX_YEAR, MIN_DAYS, MIN_YEAR, UtcDate, civil_from_days, days_from_civil};
use crate::error::TimeError;
use std::collections::HashSet;

fn date(year: i32, month: u8, day: u8) -> UtcDate {
    UtcDate::new(year, month, day).expect("a day of the calendar")
}

/// The date of a day count inside the range.
fn on_day(days: i64) -> UtcDate {
    UtcDate::from_days_since_epoch(days).expect("a day of the range")
}

/// The leap rule, written apart from the code under test.
fn leap(year: i64) -> bool {
    (year.rem_euclid(4) == 0 && year.rem_euclid(100) != 0) || year.rem_euclid(400) == 0
}

/// The length of a month, written apart from the code under test.
fn month_length(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if leap(year) => 29,
        _ => 28,
    }
}

/// The day after a date, by stepping the calendar.
fn day_after((year, month, day): (i64, i64, i64)) -> (i64, i64, i64) {
    if day < month_length(year, month) {
        (year, month, day + 1)
    } else if month < 12 {
        (year, month + 1, 1)
    } else {
        (year + 1, 1, 1)
    }
}

fn fields(date: UtcDate) -> (i64, i64, i64) {
    (
        i64::from(date.year()),
        i64::from(date.month()),
        i64::from(date.day()),
    )
}

/// Walks every day of `first..=last` beside a calendar stepped one day at a
/// time, and holds the two conversions to it.
fn walk(first: i64, last: i64) -> u64 {
    let mut expected = fields(on_day(first));
    let mut walked = 0;
    for days in first..=last {
        let date = on_day(days);
        assert_eq!(fields(date), expected, "the date of day {days}");
        assert_eq!(date.days_since_epoch(), days, "the day of {date}");
        assert_eq!(
            UtcDate::new(date.year(), date.month(), date.day()),
            Some(date)
        );
        expected = day_after(expected);
        walked += 1;
    }
    walked
}

#[test]
fn the_range_is_the_pinned_one() {
    assert_eq!((MIN_YEAR, MAX_YEAR), (-262_143, 262_142));
    assert_eq!((MIN_DAYS, MAX_DAYS), (-96_465_292, 95_026_236));
    assert_eq!(fields(UtcDate::MIN), (-262_143, 1, 1));
    assert_eq!(fields(UtcDate::MAX), (262_142, 12, 31));
    assert_eq!(UtcDate::MIN.days_since_epoch(), MIN_DAYS);
    assert_eq!(UtcDate::MAX.days_since_epoch(), MAX_DAYS);
    assert_eq!(UtcDate::MIN, date(-262_143, 1, 1));
    assert_eq!(UtcDate::MAX, date(262_142, 12, 31));
}

#[test]
fn known_dates_have_their_day_counts() {
    let cases = [
        ((1970, 1, 1), 0),
        ((1970, 1, 2), 1),
        ((1969, 12, 31), -1),
        ((2026, 1, 1), 20_454),
        ((2000, 2, 29), 11_016),
        ((2000, 3, 1), 11_017),
        ((1900, 3, 1), -25_508),
        ((1600, 2, 29), -135_081),
        ((1, 1, 1), -719_162),
        ((0, 12, 31), -719_163),
        ((0, 3, 1), -719_468),
        ((0, 2, 29), -719_469),
        ((0, 1, 1), -719_528),
        ((-1, 12, 31), -719_529),
        ((9999, 12, 31), 2_932_896),
        ((10_000, 1, 1), 2_932_897),
    ];
    for ((year, month, day), days) in cases {
        let date = date(year, month, day);
        assert_eq!(date.days_since_epoch(), days, "{date}");
        assert_eq!(
            UtcDate::from_days_since_epoch(days),
            Some(date),
            "day {days}"
        );
    }
}

#[test]
fn a_date_reads_back_its_fields() {
    let date = date(2026, 11, 18);
    assert_eq!(date.year(), 2026);
    assert_eq!(date.month(), 11);
    assert_eq!(date.day(), 18);
}

#[test]
fn every_month_has_its_length() {
    for year in [
        2023, 2024, 1900, 2000, 0, -1, -4, -100, -400, 262_142, -262_143,
    ] {
        for month in 1..=12u8 {
            let length = month_length(i64::from(year), i64::from(month)) as u8;
            assert_eq!(UtcDate::new(year, month, 0), None, "{year}-{month}-0");
            for day in 1..=length {
                let date = UtcDate::new(year, month, day).expect("a day of the month");
                assert_eq!((date.year(), date.month(), date.day()), (year, month, day));
            }
            for day in length + 1..=u8::MAX {
                assert_eq!(UtcDate::new(year, month, day), None, "{year}-{month}-{day}");
            }
        }
    }
}

#[test]
fn the_leap_day_follows_the_gregorian_rule() {
    let leap_years = [
        2024, 2000, 1600, 2400, 4, 0, -4, -400, -800, -262_140, 262_140,
    ];
    let common_years = [
        2023, 2025, 2026, 1900, 2100, 2200, 2300, 1, -1, -100, -200, -300, -262_143, 262_142, 100,
    ];
    for year in leap_years {
        assert!(UtcDate::new(year, 2, 29).is_some(), "{year} is a leap year");
        assert_eq!(UtcDate::new(year, 2, 30), None);
        assert_eq!(
            date(year, 3, 1).days_since_epoch() - date(year, 2, 28).days_since_epoch(),
            2
        );
    }
    for year in common_years {
        assert_eq!(UtcDate::new(year, 2, 29), None, "{year} is a common year");
        assert!(UtcDate::new(year, 2, 28).is_some());
        assert_eq!(
            date(year, 3, 1).days_since_epoch() - date(year, 2, 28).days_since_epoch(),
            1
        );
    }
}

#[test]
fn a_month_or_a_year_outside_its_range_is_no_date() {
    assert_eq!(UtcDate::new(2026, 0, 1), None);
    assert_eq!(UtcDate::new(2026, 13, 1), None);
    assert_eq!(UtcDate::new(2026, u8::MAX, 1), None);
    assert_eq!(UtcDate::new(MIN_YEAR - 1, 12, 31), None);
    assert_eq!(UtcDate::new(MAX_YEAR + 1, 1, 1), None);
    assert_eq!(UtcDate::new(i32::MIN, 1, 1), None);
    assert_eq!(UtcDate::new(i32::MAX, 1, 1), None);
    assert!(UtcDate::new(MIN_YEAR, 1, 1).is_some());
    assert!(UtcDate::new(MAX_YEAR, 12, 31).is_some());
}

#[test]
fn a_date_is_checked_when_the_code_is_compiled() {
    const DAY: Option<UtcDate> = UtcDate::new(2026, 1, 1);
    const NO_DAY: Option<UtcDate> = UtcDate::new(2026, 2, 29);
    assert_eq!(DAY, Some(date(2026, 1, 1)));
    assert_eq!(NO_DAY, None);
}

#[test]
fn dates_order_by_year_then_month_then_day() {
    let ordered = [
        UtcDate::MIN,
        date(-262_143, 1, 2),
        date(-1, 12, 31),
        date(0, 1, 1),
        date(1969, 12, 31),
        date(1970, 1, 1),
        date(2025, 12, 31),
        date(2026, 1, 1),
        date(2026, 1, 2),
        date(2026, 2, 1),
        date(2027, 1, 1),
        date(262_142, 12, 30),
        UtcDate::MAX,
    ];
    for (index, earlier) in ordered.iter().enumerate() {
        for later in &ordered[index + 1..] {
            assert!(earlier < later, "{earlier} is before {later}");
            assert!(earlier.days_since_epoch() < later.days_since_epoch());
        }
        assert_eq!(earlier.cmp(earlier), std::cmp::Ordering::Equal);
    }
}

#[test]
fn equal_dates_hash_alike() {
    let seen: HashSet<UtcDate> = [date(2026, 1, 1), date(2026, 1, 1), date(2026, 1, 2)]
        .into_iter()
        .collect();
    assert_eq!(seen.len(), 2);
    assert!(seen.contains(&on_day(20_454)));
}

#[test]
fn a_day_count_outside_the_range_is_no_date() {
    // Both ends of the range, and the day inside and the day outside each.
    assert_eq!(UtcDate::from_days_since_epoch(MIN_DAYS), Some(UtcDate::MIN));
    assert_eq!(
        UtcDate::from_days_since_epoch(MIN_DAYS + 1),
        Some(date(-262_143, 1, 2))
    );
    assert_eq!(UtcDate::from_days_since_epoch(MIN_DAYS - 1), None);
    assert_eq!(UtcDate::from_days_since_epoch(i64::MIN), None);
    assert_eq!(UtcDate::from_days_since_epoch(MAX_DAYS), Some(UtcDate::MAX));
    assert_eq!(
        UtcDate::from_days_since_epoch(MAX_DAYS - 1),
        Some(date(262_142, 12, 30))
    );
    assert_eq!(UtcDate::from_days_since_epoch(MAX_DAYS + 1), None);
    assert_eq!(UtcDate::from_days_since_epoch(i64::MAX), None);
    // The pinned counts of the two ends, by number.
    assert_eq!(
        UtcDate::from_days_since_epoch(-96_465_292),
        Some(UtcDate::MIN)
    );
    assert_eq!(UtcDate::from_days_since_epoch(-96_465_293), None);
    assert_eq!(
        UtcDate::from_days_since_epoch(95_026_236),
        Some(UtcDate::MAX)
    );
    assert_eq!(UtcDate::from_days_since_epoch(95_026_237), None);
}

#[test]
fn the_day_count_starts_at_the_first_of_january_1970() {
    assert_eq!(UtcDate::from_days_since_epoch(0), Some(date(1970, 1, 1)));
    assert_eq!(UtcDate::from_days_since_epoch(1), Some(date(1970, 1, 2)));
    assert_eq!(UtcDate::from_days_since_epoch(-1), Some(date(1969, 12, 31)));
    assert_eq!(date(1970, 1, 1).days_since_epoch(), 0);
    assert_eq!(date(1970, 1, 2).days_since_epoch(), 1);
    assert_eq!(date(1969, 12, 31).days_since_epoch(), -1);
    assert_eq!(UtcDate::MIN.days_since_epoch(), -96_465_292);
    assert_eq!(date(-262_143, 1, 2).days_since_epoch(), -96_465_291);
    assert_eq!(UtcDate::MAX.days_since_epoch(), 95_026_236);
    assert_eq!(date(262_142, 12, 30).days_since_epoch(), 95_026_235);
}

#[test]
fn the_day_count_is_checked_when_the_code_is_compiled() {
    const EPOCH: Option<UtcDate> = UtcDate::from_days_since_epoch(0);
    const PAST_THE_END: Option<UtcDate> = UtcDate::from_days_since_epoch(95_026_237);
    const NEW_YEAR: i64 = UtcDate::new(2026, 1, 1).unwrap().days_since_epoch();
    assert_eq!(EPOCH, Some(date(1970, 1, 1)));
    assert_eq!(PAST_THE_END, None);
    assert_eq!(NEW_YEAR, 20_454);
}

#[test]
fn the_conversions_agree_at_the_edges_and_at_every_leap_rule_boundary() {
    // Both ends of the range, and the days around the epoch and year 0.
    let mut walked = walk(MIN_DAYS, MIN_DAYS + 1_500);
    walked += walk(MAX_DAYS - 1_500, MAX_DAYS);
    walked += walk(-800, 800);
    walked += walk(-719_528 - 800, -719_528 + 800);
    // The turn of February in every year that is a multiple of four from
    // -2400 to 2400, which holds every case of the leap rule many times,
    // and the turn of each of those years.
    for year in (-2_400..=2_400).step_by(4) {
        let march = days_from_civil(year, 3, 1);
        walked += walk(march - 3, march + 1);
        let january = days_from_civil(year, 1, 1);
        walked += walk(january - 2, january + 1);
    }
    // The same at the centuries nearest each end of the range.
    for year in [-262_100, -262_000, -261_600, 261_600, 262_000, 262_100] {
        let march = days_from_civil(year, 3, 1);
        walked += walk(march - 3, march + 1);
    }
    assert!(walked > 15_000, "{walked} days walked");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "a walk of 192,068 days is too slow to interpret; the tables of this module cover the same code under Miri"
)]
fn a_strided_sample_of_the_whole_range_round_trips() {
    // A stride prime to the 146,097 days of the calendar's cycle, so the
    // sample lands on every part of it.
    let mut days = MIN_DAYS;
    let mut sampled = 0u32;
    while days <= MAX_DAYS {
        let (year, month, day) = civil_from_days(days);
        assert_eq!(days_from_civil(year, month, day), days);
        assert!((1..=12).contains(&month) && (1..=month_length(year, month)).contains(&day));
        let date = on_day(days);
        assert_eq!(fields(date), (year, month, day));
        assert_eq!(date.days_since_epoch(), days);
        // The next day is the calendar's next day.
        if days < MAX_DAYS {
            assert_eq!(
                civil_from_days(days + 1),
                day_after((year, month, day)),
                "the day after day {days}"
            );
        }
        days += 997;
        sampled += 1;
    }
    assert_eq!(sampled, 192_068);
}

#[test]
#[ignore = "walks all 191,491,529 days of the range, which takes a while; run by hand with --ignored"]
fn every_day_of_the_range_round_trips() {
    assert_eq!(walk(MIN_DAYS, MAX_DAYS), 191_491_529);
}

#[test]
fn a_date_is_written_as_year_month_day() {
    let cases = [
        ((2026, 2, 28), "2026-02-28"),
        ((2026, 11, 18), "2026-11-18"),
        ((1970, 1, 1), "1970-01-01"),
        ((999, 9, 9), "0999-09-09"),
        ((1, 1, 1), "0001-01-01"),
        ((0, 1, 1), "0000-01-01"),
        ((9999, 12, 31), "9999-12-31"),
        ((10_000, 1, 1), "+10000-01-01"),
        ((-1, 12, 31), "-0001-12-31"),
        ((-999, 1, 1), "-0999-01-01"),
        ((-9999, 1, 1), "-9999-01-01"),
        ((-10_000, 1, 1), "-10000-01-01"),
        ((262_142, 12, 31), "+262142-12-31"),
        ((-262_143, 1, 1), "-262143-01-01"),
    ];
    for ((year, month, day), text) in cases {
        let date = date(year, month, day);
        assert_eq!(date.to_string(), text);
        assert_eq!(text.parse::<UtcDate>(), Ok(date), "{text}");
    }
}

#[test]
fn only_the_written_form_reads_as_a_date() {
    let cases = [
        ("", TimeError::Invalid),
        ("2026", TimeError::Invalid),
        ("2026-01", TimeError::Invalid),
        ("2026-1-01", TimeError::Invalid),
        ("2026-01-1", TimeError::Invalid),
        ("226-01-01", TimeError::Invalid),
        ("02026-01-01", TimeError::Invalid),
        ("+2026-01-01", TimeError::Invalid),
        ("-0000-01-01", TimeError::Invalid),
        ("+0000-01-01", TimeError::Invalid),
        ("10000-01-01", TimeError::Invalid),
        ("+010000-01-01", TimeError::Invalid),
        ("2026-+1-01", TimeError::Invalid),
        ("2026-01-+1", TimeError::Invalid),
        (" 2026-01-01", TimeError::Invalid),
        ("2026-01-01 ", TimeError::Invalid),
        ("2026-01-01T00:00:00Z", TimeError::Invalid),
        ("2026/01/01", TimeError::Invalid),
        ("2026-01-01-01", TimeError::Invalid),
        ("20260101", TimeError::Invalid),
        ("year-01-01", TimeError::Invalid),
        ("\u{0662}\u{0660}\u{0662}\u{0666}-01-01", TimeError::Invalid),
        ("99999999999-01-01", TimeError::Invalid),
        ("2026-00-01", TimeError::OutOfRange),
        ("2026-13-01", TimeError::OutOfRange),
        ("2026-01-00", TimeError::OutOfRange),
        ("2026-01-32", TimeError::OutOfRange),
        ("2026-02-29", TimeError::OutOfRange),
        ("2026-02-30", TimeError::OutOfRange),
        ("2026-04-31", TimeError::OutOfRange),
        ("+262143-01-01", TimeError::OutOfRange),
        ("-262144-12-31", TimeError::OutOfRange),
    ];
    for (text, error) in cases {
        assert_eq!(text.parse::<UtcDate>(), Err(error), "{text:?}");
    }
}

#[test]
fn a_written_date_reads_back_across_the_range() {
    let mut days = MIN_DAYS;
    while days <= MAX_DAYS {
        let date = on_day(days);
        assert_eq!(date.to_string().parse::<UtcDate>(), Ok(date));
        days += 104_729;
    }
}
