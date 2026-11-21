//! The time types agree with chrono 0.4, the library earlier releases held
//! their times in.
//!
//! Stored rows and sent texts were written and read by chrono, so the types
//! here give the same text for the same instant, read every text chrono read
//! as the same instant and refuse every text it refused, break an instant
//! down into the same date and time of day, count the same seconds,
//! milliseconds and microseconds, add and subtract to the same results, and
//! print a span as the same text.
//! Each case draws values from a small deterministic generator, across the
//! whole range and near its ends, and compares the two libraries on them.
//!
//! One difference is by design. chrono kept a second of 60 as a leap second:
//! its Unix second was that of second 59 and its fraction was a whole second
//! or more. A `Timestamp` has no leap second and reads such a text as the
//! last nanosecond of second 59, so the Unix second is the same and the
//! fraction is 999,999,999. The reader cases compare with that rule.

use axess_clock::{SignedDuration, Timestamp, UtcDate};
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat, TimeDelta, Timelike, Utc};
use std::time::Duration;

/// How many generated values each case compares.
const VALUES: usize = 200_000;

/// The SplitMix64 generator: the same seed gives the same values on every
/// run and every machine.
struct Generator {
    state: u64,
}

impl Generator {
    fn new(seed: u64) -> Generator {
        Generator { state: seed }
    }

    fn word(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// A value in `low..=high`.
    fn between(&mut self, low: i64, high: i64) -> i64 {
        let width = (i128::from(high) - i128::from(low) + 1) as u128;
        (i128::from(low) + (u128::from(self.word()) % width) as i128) as i64
    }

    /// One of `choices`.
    fn pick<T: Copy>(&mut self, choices: &[T]) -> T {
        choices[self.between(0, choices.len() as i64 - 1) as usize]
    }

    /// True one time in `odds`.
    fn one_in(&mut self, odds: u64) -> bool {
        self.word().is_multiple_of(odds)
    }

    /// A fraction of a second: none, whole milliseconds, whole microseconds
    /// or any count of nanoseconds, each one time in four.
    fn nanos(&mut self) -> u32 {
        match self.word() % 4 {
            0 => 0,
            1 => self.between(0, 999) as u32 * 1_000_000,
            2 => self.between(0, 999_999) as u32 * 1_000,
            _ => self.between(0, 999_999_999) as u32,
        }
    }

    /// A Unix second: anywhere in the range, in the years people live in,
    /// near the epoch, or near either end of the range.
    fn seconds(&mut self) -> i64 {
        let (first, last) = (Timestamp::MIN.unix_seconds(), Timestamp::MAX.unix_seconds());
        match self.word() % 10 {
            0..=3 => self.between(first, last),
            4..=6 => self.between(-2_208_988_800, 4_102_444_800),
            7 => self.between(-172_800, 172_800),
            8 => self.between(first, first + 172_800),
            _ => self.between(last - 172_800, last),
        }
    }

    /// The same instant in both libraries.
    fn instant(&mut self) -> (Timestamp, DateTime<Utc>) {
        let (secs, nanos) = (self.seconds(), self.nanos());
        (
            Timestamp::new(secs, nanos).expect("a reading inside the range"),
            DateTime::from_timestamp(secs, nanos).expect("an instant chrono holds"),
        )
    }

    /// The same span in both libraries, of a size chrono holds: a few
    /// seconds, up to the width of the range, or up to a hundred times it.
    fn span(&mut self) -> (SignedDuration, TimeDelta) {
        let secs = match self.word() % 3 {
            0 => self.between(-100_000, 100_000),
            1 => self.between(-17_000_000_000_000, 17_000_000_000_000),
            _ => self.between(-1_700_000_000_000_000, 1_700_000_000_000_000),
        };
        let nanos = i64::from(self.nanos());
        let nanos = if secs < 0 { -nanos } else { nanos };
        (
            SignedDuration::seconds(secs)
                .checked_add(SignedDuration::nanoseconds(nanos))
                .expect("a span inside the range"),
            TimeDelta::seconds(secs) + TimeDelta::nanoseconds(nanos),
        )
    }
}

fn fields(at: Timestamp) -> (i64, u32) {
    (at.unix_seconds(), at.subsec_nanos())
}

fn their_fields(at: DateTime<Utc>) -> (i64, u32) {
    (at.timestamp(), at.timestamp_subsec_nanos())
}

fn span_fields(span: SignedDuration) -> (i64, i32) {
    (span.whole_seconds(), span.subsec_nanos())
}

fn their_span_fields(span: TimeDelta) -> (i64, i32) {
    (span.num_seconds(), span.subsec_nanos())
}

/// What the reader here gives for what chrono's reader gave: the same
/// instant, and for chrono's leap second the last nanosecond of second 59.
fn read_as(theirs: DateTime<Utc>) -> (i64, u32) {
    match their_fields(theirs) {
        (secs, leap) if leap >= 1_000_000_000 => (secs, 999_999_999),
        instant => instant,
    }
}

/// Holds the two readers to each other on one text: both refuse it, or both
/// read it as the same instant.
fn assert_read_alike(text: &str) {
    let theirs = text.parse::<DateTime<Utc>>().ok().map(read_as);
    let ours = Timestamp::parse_rfc3339(text).ok().map(fields);
    assert_eq!(ours, theirs, "the two readers differ on {text:?}");
}

#[test]
fn the_range_is_the_one_chrono_held() {
    assert_eq!(
        fields(Timestamp::MIN),
        their_fields(DateTime::<Utc>::MIN_UTC)
    );
    assert_eq!(
        fields(Timestamp::MAX),
        their_fields(DateTime::<Utc>::MAX_UTC)
    );
    assert_eq!(
        fields(Timestamp::UNIX_EPOCH),
        their_fields(DateTime::UNIX_EPOCH)
    );
    for secs in [
        Timestamp::MIN.unix_seconds() - 1,
        Timestamp::MAX.unix_seconds() + 1,
        i64::MIN,
        i64::MAX,
    ] {
        assert!(DateTime::<Utc>::from_timestamp(secs, 0).is_none(), "{secs}");
        assert!(Timestamp::new(secs, 0).is_none(), "{secs}");
        assert!(Timestamp::from_unix_seconds(secs).is_none(), "{secs}");
    }
    assert_eq!(
        (
            UtcDate::MIN.year(),
            UtcDate::MIN.month(),
            UtcDate::MIN.day()
        ),
        (NaiveDate::MIN.year(), 1, 1)
    );
    assert_eq!(
        (
            UtcDate::MAX.year(),
            UtcDate::MAX.month(),
            UtcDate::MAX.day()
        ),
        (NaiveDate::MAX.year(), 12, 31)
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the unit tests cover the types under Miri"
)]
fn both_written_forms_are_the_text_chrono_wrote() {
    let mut generator = Generator::new(0xC0DE_0001);
    for _ in 0..VALUES {
        let (ours, theirs) = generator.instant();
        // What chrono's serde wrote: UTC with a `Z` and the fewest of 0, 3,
        // 6 or 9 fraction digits.
        assert_eq!(
            ours.to_rfc3339(),
            theirs.to_rfc3339_opts(SecondsFormat::AutoSi, true)
        );
        assert_eq!(ours.to_string(), format!("{theirs:?}"));
        assert_eq!(format!("{ours:?}"), format!("{theirs:?}"));
        // What chrono's `to_rfc3339` wrote: the same with `+00:00`.
        assert_eq!(ours.to_rfc3339_numeric_offset(), theirs.to_rfc3339());
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the unit tests cover the types under Miri"
)]
fn the_breakdown_is_the_date_and_time_of_day_chrono_gave() {
    let mut generator = Generator::new(0xC0DE_0002);
    for _ in 0..VALUES {
        let (ours, theirs) = generator.instant();
        let (date, hour, minute, second, nanosecond) = ours.to_utc();
        assert_eq!(
            (
                date.year(),
                u32::from(date.month()),
                u32::from(date.day()),
                u32::from(hour),
                u32::from(minute),
                u32::from(second),
                nanosecond
            ),
            (
                theirs.year(),
                theirs.month(),
                theirs.day(),
                theirs.hour(),
                theirs.minute(),
                theirs.second(),
                theirs.nanosecond()
            ),
            "{ours}"
        );
        assert_eq!(ours.utc_date(), date);
        assert_eq!(date.to_string(), format!("{:?}", theirs.date_naive()));
        // And back: the date and the time of day give the second again.
        assert_eq!(
            Timestamp::from_utc(date.year(), date.month(), date.day(), hour, minute, second)
                .map(fields),
            Some((theirs.timestamp(), 0)),
            "{ours}"
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the unit tests cover the types under Miri"
)]
fn a_date_exists_where_chrono_had_one() {
    let mut generator = Generator::new(0xC0DE_0003);
    for _ in 0..VALUES {
        let year = match generator.word() % 4 {
            0 => generator.between(-262_150, 262_150),
            1 => generator.between(i64::from(i32::MIN), i64::from(i32::MAX)),
            _ => generator.between(-2_500, 2_500),
        } as i32;
        let month = generator.between(0, 14) as u8;
        let day = generator.between(0, 33) as u8;
        let ours = UtcDate::new(year, month, day);
        let theirs = NaiveDate::from_ymd_opt(year, u32::from(month), u32::from(day));
        assert_eq!(ours.is_some(), theirs.is_some(), "{year}-{month}-{day}");
        if let (Some(ours), Some(theirs)) = (ours, theirs) {
            assert_eq!(ours.to_string(), format!("{theirs:?}"));
        }
    }
}

/// Days from the first day of year 1, which chrono counts from, to
/// 1970-01-01.
const EPOCH_DAY_OF_COMMON_ERA: i64 = 719_163;

/// The date chrono had for a count of days since 1970-01-01, if it had one.
fn their_date_on(days: i64) -> Option<NaiveDate> {
    let from_common_era = days.checked_add(EPOCH_DAY_OF_COMMON_ERA)?;
    NaiveDate::from_num_days_from_ce_opt(i32::try_from(from_common_era).ok()?)
}

#[test]
fn the_day_count_has_the_ends_and_the_epoch_chrono_had() {
    let first = UtcDate::MIN.days_since_epoch();
    let last = UtcDate::MAX.days_since_epoch();
    for days in [
        first - 1,
        first,
        first + 1,
        -1,
        0,
        1,
        last - 1,
        last,
        last + 1,
        i64::MIN,
        i64::MAX,
    ] {
        let ours = UtcDate::from_days_since_epoch(days);
        let theirs = their_date_on(days);
        assert_eq!(
            ours.map(|date| date.to_string()),
            theirs.map(|date| format!("{date:?}")),
            "day {days}"
        );
    }
    assert_eq!(their_date_on(first), Some(NaiveDate::MIN));
    assert_eq!(their_date_on(last), Some(NaiveDate::MAX));
    assert_eq!(their_date_on(0), NaiveDate::from_ymd_opt(1970, 1, 1));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the unit tests cover the types under Miri"
)]
fn a_day_count_is_the_date_chrono_gave_and_back() {
    let mut generator = Generator::new(0xC0DE_0009);
    let first = UtcDate::MIN.days_since_epoch();
    let last = UtcDate::MAX.days_since_epoch();
    for _ in 0..VALUES {
        let days = match generator.word() % 5 {
            0 => generator.between(first - 1_000, first + 1_000),
            1 => generator.between(last - 1_000, last + 1_000),
            2 => generator.between(-800_000, 800_000),
            3 => generator.between(i64::MIN, i64::MAX),
            _ => generator.between(first, last),
        };
        let ours = UtcDate::from_days_since_epoch(days);
        let theirs = their_date_on(days);
        assert_eq!(ours.is_some(), theirs.is_some(), "day {days}");
        if let (Some(ours), Some(theirs)) = (ours, theirs) {
            assert_eq!(ours.to_string(), format!("{theirs:?}"), "day {days}");
            assert_eq!(ours.days_since_epoch(), days);
            assert_eq!(
                ours.days_since_epoch(),
                i64::from(theirs.num_days_from_ce()) - EPOCH_DAY_OF_COMMON_ERA
            );
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the unit tests cover the types under Miri"
)]
fn the_counts_since_the_epoch_are_the_numbers_chrono_gave() {
    let mut generator = Generator::new(0xC0DE_0004);
    for _ in 0..VALUES {
        let (ours, theirs) = generator.instant();
        assert_eq!(ours.unix_seconds(), theirs.timestamp(), "{ours}");
        assert_eq!(ours.unix_millis(), theirs.timestamp_millis(), "{ours}");
        assert_eq!(ours.unix_micros(), theirs.timestamp_micros(), "{ours}");
        assert_eq!(
            ours.subsec_nanos(),
            theirs.timestamp_subsec_nanos(),
            "{ours}"
        );
        // chrono gave the nanoseconds only where they fit an `i64`.
        assert_eq!(
            i64::try_from(ours.unix_nanos()).ok(),
            theirs.timestamp_nanos_opt(),
            "{ours}"
        );

        // A count reads as the instant chrono read it as, or as none.
        let millis = match generator.word() % 3 {
            0 => generator.between(i64::MIN, i64::MAX),
            _ => ours.unix_millis() + generator.between(-2, 2) * 86_400_000,
        };
        assert_eq!(
            Timestamp::from_unix_millis(millis).map(fields),
            DateTime::from_timestamp_millis(millis).map(their_fields),
            "{millis} milliseconds"
        );
        let micros = match generator.word() % 3 {
            0 => generator.between(i64::MIN, i64::MAX),
            _ => ours.unix_micros(),
        };
        assert_eq!(
            Timestamp::from_unix_micros(micros).map(fields),
            DateTime::from_timestamp_micros(micros).map(their_fields),
            "{micros} microseconds"
        );
        let nanos = generator.between(i64::MIN, i64::MAX);
        assert_eq!(
            Timestamp::from_unix_nanos(i128::from(nanos)).map(fields),
            Some(their_fields(DateTime::from_timestamp_nanos(nanos))),
            "{nanos} nanoseconds"
        );
        let secs = match generator.word() % 3 {
            0 => generator.between(i64::MIN, i64::MAX),
            _ => ours.unix_seconds() + generator.between(-2, 2) * 86_400,
        };
        let fraction = match generator.word() % 8 {
            0 => generator.between(1_000_000_000, i64::from(u32::MAX)) as u32,
            _ => generator.nanos(),
        };
        // chrono took a fraction of a whole second or more as a leap second
        // in second 59; a reading has none.
        let theirs = DateTime::from_timestamp(secs, fraction)
            .filter(|read| read.timestamp_subsec_nanos() < 1_000_000_000)
            .map(their_fields);
        assert_eq!(
            Timestamp::new(secs, fraction).map(fields),
            theirs,
            "{secs} seconds and {fraction} nanoseconds"
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the unit tests cover the types under Miri"
)]
fn readings_add_subtract_and_differ_as_chrono_instants_did() {
    let mut generator = Generator::new(0xC0DE_0005);
    for _ in 0..VALUES {
        let (ours, theirs) = generator.instant();
        let (other, their_other) = generator.instant();
        assert_eq!(
            span_fields(ours.since(other)),
            their_span_fields(theirs.signed_duration_since(their_other)),
            "{ours} since {other}"
        );
        assert_eq!(ours.cmp(&other), theirs.cmp(&their_other));

        // A generated span, or the span to the other instant, which lands
        // inside the range.
        let (span, delta) = if generator.one_in(3) {
            (ours.since(other), theirs.signed_duration_since(their_other))
        } else {
            generator.span()
        };
        assert_eq!(
            ours.checked_add(span).map(fields),
            theirs.checked_add_signed(delta).map(their_fields),
            "{ours} + {span:?}"
        );
        assert_eq!(
            ours.checked_sub(span).map(fields),
            theirs.checked_sub_signed(delta).map(their_fields),
            "{ours} - {span:?}"
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the unit tests cover the types under Miri"
)]
fn spans_are_built_read_and_combined_as_chrono_spans_were() {
    let mut generator = Generator::new(0xC0DE_0006);
    for _ in 0..VALUES {
        // The constructors, over the arguments chrono's took.
        let small = generator.between(-1_000_000, 1_000_000);
        let count = small as i32;
        let wide = generator.between(-9_000_000_000_000_000, 9_000_000_000_000_000);
        for (ours, theirs) in [
            (SignedDuration::seconds(wide), TimeDelta::seconds(wide)),
            (SignedDuration::minutes(count), TimeDelta::minutes(small)),
            (SignedDuration::hours(count), TimeDelta::hours(small)),
            (SignedDuration::days(count), TimeDelta::days(small)),
            (
                SignedDuration::milliseconds(wide),
                TimeDelta::milliseconds(wide),
            ),
            (
                SignedDuration::microseconds(wide),
                TimeDelta::microseconds(wide),
            ),
            (
                SignedDuration::nanoseconds(wide),
                TimeDelta::nanoseconds(wide),
            ),
        ] {
            assert_eq!(span_fields(ours), their_span_fields(theirs));
        }

        let (a, their_a) = generator.span();
        let (b, their_b) = generator.span();
        assert_eq!(a.whole_seconds(), their_a.num_seconds(), "{a:?}");
        assert_eq!(
            a.whole_milliseconds(),
            i128::from(their_a.num_milliseconds()),
            "{a:?}"
        );
        assert_eq!(a.is_negative(), their_a < TimeDelta::zero(), "{a:?}");
        assert_eq!(a.is_zero(), their_a.is_zero(), "{a:?}");
        assert_eq!(a.cmp(&b), their_a.cmp(&their_b), "{a:?} against {b:?}");
        assert_eq!(
            a.unsigned_abs(),
            their_a.abs().to_std().expect("not negative")
        );
        assert_eq!(Duration::try_from(a).ok(), their_a.to_std().ok(), "{a:?}");
        if let Ok(unsigned) = Duration::try_from(a) {
            assert_eq!(
                SignedDuration::try_from(unsigned).map(span_fields).ok(),
                TimeDelta::from_std(unsigned).map(their_span_fields).ok()
            );
        }

        // Sums, differences and products that stay inside the spans chrono
        // held are the same span; these are far inside it.
        assert_eq!(
            a.checked_add(b).map(span_fields),
            their_a.checked_add(&their_b).map(their_span_fields),
            "{a:?} + {b:?}"
        );
        assert_eq!(
            a.checked_sub(b).map(span_fields),
            their_a.checked_sub(&their_b).map(their_span_fields),
            "{a:?} - {b:?}"
        );
        let factor = generator.between(-3, 3) as i32;
        assert_eq!(
            a.checked_mul(factor).map(span_fields),
            their_a.checked_mul(factor).map(their_span_fields),
            "{a:?} times {factor}"
        );
    }
}

/// The same span in both libraries from a count of seconds and a fraction
/// that runs the same way.
fn span_of(secs: i64, nanos: i64) -> (SignedDuration, TimeDelta) {
    (
        SignedDuration::seconds(secs)
            .checked_add(SignedDuration::nanoseconds(nanos))
            .expect("a span inside the range"),
        TimeDelta::seconds(secs) + TimeDelta::nanoseconds(nanos),
    )
}

#[test]
fn a_span_prints_as_chrono_printed_it() {
    // Whole seconds, fractions of every length, both signs, no time at all,
    // and the longest spans chrono held either way: `i64::MAX` milliseconds.
    let most = i64::MAX / 1_000;
    let cases = [
        (0, 0, "P0D"),
        (1, 0, "PT1S"),
        (-1, 0, "-PT1S"),
        (7_200, 0, "PT7200S"),
        (-7_200, 0, "-PT7200S"),
        (300, 0, "PT300S"),
        (86_400, 0, "PT86400S"),
        (1, 500_000_000, "PT1.5S"),
        (-1, -500_000_000, "-PT1.5S"),
        (0, 250_000_000, "PT0.25S"),
        (0, -250_000_000, "-PT0.25S"),
        (0, 1, "PT0.000000001S"),
        (0, -1, "-PT0.000000001S"),
        (0, 999_999_999, "PT0.999999999S"),
        (3, 1_000, "PT3.000001S"),
        (3, 1_000_000, "PT3.001S"),
        (3, 123_456_780, "PT3.12345678S"),
        (most, 807_000_000, "PT9223372036854775.807S"),
        (-most, -807_000_000, "-PT9223372036854775.807S"),
        (most, 0, "PT9223372036854775S"),
        (-most, 0, "-PT9223372036854775S"),
    ];
    for (secs, nanos, text) in cases {
        let (ours, theirs) = span_of(secs, nanos);
        assert_eq!(theirs.to_string(), text, "chrono, for {secs} s {nanos} ns");
        assert_eq!(ours.to_string(), text, "{ours:?}");
    }
    assert_eq!(span_of(most, 807_000_000).1, TimeDelta::MAX);
    assert_eq!(span_of(-most, -807_000_000).1, TimeDelta::MIN);
    assert_eq!(
        SignedDuration::milliseconds(i64::MAX).to_string(),
        TimeDelta::MAX.to_string()
    );
    assert_eq!(
        SignedDuration::milliseconds(-i64::MAX).to_string(),
        TimeDelta::MIN.to_string()
    );
    // Neither applies a width or a precision.
    let (ours, theirs) = span_of(5, 250_000_000);
    assert_eq!(format!("{ours:>12}"), format!("{theirs:>12}"));
    assert_eq!(format!("{ours:.1}"), format!("{theirs:.1}"));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the unit tests cover the types under Miri"
)]
fn generated_spans_print_as_chrono_printed_them() {
    let mut generator = Generator::new(0xC0DE_000A);
    for _ in 0..VALUES {
        let (ours, theirs) = generator.span();
        assert_eq!(ours.to_string(), theirs.to_string(), "{ours:?}");
        // Near no time at all, where the sign sits on the fraction alone.
        let nanos = generator.between(-1_999_999_999, 1_999_999_999);
        let (ours, theirs) = (
            SignedDuration::nanoseconds(nanos),
            TimeDelta::nanoseconds(nanos),
        );
        assert_eq!(ours.to_string(), theirs.to_string(), "{nanos} ns");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the unit tests cover the types under Miri"
)]
fn a_span_divides_as_a_chrono_span_did_where_chrono_was_exact() {
    // chrono divided the seconds and the fraction apart and added the two
    // quotients, which is the exact quotient rounded towards zero when the
    // divisor goes into a second a whole number of times and the span does
    // not run backwards with a fraction: the cases compared here. Elsewhere
    // chrono could be a nanosecond out (two seconds and two nanoseconds in
    // three parts), and `checked_div` is exact.
    let divisors = [1, 2, 4, 5, 8, 10, 16, 25, 100, 125, 1_000, 1_000_000];
    let mut generator = Generator::new(0xC0DE_000B);
    for _ in 0..VALUES {
        let divisor: i32 = generator.pick(&divisors);
        let secs = match generator.word() % 3 {
            0 => generator.between(0, 100_000),
            1 => generator.between(0, 17_000_000_000_000),
            _ => generator.between(0, 1_700_000_000_000_000),
        };
        let (ours, theirs) = span_of(secs, i64::from(generator.nanos()));
        assert_eq!(
            ours.checked_div(divisor).map(span_fields),
            theirs.checked_div(divisor).map(their_span_fields),
            "{ours:?} in {divisor} parts"
        );
        // Whole seconds, either way round and either way divided.
        let whole = generator.between(-1_700_000_000_000_000, 1_700_000_000_000_000);
        let (ours, theirs) = span_of(whole, 0);
        for divisor in [divisor, -divisor] {
            assert_eq!(
                ours.checked_div(divisor).map(span_fields),
                theirs.checked_div(divisor).map(their_span_fields),
                "{ours:?} in {divisor} parts"
            );
        }
    }
    let (ours, theirs) = span_of(3_600, 0);
    assert_eq!(ours.checked_div(0), None);
    assert_eq!(theirs.checked_div(0), None);
    assert_eq!(
        ours.checked_div(100).map(span_fields),
        Some(their_span_fields(theirs / 100))
    );
}

/// Texts in every form the reader takes, and texts it refuses for each of
/// its reasons: the starting points of the mutated texts.
const SEEDS: &[&str] = &[
    "2026-01-01T00:00:00Z",
    "2026-01-01T00:00:00.500Z",
    "2026-01-01T00:00:00.123456789Z",
    "2026-01-01T00:00:00+00:00",
    "2026-01-01T01:00:00+01:00",
    "2025-12-31T19:30:00-04:30",
    "2026-01-01t00:00:00z",
    "2026-01-01 00:00:00Z",
    "2026-01-01T00:00:00.000000000000Z",
    "2026-01-01T00:00:00+0000",
    "2026-01-01T00:00:00 UTC",
    "2026-01-01T00:00:00 +00:00",
    "2026-01-01T00:00:00.1234567899Z",
    "+262142-12-31T23:59:59.999999999Z",
    "-262143-01-01T00:00:00Z",
    "+10000-01-01T00:00:00Z",
    "-0001-12-31T23:59:59Z",
    "0001-01-01T00:00:00Z",
    "9999-12-31T23:59:59.999999999Z",
    "1969-12-31T23:59:59.999999999Z",
    "2026-01-01T00:00:60Z",
    "2026-01-01T23:59:60.5Z",
    "2016-12-31T23:59:60+01:00",
    "+262142-12-31T23:59:60Z",
    "+262142-12-31T23:59:60.999999999Z",
    "-262143-01-01T00:00:60+00:01",
    "2026-01-01T00:00:00-00:00",
    "26-01-01T00:00:00Z",
    "0-1-1T0:0:0Z",
    "2026-01-01T00:00:00,5Z",
    "2026-01-01T00:00:00\u{2212}04:30",
    "2026 - 01 - 01T00 : 00 : 00 Z",
    "  2026-01-01T00:00:00Z  ",
    "\u{a0}2026-01-01T00:00:00Z\u{2003}",
    "2026-01-01T05:45:00+05::45",
    "2026-01-01T05:45:00+05 45",
    "2026-01-01T00:00:00+23:59",
    "2026-01-01T00:00:00-23:59",
    "2026-01-01T00:00:00+24:00",
    "2026-01-01T00:00:00+99:59",
    "-262143-01-01T00:00:00+00:01",
    "-262143-01-01T00:01:00+00:01",
    "+262142-12-31T23:59:59.999999999-00:01",
    "+262142-12-31T23:58:59.999999999-00:01",
    "+262143-01-01T00:30:00+01:00",
    "-262144-12-31T23:30:00-01:00",
    "+2147483648-01-01T00:00:00Z",
    "+99999999999999999999999999999999-01-01T00:00:00Z",
    "+000000000000000000000000000000012345-01-01T00:00:00Z",
    "-0000-01-01T00:00:00Z",
    "2026-02-30T00:00:00Z",
    "2026-13-01T00:00:00Z",
    "2026-01-01T24:00:00Z",
    "2026-01-01T00:00:00Zjunk",
    "1767225600",
    "",
    "2026-01-01",
    "2026-01-01T00:00:00",
    "2026-01-01T00:00:00UTC",
    "2026-01-01T00:00:00utc",
    "2026-01-01T00:00:00.Z",
    "2026-01-01T00:00:00 .5Z",
    "10000-01-01T00:00:00Z",
    "2026-01-01\t00:00:00Z",
    "2026-01-01T 00:00:00Z",
    "2026-01-01  00:00:00Z",
    "2026-01-01T00:00:00+1:00",
    "2026-01-01T00:00:00+ 00:00",
];

/// The characters a mutated text gains: those the format uses, weighted
/// towards digits, and some it has no place for.
const ALPHABET: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '5', '9', '6', ' ', ' ', '+', '-', '-',
    ':', ':', '.', ',', 'T', 't', 'Z', 'z', 'U', 'u', 'C', 'c', '\t', '\n', '\u{2212}', '\u{a0}',
    '\u{e9}', '\u{ff16}', 'x', '/',
];

/// A text one to four edits away from `text`: a character removed, added,
/// replaced, doubled or swapped with its neighbour, or the text cut short.
fn mutated(generator: &mut Generator, text: &str) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    for _ in 0..=generator.between(0, 3) {
        let added = generator.pick(ALPHABET);
        let place = generator.between(0, chars.len() as i64) as usize;
        match generator.word() % 6 {
            0 if place < chars.len() => {
                chars.remove(place);
            }
            1 => chars.insert(place, added),
            2 if place < chars.len() => chars[place] = added,
            3 if place < chars.len() => chars.insert(place, chars[place]),
            4 if place + 1 < chars.len() => chars.swap(place, place + 1),
            5 if generator.one_in(4) => chars.truncate(place),
            _ => {}
        }
    }
    chars.into_iter().collect()
}

/// A number of two digits, sometimes of one, mostly within `low..=high`.
fn two_digits(generator: &mut Generator, low: i64, high: i64) -> String {
    let value = if generator.one_in(12) {
        generator.between(0, 99)
    } else {
        generator.between(low, high)
    };
    if generator.one_in(6) {
        format!("{value}")
    } else {
        format!("{value:02}")
    }
}

/// White space, one time in ten.
fn gap(generator: &mut Generator) -> &'static str {
    if generator.one_in(10) { " " } else { "" }
}

/// A text built from generated fields in a generated spelling: with and
/// without padding, signs, white space, a fraction of any length, and every
/// form of offset. About half of them name an instant.
fn spelled(generator: &mut Generator) -> String {
    let year = match generator.word() % 6 {
        0 => generator.between(-262_150, 262_150),
        1 => generator.between(-3, 12),
        2 => generator.between(9_990, 10_010),
        _ => generator.between(1_900, 2_100),
    };
    let mut text = String::from(gap(generator));
    text.push_str(&match generator.word() % 5 {
        0 => format!("{year}"),
        1 => format!("{year:+}"),
        2 => format!("{year:+05}"),
        3 => format!("{year:06}"),
        _ => format!("{year:04}"),
    });
    text.push_str(gap(generator));
    text.push('-');
    text.push_str(&two_digits(generator, 1, 12));
    text.push_str(gap(generator));
    text.push('-');
    text.push_str(&two_digits(generator, 1, 31));
    text.push(generator.pick(&['T', 't', ' ', 'T']));
    text.push_str(&two_digits(generator, 0, 23));
    text.push_str(gap(generator));
    text.push(':');
    text.push_str(&two_digits(generator, 0, 59));
    text.push_str(gap(generator));
    text.push(':');
    text.push_str(&two_digits(generator, 0, 60));
    if generator.one_in(2) {
        text.push('.');
        for _ in 0..generator.between(0, 12) {
            text.push(generator.pick(&['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']));
        }
    }
    text.push_str(gap(generator));
    match generator.word() % 8 {
        0 => text.push('Z'),
        1 => text.push('z'),
        2 => text.push_str("UTC"),
        3 => text.push_str(" utc"),
        _ => {
            text.push(generator.pick(&['+', '-', '\u{2212}', '+']));
            let hours = if generator.one_in(10) {
                generator.between(0, 99)
            } else {
                generator.between(0, 23)
            };
            text.push_str(&format!("{hours:02}"));
            text.push_str(generator.pick(&["", ":", " ", "::"]));
            let minutes = if generator.one_in(10) {
                generator.between(0, 99)
            } else {
                generator.between(0, 59)
            };
            text.push_str(&format!("{minutes:02}"));
        }
    }
    text.push_str(gap(generator));
    text
}

#[test]
fn the_reader_reads_and_refuses_the_seed_texts_as_chrono_did() {
    let mut read = 0;
    for seed in SEEDS {
        assert_read_alike(seed);
        if Timestamp::parse_rfc3339(seed).is_ok() {
            read += 1;
        }
    }
    // The seeds hold both kinds, so the comparison is of readings and of
    // refusals.
    assert!(read >= 30, "{read} seeds read");
    assert!(SEEDS.len() - read >= 20, "{read} seeds read");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated texts are too slow to interpret; the unit tests cover the reader under Miri"
)]
fn the_reader_reads_and_refuses_mutated_texts_as_chrono_did() {
    let mut generator = Generator::new(0xC0DE_0007);
    for _ in 0..VALUES / SEEDS.len() * 4 {
        for seed in SEEDS {
            assert_read_alike(&mutated(&mut generator, seed));
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated texts are too slow to interpret; the unit tests cover the reader under Miri"
)]
fn the_reader_reads_and_refuses_spelled_texts_as_chrono_did() {
    let mut generator = Generator::new(0xC0DE_0008);
    let (mut read, mut leap_seconds) = (0, 0);
    for _ in 0..VALUES * 2 {
        let text = spelled(&mut generator);
        assert_read_alike(&text);
        assert_read_alike(&mutated(&mut generator, &text));
        if let Ok(theirs) = text.parse::<DateTime<Utc>>() {
            read += 1;
            if theirs.timestamp_subsec_nanos() >= 1_000_000_000 {
                leap_seconds += 1;
            }
        }
    }
    // The spelled texts hold readings, refusals and seconds of 60 in
    // number, so each rule of the reader is compared.
    assert!(read > VALUES / 2, "{read} spelled texts read");
    assert!(read < VALUES * 2 - VALUES / 2, "{read} spelled texts read");
    assert!(
        leap_seconds > VALUES / 200,
        "{leap_seconds} seconds of 60 read"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated texts are too slow to interpret; the unit tests cover the reader under Miri"
)]
fn the_reader_reads_the_texts_chrono_wrote() {
    let mut generator = Generator::new(0xC0DE_0009);
    for _ in 0..VALUES {
        let (ours, theirs) = generator.instant();
        // Either written form, as chrono wrote it.
        let text = theirs.to_rfc3339_opts(SecondsFormat::AutoSi, generator.one_in(2));
        assert_eq!(Timestamp::parse_rfc3339(&text), Ok(ours), "{text}");
        assert_read_alike(&text);
        assert_read_alike(&mutated(&mut generator, &text));
        // What chrono's `Display` wrote, which its reader took back.
        let shown = theirs.to_string();
        assert_eq!(Timestamp::parse_rfc3339(&shown), Ok(ours), "{shown}");
    }
}
