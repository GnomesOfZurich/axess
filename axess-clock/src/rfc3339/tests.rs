use crate::duration::SignedDuration;
use crate::error::TimeError;
use crate::sample::Generator;
use crate::timestamp::Timestamp;

/// 2026-01-01T00:00:00Z as Unix seconds.
const R: i64 = 1_767_225_600;

fn at(secs: i64, nanos: u32) -> Timestamp {
    Timestamp::new(secs, nanos).expect("a reading inside the range")
}

fn read(text: &str) -> Result<(i64, u32), TimeError> {
    Timestamp::parse_rfc3339(text).map(|at| (at.unix_seconds(), at.subsec_nanos()))
}

/// The texts stored rows hold, each with the reading it names. Every one is
/// the written form of its reading.
const WRITTEN: [(&str, i64, u32); 31] = [
    ("2026-01-01T00:00:00Z", R, 0),
    ("2026-01-01T00:00:00.500Z", R, 500_000_000),
    ("2026-01-01T00:00:00.120Z", R, 120_000_000),
    ("2026-01-01T00:00:00.001Z", R, 1_000_000),
    ("2026-01-01T00:00:00.123456Z", R, 123_456_000),
    ("2026-01-01T00:00:00.000001Z", R, 1_000),
    ("2026-01-01T00:00:00.123456789Z", R, 123_456_789),
    ("2026-01-01T00:00:00.100000001Z", R, 100_000_001),
    ("2026-01-01T00:00:00.000000001Z", R, 1),
    ("1970-01-01T00:00:00Z", 0, 0),
    ("1969-12-31T23:59:59.999999999Z", -1, 999_999_999),
    ("1969-12-31T23:59:59.999999500Z", -1, 999_999_500),
    ("0001-01-01T00:00:00Z", -62_135_596_800, 0),
    ("0000-01-01T00:00:00Z", -62_167_219_200, 0),
    (
        "9999-12-31T23:59:59.999999999Z",
        253_402_300_799,
        999_999_999,
    ),
    (
        "+262142-12-31T23:59:59.999999999Z",
        8_210_266_876_799,
        999_999_999,
    ),
    ("-262143-01-01T00:00:00Z", -8_334_601_228_800, 0),
    ("+10000-01-01T00:00:00Z", 253_402_300_800, 0),
    ("-0001-12-31T23:59:59Z", -62_167_219_201, 0),
    ("2026-01-01T00:15:00.250Z", R + 900, 250_000_000),
    ("2026-01-02T03:04:05.000006Z", R + 97_445, 6_000),
    ("2026-01-02T00:00:00.000000007Z", R + 86_400, 7),
    ("2026-01-01T00:00:10.123Z", R + 10, 123_000_000),
    ("2026-01-01T00:00:05Z", R + 5, 0),
    ("2026-01-01T00:00:10.123456Z", R + 10, 123_456_000),
    ("2026-01-01T00:00:02.123456789Z", R + 2, 123_456_789),
    ("2026-01-31T23:59:59.999Z", R + 2_678_399, 999_000_000),
    ("2026-01-01T00:00:01.250Z", R + 1, 250_000_000),
    ("2025-12-31T23:59:59.999999999Z", R - 1, 999_999_999),
    ("2026-01-01T01:00:00.000000001Z", R + 3_600, 1),
    ("2026-07-04T12:34:56.789Z", 1_783_168_496, 789_000_000),
];

#[test]
fn a_reading_is_written_in_utc_with_the_fewest_fraction_digits_that_hold_it() {
    for (text, secs, nanos) in WRITTEN {
        let reading = at(secs, nanos);
        assert_eq!(reading.to_rfc3339(), text);
        assert_eq!(reading.to_string(), text);
        assert_eq!(format!("{reading}"), text);
        assert_eq!(format!("{reading:?}"), text);
    }
}

#[test]
fn the_written_text_reads_back_as_the_reading() {
    for (text, secs, nanos) in WRITTEN {
        assert_eq!(read(text), Ok((secs, nanos)), "{text}");
        assert_eq!(text.parse::<Timestamp>(), Ok(at(secs, nanos)), "{text}");
        assert_eq!(Timestamp::parse_rfc3339(text), Ok(at(secs, nanos)));
    }
}

#[test]
fn the_numeric_offset_form_differs_in_the_offset_alone() {
    let cases = [
        (R, 0, "2026-01-01T00:00:00+00:00"),
        (R + 300, 0, "2026-01-01T00:05:00+00:00"),
        (R + 300, 250_000_000, "2026-01-01T00:05:00.250+00:00"),
        (R + 300, 1, "2026-01-01T00:05:00.000000001+00:00"),
        (R, 123_456_000, "2026-01-01T00:00:00.123456+00:00"),
        (0, 0, "1970-01-01T00:00:00+00:00"),
        (-1, 999_999_999, "1969-12-31T23:59:59.999999999+00:00"),
        (
            8_210_266_876_799,
            999_999_999,
            "+262142-12-31T23:59:59.999999999+00:00",
        ),
        (-8_334_601_228_800, 0, "-262143-01-01T00:00:00+00:00"),
        (-62_167_219_201, 0, "-0001-12-31T23:59:59+00:00"),
    ];
    for (secs, nanos, text) in cases {
        let reading = at(secs, nanos);
        assert_eq!(reading.to_rfc3339_numeric_offset(), text);
        assert_eq!(read(text), Ok((secs, nanos)), "{text}");
    }
    for (text, secs, nanos) in WRITTEN {
        let with_offset = at(secs, nanos).to_rfc3339_numeric_offset();
        assert_eq!(
            with_offset,
            format!("{}+00:00", text.strip_suffix('Z').expect("the Z form"))
        );
        assert_eq!(read(&with_offset), Ok((secs, nanos)));
    }
}

#[test]
fn the_other_forms_earlier_releases_read_still_read_as_the_same_reading() {
    for text in [
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T01:00:00+01:00",
        "2025-12-31T19:30:00-04:30",
        "2026-01-01t00:00:00z",
        "2026-01-01 00:00:00Z",
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:00:00.000000000000Z",
        "2026-01-01T00:00:00+0000",
        "2026-01-01T00:00:00 UTC",
        "2026-01-01T00:00:00 +00:00",
        // Further spellings the same reader took.
        "2026-01-01T00:00:00-00:00",
        "2026-01-01T00:00:00.0Z",
        "2026-01-01T00:00:00UTC",
        "2026-01-01T00:00:00utc",
        "2026-01-01T00:00:00 Utc",
        "2026-01-01T00:00:00   Z",
        "2026-01-01T23:59:00+23:59",
        "2025-12-31T00:01:00-23:59",
        "2026-01-01T05:45:00+0545",
        "2026-01-01T05:45:00+05 45",
        "2026-01-01T05:45:00+05::45",
        "2026-01-01T05:45:00+05: :45",
        "2025-12-31T19:30:00\u{2212}04:30",
        "2025-12-31T19:30:00 -0430",
        "+2026-01-01T00:00:00Z",
        "+002026-01-01T00:00:00Z",
        "2026-1-1T0:0:0Z",
        "2026-01-01  00:00:00Z",
        "2026-01-01T 00:00:00Z",
        "2026 - 01 - 01T00 : 00 : 00 Z",
        "  2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z  ",
        "\t2026-01-01T00:00:00Z\n",
        "\u{a0}2026-01-01T00:00:00Z\u{2003}",
    ] {
        assert_eq!(read(text), Ok((R, 0)), "{text:?}");
    }
}

#[test]
fn a_fraction_of_any_length_reads_and_digits_past_the_ninth_are_dropped() {
    let cases = [
        ("2026-01-01T00:00:00.1Z", 100_000_000),
        ("2026-01-01T00:00:00.5Z", 500_000_000),
        ("2026-01-01T00:00:00.9Z", 900_000_000),
        ("2026-01-01T00:00:00.12Z", 120_000_000),
        ("2026-01-01T00:00:00.123Z", 123_000_000),
        ("2026-01-01T00:00:00.1234Z", 123_400_000),
        ("2026-01-01T00:00:00.12345Z", 123_450_000),
        ("2026-01-01T00:00:00.123456Z", 123_456_000),
        ("2026-01-01T00:00:00.1234567Z", 123_456_700),
        ("2026-01-01T00:00:00.12345678Z", 123_456_780),
        ("2026-01-01T00:00:00.123456789Z", 123_456_789),
        ("2026-01-01T00:00:00.000000001Z", 1),
        ("2026-01-01T00:00:00.000000009Z", 9),
        ("2026-01-01T00:00:00.0000000019Z", 1),
        ("2026-01-01T00:00:00.1234567899Z", 123_456_789),
        ("2026-01-01T00:00:00.9999999999Z", 999_999_999),
        (
            "2026-01-01T00:00:00.99999999999999999999999999Z",
            999_999_999,
        ),
        ("2026-01-01T00:00:00.0000000009Z", 0),
        ("2026-01-01T00:00:00.123456789+00:00", 123_456_789),
        ("2026-01-01T00:00:00.5 UTC", 500_000_000),
    ];
    for (text, nanos) in cases {
        assert_eq!(read(text), Ok((R, nanos)), "{text}");
    }
    // The dropped digits do not round the ninth up.
    assert_eq!(
        Timestamp::parse_rfc3339("2026-01-01T00:00:00.1234567899Z").map(|at| at.to_rfc3339()),
        Ok("2026-01-01T00:00:00.123456789Z".to_owned())
    );
    for (stored, written) in [
        ("2026-01-01T00:00:01.5Z", "2026-01-01T00:00:01.500Z"),
        ("2026-01-01T00:00:09.9Z", "2026-01-01T00:00:09.900Z"),
        ("2026-01-01T00:02:00.5Z", "2026-01-01T00:02:00.500Z"),
    ] {
        assert_eq!(
            Timestamp::parse_rfc3339(stored).map(|at| at.to_rfc3339()),
            Ok(written.to_owned())
        );
    }
}

#[test]
fn an_offset_is_converted_to_utc_and_dropped() {
    let cases = [
        ("2026-01-01T01:00:00+01:00", R),
        ("2026-01-01T00:00:00+01:00", R - 3_600),
        ("2026-01-01T00:00:00-01:00", R + 3_600),
        ("2026-01-01T00:00:00+00:01", R - 60),
        ("2026-01-01T00:00:00-00:01", R + 60),
        ("2026-01-01T00:00:00+23:59", R - 86_340),
        ("2026-01-01T00:00:00-23:59", R + 86_340),
        ("2026-01-01T00:00:00+05:45", R - 20_700),
        ("2026-01-01T00:00:00-04:30", R + 16_200),
        ("1970-01-01T00:00:00+00:01", -60),
        ("0000-01-01T00:00:00+01:00", -62_167_219_200 - 3_600),
    ];
    for (text, secs) in cases {
        assert_eq!(read(text), Ok((secs, 0)), "{text}");
    }
}

#[test]
fn a_text_that_is_no_reading_is_refused() {
    let cases = [
        ("", TimeError::TooShort),
        ("2026-01-01", TimeError::TooShort),
        ("2026-01-01T00:00:00", TimeError::TooShort),
        ("2026-13-01T00:00:00Z", TimeError::OutOfRange),
        ("2026-02-30T00:00:00Z", TimeError::OutOfRange),
        ("2026-01-01T24:00:00Z", TimeError::OutOfRange),
        ("2026-01-01T00:00:00+24:00", TimeError::OutOfRange),
        ("2026-01-01T00:00:00Zjunk", TimeError::TrailingText),
        ("1767225600", TimeError::Invalid),
    ];
    for (text, error) in cases {
        assert_eq!(read(text), Err(error), "{text:?}");
        assert_eq!(text.parse::<Timestamp>(), Err(error), "{text:?}");
    }
}

#[test]
fn a_second_of_sixty_reads_as_the_last_nanosecond_of_second_fifty_nine() {
    let cases = [
        ("2026-01-01T00:00:60Z", R + 59),
        ("2026-01-01T00:00:60.5Z", R + 59),
        ("2026-01-01T00:00:60.000000001Z", R + 59),
        ("2026-01-01T00:00:60.999999999Z", R + 59),
        ("2026-01-01T12:34:60Z", R + 45_299),
        ("2026-01-01T23:59:60Z", R + 86_399),
        ("2026-01-01T01:00:60+01:00", R + 59),
        ("2016-12-31T23:59:60Z", 1_483_228_799),
        ("+262142-12-31T23:59:60Z", 8_210_266_876_799),
    ];
    for (text, secs) in cases {
        assert_eq!(read(text), Ok((secs, 999_999_999)), "{text}");
    }
    assert_eq!(
        Timestamp::parse_rfc3339("+262142-12-31T23:59:60Z"),
        Ok(Timestamp::MAX)
    );
    // Only 60: a second past it is outside its range.
    assert_eq!(read("2026-01-01T00:00:61Z"), Err(TimeError::OutOfRange));
    assert_eq!(read("2026-01-01T00:00:99Z"), Err(TimeError::OutOfRange));
    // A second of 59 keeps its own fraction.
    assert_eq!(read("2026-01-01T00:00:59.5Z"), Ok((R + 59, 500_000_000)));
    assert_eq!(read("2026-01-01T00:00:59Z"), Ok((R + 59, 0)));
}

#[test]
fn a_second_of_sixty_keeps_its_unix_second_and_its_place_in_the_order() {
    let parse = |text: &str| Timestamp::parse_rfc3339(text).expect("a text the reader takes");
    let last_of_fifty_nine = "2016-12-31T23:59:59.999999999Z";
    for text in [
        "2016-12-31T23:59:60Z",
        "2016-12-31T23:59:60.000000001Z",
        "2016-12-31T23:59:60.5Z",
        "2016-12-31T23:59:60.999999999Z",
        "2016-12-31T23:59:60+00:00",
        "2017-01-01T00:59:60+01:00",
    ] {
        let read = parse(text);
        // The value read, and the counts earlier releases stored for it.
        assert_eq!(read, at(1_483_228_799, 999_999_999), "{text}");
        assert_eq!(read.unix_seconds(), 1_483_228_799, "{text}");
        assert_eq!(read.subsec_nanos(), 999_999_999, "{text}");
        assert_eq!(read.unix_millis(), 1_483_228_799_999, "{text}");
        assert_eq!(read.unix_micros(), 1_483_228_799_999_999, "{text}");
        // Its place in the order: with the last nanosecond of second 59,
        // after the nanosecond before that, before the next second.
        assert_eq!(read, parse(last_of_fifty_nine), "{text}");
        assert!(read > parse("2016-12-31T23:59:59.999999998Z"), "{text}");
        assert!(read > parse("2016-12-31T23:59:59Z"), "{text}");
        assert!(read < parse("2017-01-01T00:00:00Z"), "{text}");
        assert_eq!(
            parse("2017-01-01T00:00:00Z").since(read),
            SignedDuration::nanoseconds(1),
            "{text}"
        );
        // It is written back as the last nanosecond of second 59.
        assert_eq!(read.to_rfc3339(), last_of_fifty_nine, "{text}");
        assert_eq!(read.to_string(), last_of_fifty_nine, "{text}");
        assert_eq!(
            read.to_rfc3339_numeric_offset(),
            "2016-12-31T23:59:59.999999999+00:00",
            "{text}"
        );
        assert_eq!(parse(&read.to_rfc3339()), read, "{text}");
    }
}

#[test]
fn a_year_of_fewer_than_four_digits_reads_as_that_year() {
    let year = |year| {
        Timestamp::from_utc(year, 1, 1, 0, 0, 0)
            .expect("a day of the calendar")
            .unix_seconds()
    };
    let cases = [
        ("26-01-01T00:00:00Z", year(26)),
        ("026-01-01T00:00:00Z", year(26)),
        ("0026-01-01T00:00:00Z", year(26)),
        ("7-01-01T00:00:00Z", year(7)),
        ("0-01-01T00:00:00Z", year(0)),
        ("999-01-01T00:00:00Z", year(999)),
        ("+26-01-01T00:00:00Z", year(26)),
        ("-26-01-01T00:00:00Z", year(-26)),
        ("-1-01-01T00:00:00Z", year(-1)),
        ("-0-01-01T00:00:00Z", year(0)),
        ("-0000-01-01T00:00:00Z", year(0)),
        ("+0-01-01T00:00:00Z", year(0)),
        ("+12345-01-01T00:00:00Z", year(12_345)),
        ("-12345-01-01T00:00:00Z", year(-12_345)),
        (
            "+000000000000000000000000000000012345-01-01T00:00:00Z",
            year(12_345),
        ),
    ];
    for (text, secs) in cases {
        assert_eq!(read(text), Ok((secs, 0)), "{text}");
    }
    // Without a sign a year has four digits at most: a fifth is out of
    // place where the `-` belongs.
    assert_eq!(read("10000-01-01T00:00:00Z"), Err(TimeError::Invalid));
    assert_eq!(read("02026-01-01T00:00:00Z"), Err(TimeError::Invalid));
    assert_eq!(read("20260-01-01T00:00:00Z"), Err(TimeError::Invalid));
}

#[test]
fn a_character_out_of_place_is_refused() {
    for text in [
        // A comma is not the mark of a fraction.
        "2026-01-01T00:00:00,5Z",
        "2026-01-01T00:00:00,500+00:00",
        // No digit after the mark of a fraction.
        "2026-01-01T00:00:00.Z",
        "2026-01-01T00:00:00.+00:00",
        "2026-01-01T00:00:00. 5Z",
        // The mark of a fraction after white space is where the offset
        // belongs.
        "2026-01-01T00:00:00 .5Z",
        // Separators.
        "2026/01/01T00:00:00Z",
        "2026-01/01T00:00:00Z",
        "2026-01-01T00.00.00Z",
        "2026-01-01T00:00.00Z",
        "2026-01-01X00:00:00Z",
        "2026-01-01\t00:00:00Z",
        "2026-01-01_00:00:00Z",
        "2026-01-01 T00:00:00Z",
        "2026-01-01TT00:00:00Z",
        "20260101T000000Z",
        // Signs and letters where a digit belongs.
        "x2026-01-01T00:00:00Z",
        "+-2026-01-01T00:00:00Z",
        "- 2026-01-01T00:00:00Z",
        "+ 2026-01-01T00:00:00Z",
        "2026--01-01T00:00:00Z",
        "2026-+1-01T00:00:00Z",
        "2026-01-01T-1:00:00Z",
        "2026-01-01T00:00:-1Z",
        "\u{2212}0001-01-01T00:00:00Z",
        "\u{ff12}\u{ff10}\u{ff12}\u{ff16}-01-01T00:00:00Z",
        "2026-01-01T00:00:0\u{0660}Z",
        "\u{e9}",
        // Offsets.
        "2026-01-01T00:00:00X",
        "2026-01-01T00:00:00 GMT",
        "2026-01-01T00:00:00UT",
        "2026-01-01T00:00:00U",
        "2026-01-01T00:00:00+1:00",
        "2026-01-01T00:00:00+0a:00",
        "2026-01-01T00:00:00+a0:00",
        "2026-01-01T00:00:00+00:a0",
        "2026-01-01T00:00:00+00:0a",
        "2026-01-01T00:00:00+00-00",
        "2026-01-01T00:00:00+ 00:00",
        "2026-01-01T00:00:00++00:00",
        "2026-01-01T00:00:00\u{b1}00:00",
        "2026-01-01T00:00:00+0\u{0660}:00",
    ] {
        assert_eq!(read(text), Err(TimeError::Invalid), "{text:?}");
    }
}

#[test]
fn a_text_that_ends_early_is_refused() {
    for text in [
        "",
        " ",
        "2",
        "2026",
        "2026-",
        "2026-01",
        "2026-01-",
        "2026-01-01",
        "2026-01-01T",
        "2026-01-01T00",
        "2026-01-01T00:",
        "2026-01-01T00:00",
        "2026-01-01T00:00:",
        "2026-01-01T00:00:00",
        "2026-01-01T00:00:00 ",
        "2026-01-01T00:00:00.",
        "2026-01-01T00:00:00.5",
        "2026-01-01T00:00:00+",
        "2026-01-01T00:00:00-",
        "2026-01-01T00:00:00+0",
        "2026-01-01T00:00:00+00",
        "2026-01-01T00:00:00+00:",
        "2026-01-01T00:00:00+00:0",
        "2026-01-01T00:00:00+000",
        "2026-01-01T00:00:00\u{2212}",
        "+",
        "-",
    ] {
        assert_eq!(read(text), Err(TimeError::TooShort), "{text:?}");
    }
}

#[test]
fn text_after_the_offset_is_refused() {
    for text in [
        "2026-01-01T00:00:00Zjunk",
        "2026-01-01T00:00:00ZZ",
        "2026-01-01T00:00:00Z0",
        "2026-01-01T00:00:00Z Z",
        "2026-01-01T00:00:00Z+00:00",
        "2026-01-01T00:00:00+00:000",
        "2026-01-01T00:00:00+00:00:00",
        "2026-01-01T00:00:00+00:00Z",
        "2026-01-01T00:00:00UTCZ",
        "2026-01-01T00:00:00 UTC+1",
        "2026-01-01T00:00:00Z\u{e9}",
        "2026-01-01T00:00:00Z 2026-01-01T00:00:00Z",
    ] {
        assert_eq!(read(text), Err(TimeError::TrailingText), "{text:?}");
    }
}

#[test]
fn a_field_outside_its_range_is_refused() {
    for text in [
        "2026-00-01T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-99-01T00:00:00Z",
        "2026-01-00T00:00:00Z",
        "2026-01-32T00:00:00Z",
        "2026-01-99T00:00:00Z",
        "2026-02-29T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T99:00:00Z",
        "2026-01-01T00:60:00Z",
        "2026-01-01T00:99:00Z",
        "2026-01-01T00:00:61Z",
        "2026-01-01T00:00:00+24:00",
        "2026-01-01T00:00:00-24:00",
        "2026-01-01T00:00:00+99:00",
        "2026-01-01T00:00:00+99:59",
        "2026-01-01T00:00:00+00:60",
        "2026-01-01T00:00:00+00:99",
        "2026-01-01T00:00:00-00:60",
        "+262143-01-01T00:00:00Z",
        "-262144-12-31T23:59:59Z",
        "+2147483647-01-01T00:00:00Z",
        "+2147483648-01-01T00:00:00Z",
        "-2147483648-01-01T00:00:00Z",
        "-2147483649-01-01T00:00:00Z",
        "+9223372036854775807-01-01T00:00:00Z",
        "+9223372036854775808-01-01T00:00:00Z",
        "-9223372036854775808-01-01T00:00:00Z",
        "+99999999999999999999999999999999-01-01T00:00:00Z",
    ] {
        assert_eq!(read(text), Err(TimeError::OutOfRange), "{text:?}");
    }
    assert!(read("2024-02-29T00:00:00Z").is_ok());
    assert!(read("2000-02-29T00:00:00Z").is_ok());
    assert!(read("2026-01-01T23:59:59Z").is_ok());
}

#[test]
fn a_reading_outside_the_range_is_refused_in_local_time_and_in_utc() {
    // The first and the last readings, written with an offset on the side
    // that keeps the local date in the range.
    assert_eq!(
        read("-262143-01-01T00:01:00+00:01"),
        Ok((-8_334_601_228_800, 0))
    );
    assert_eq!(
        read("-262143-01-01T23:59:00+23:59"),
        Ok((-8_334_601_228_800, 0))
    );
    assert_eq!(
        read("+262142-12-31T23:58:59.999999999-00:01"),
        Ok((8_210_266_876_799, 999_999_999))
    );
    assert_eq!(
        read("+262142-12-31T00:00:59.999999999-23:59"),
        Ok((8_210_266_876_799, 999_999_999))
    );
    for text in [
        // In the range as written, outside it in UTC.
        "-262143-01-01T00:00:00+00:01",
        "-262143-01-01T23:58:59.999999999+23:59",
        "+262142-12-31T23:59:59.999999999-00:01",
        "+262142-12-31T23:59:00-00:01",
        "+262142-12-31T00:01:00-23:59",
        // In the range in UTC, written with a local date outside it.
        "+262143-01-01T00:30:00+01:00",
        "-262144-12-31T23:30:00-01:00",
    ] {
        assert_eq!(read(text), Err(TimeError::OutOfRange), "{text}");
    }
}

/// The digits of a fraction the written form must carry for `nanos`.
fn fraction_digits(nanos: u32) -> usize {
    if nanos == 0 {
        0
    } else if nanos.is_multiple_of(1_000_000) {
        3
    } else if nanos.is_multiple_of(1_000) {
        6
    } else {
        9
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the tables of this module cover the same code under Miri"
)]
fn generated_readings_write_the_pinned_shape_and_read_back() {
    let mut generator = Generator::new(0x5EED_0004);
    for _ in 0..300_000 {
        let reading = generator.timestamp();
        let text = reading.to_rfc3339();
        assert_eq!(Timestamp::parse_rfc3339(&text), Ok(reading), "{text}");
        assert_eq!(text.parse::<Timestamp>(), Ok(reading));

        // The shape, taken apart by hand: date, `T`, time, fraction, `Z`.
        let (date, hour, minute, second, nanos) = reading.to_utc();
        let body = text.strip_suffix('Z').expect("the text ends with Z");
        let (day, time) = body.split_once('T').expect("a T between date and time");
        assert_eq!(day, date.to_string());
        let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
        assert_eq!(clock, format!("{hour:02}:{minute:02}:{second:02}"));
        assert_eq!(fraction.len(), fraction_digits(nanos), "{text}");
        assert!(fraction.bytes().all(|digit| digit.is_ascii_digit()));
        assert_eq!(
            format!("{fraction:0<9}").parse::<u32>(),
            Ok(nanos),
            "{text}"
        );
        assert!(text.is_ascii());

        let with_offset = reading.to_rfc3339_numeric_offset();
        assert_eq!(with_offset, format!("{body}+00:00"));
        assert_eq!(Timestamp::parse_rfc3339(&with_offset), Ok(reading));

        // Other spellings of the same text.
        assert_eq!(Timestamp::parse_rfc3339(&text.to_lowercase()), Ok(reading));
        assert_eq!(
            Timestamp::parse_rfc3339(&format!(" {} UTC ", body.replace('T', " "))),
            Ok(reading)
        );
        // Every field without its padding, and a fraction of nine digits
        // and more.
        let signed = if (0..=9999).contains(&date.year()) {
            ""
        } else {
            "+"
        };
        let loose = format!(
            "{}{}-{}-{}t{}:{}:{}.{:09}123z",
            if date.year() < 0 { "" } else { signed },
            date.year(),
            date.month(),
            date.day(),
            hour,
            minute,
            second,
            nanos
        );
        assert_eq!(Timestamp::parse_rfc3339(&loose), Ok(reading), "{loose}");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the tables of this module cover the same code under Miri"
)]
fn a_generated_offset_form_reads_as_the_utc_form_shifted() {
    let mut generator = Generator::new(0x5EED_0005);
    let mut read_back = 0u32;
    let mut refused = 0u32;
    for _ in 0..300_000 {
        let reading = generator.timestamp();
        let minutes = generator.between(-1_439, 1_439) as i32;
        let (sign, size) = if minutes < 0 {
            ('-', -minutes)
        } else {
            ('+', minutes)
        };
        // The local time of the reading at that offset, written as UTC,
        // with the offset in place of the `Z`.
        let local = reading.checked_add(SignedDuration::minutes(minutes));
        let Some(local) = local else {
            // The local time is past an end of the range. The reading
            // written as a local time at the opposite offset names that
            // same time in UTC, so that text is refused.
            let other = if sign == '-' { '+' } else { '-' };
            let body = reading.to_rfc3339();
            let body = body.strip_suffix('Z').expect("the text ends with Z");
            let text = format!("{body}{other}{:02}:{:02}", size / 60, size % 60);
            assert_eq!(read(&text), Err(TimeError::OutOfRange), "{text}");
            refused += 1;
            continue;
        };
        let body = local.to_rfc3339();
        let body = body.strip_suffix('Z').expect("the text ends with Z");
        let colon = format!("{body}{sign}{:02}:{:02}", size / 60, size % 60);
        let plain = format!("{body}{sign}{:02}{:02}", size / 60, size % 60);
        assert_eq!(Timestamp::parse_rfc3339(&colon), Ok(reading), "{colon}");
        assert_eq!(Timestamp::parse_rfc3339(&plain), Ok(reading), "{plain}");
        // The offset form names the reading the `Z` form names, shifted.
        assert_eq!(
            Timestamp::parse_rfc3339(&format!("{body}Z")).map(|utc| utc.since(reading)),
            Ok(SignedDuration::minutes(minutes)),
            "{colon}"
        );
        read_back += 1;
    }
    assert!(read_back > 290_000, "{read_back} offset forms read back");
    assert!(
        refused > 100,
        "{refused} offset forms past the range refused"
    );
}
