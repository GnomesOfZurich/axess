use super::SignedDuration;
use crate::error::TimeError;
use crate::sample::Generator;
use std::time::Duration;

/// A span from its two fields, whatever their signs.
fn span(secs: i64, nanos: i32) -> SignedDuration {
    SignedDuration::from_mixed(secs, nanos)
}

fn parts(span: SignedDuration) -> (i64, i32) {
    (span.whole_seconds(), span.subsec_nanos())
}

/// The sum of two spans by carrying the nanoseconds by hand, or `None` past
/// the range: written apart from the code under test.
fn sum(a: SignedDuration, b: SignedDuration) -> Option<(i64, i32)> {
    let mut secs = i128::from(a.whole_seconds()) + i128::from(b.whole_seconds());
    let mut nanos = a.subsec_nanos() + b.subsec_nanos();
    if nanos >= 1_000_000_000 {
        secs += 1;
        nanos -= 1_000_000_000;
    } else if nanos <= -1_000_000_000 {
        secs -= 1;
        nanos += 1_000_000_000;
    }
    if secs > 0 && nanos < 0 {
        secs -= 1;
        nanos += 1_000_000_000;
    } else if secs < 0 && nanos > 0 {
        secs += 1;
        nanos -= 1_000_000_000;
    }
    i64::try_from(secs).ok().map(|secs| (secs, nanos))
}

#[test]
fn the_named_spans_are_the_pinned_ones() {
    assert_eq!(parts(SignedDuration::ZERO), (0, 0));
    assert_eq!(parts(SignedDuration::MIN), (i64::MIN, -999_999_999));
    assert_eq!(parts(SignedDuration::MAX), (i64::MAX, 999_999_999));
    assert_eq!(SignedDuration::default(), SignedDuration::ZERO);
}

#[test]
fn whole_units_are_exact_counts_of_seconds() {
    assert_eq!(parts(SignedDuration::seconds(5)), (5, 0));
    assert_eq!(parts(SignedDuration::seconds(-5)), (-5, 0));
    assert_eq!(parts(SignedDuration::seconds(i64::MAX)), (i64::MAX, 0));
    assert_eq!(parts(SignedDuration::seconds(i64::MIN)), (i64::MIN, 0));
    assert_eq!(parts(SignedDuration::minutes(1)), (60, 0));
    assert_eq!(parts(SignedDuration::minutes(-2)), (-120, 0));
    assert_eq!(parts(SignedDuration::hours(1)), (3_600, 0));
    assert_eq!(parts(SignedDuration::hours(-24)), (-86_400, 0));
    assert_eq!(parts(SignedDuration::days(1)), (86_400, 0));
    assert_eq!(parts(SignedDuration::days(-30)), (-2_592_000, 0));
    assert_eq!(SignedDuration::days(1), SignedDuration::hours(24));
    assert_eq!(SignedDuration::hours(1), SignedDuration::minutes(60));
    assert_eq!(SignedDuration::minutes(1), SignedDuration::seconds(60));
    assert_eq!(SignedDuration::days(0), SignedDuration::ZERO);
    // The widest argument of each fits.
    assert_eq!(
        parts(SignedDuration::minutes(i32::MAX)),
        (128_849_018_820, 0)
    );
    assert_eq!(
        parts(SignedDuration::minutes(i32::MIN)),
        (-128_849_018_880, 0)
    );
    assert_eq!(
        parts(SignedDuration::hours(i32::MAX)),
        (7_730_941_129_200, 0)
    );
    assert_eq!(
        parts(SignedDuration::hours(i32::MIN)),
        (-7_730_941_132_800, 0)
    );
    assert_eq!(
        parts(SignedDuration::days(i32::MAX)),
        (185_542_587_100_800, 0)
    );
    assert_eq!(
        parts(SignedDuration::days(i32::MIN)),
        (-185_542_587_187_200, 0)
    );
}

#[test]
fn fractions_of_a_second_carry_the_sign_of_the_span() {
    let cases = [
        (SignedDuration::milliseconds(0), (0, 0)),
        (SignedDuration::milliseconds(1), (0, 1_000_000)),
        (SignedDuration::milliseconds(999), (0, 999_000_000)),
        (SignedDuration::milliseconds(1_000), (1, 0)),
        (SignedDuration::milliseconds(1_500), (1, 500_000_000)),
        (SignedDuration::milliseconds(-1), (0, -1_000_000)),
        (SignedDuration::milliseconds(-500), (0, -500_000_000)),
        (SignedDuration::milliseconds(-1_000), (-1, 0)),
        (SignedDuration::milliseconds(-1_500), (-1, -500_000_000)),
        (
            SignedDuration::milliseconds(i64::MAX),
            (9_223_372_036_854_775, 807_000_000),
        ),
        (
            SignedDuration::milliseconds(i64::MIN),
            (-9_223_372_036_854_775, -808_000_000),
        ),
        (SignedDuration::microseconds(1), (0, 1_000)),
        (SignedDuration::microseconds(999_999), (0, 999_999_000)),
        (SignedDuration::microseconds(1_000_000), (1, 0)),
        (SignedDuration::microseconds(2_500_000), (2, 500_000_000)),
        (SignedDuration::microseconds(-1), (0, -1_000)),
        (SignedDuration::microseconds(-2_500_000), (-2, -500_000_000)),
        (
            SignedDuration::microseconds(i64::MAX),
            (9_223_372_036_854, 775_807_000),
        ),
        (
            SignedDuration::microseconds(i64::MIN),
            (-9_223_372_036_854, -775_808_000),
        ),
        (SignedDuration::nanoseconds(1), (0, 1)),
        (SignedDuration::nanoseconds(999_999_999), (0, 999_999_999)),
        (SignedDuration::nanoseconds(1_000_000_000), (1, 0)),
        (SignedDuration::nanoseconds(1_000_000_001), (1, 1)),
        (SignedDuration::nanoseconds(-1), (0, -1)),
        (SignedDuration::nanoseconds(-1_000_000_001), (-1, -1)),
        (
            SignedDuration::nanoseconds(i64::MAX),
            (9_223_372_036, 854_775_807),
        ),
        (
            SignedDuration::nanoseconds(i64::MIN),
            (-9_223_372_036, -854_775_808),
        ),
    ];
    for (span, expected) in cases {
        assert_eq!(parts(span), expected);
    }
    assert_eq!(
        SignedDuration::milliseconds(1),
        SignedDuration::microseconds(1_000)
    );
    assert_eq!(
        SignedDuration::microseconds(1),
        SignedDuration::nanoseconds(1_000)
    );
    assert_eq!(
        SignedDuration::seconds(1),
        SignedDuration::milliseconds(1_000)
    );
}

#[test]
fn minus_half_a_second_is_negative_with_no_whole_second() {
    let half = SignedDuration::milliseconds(-500);
    assert!(half.is_negative());
    assert!(!half.is_zero());
    assert_eq!(half.whole_seconds(), 0);
    assert_eq!(half.subsec_nanos(), -500_000_000);
    assert_eq!(half.whole_milliseconds(), -500);
    assert_eq!(half.unsigned_abs(), Duration::from_millis(500));
    assert!(half < SignedDuration::ZERO);
    assert!(half > SignedDuration::seconds(-1));
    assert_eq!(
        half.checked_add(half),
        Some(SignedDuration::seconds(-1)),
        "two halves make minus one second"
    );
    assert_eq!(
        half.checked_add(SignedDuration::milliseconds(500)),
        Some(SignedDuration::ZERO)
    );
}

#[test]
fn mixed_signs_settle_on_the_sign_of_the_whole() {
    assert_eq!(parts(span(1, -250_000_000)), (0, 750_000_000));
    assert_eq!(parts(span(-1, 250_000_000)), (0, -750_000_000));
    assert_eq!(parts(span(2, -1)), (1, 999_999_999));
    assert_eq!(parts(span(-2, 1)), (-1, -999_999_999));
    assert_eq!(parts(span(0, 5)), (0, 5));
    assert_eq!(parts(span(0, -5)), (0, -5));
    assert_eq!(parts(span(5, 5)), (5, 5));
    assert_eq!(parts(span(-5, -5)), (-5, -5));
    assert_eq!(parts(span(5, 0)), (5, 0));
    assert_eq!(parts(span(-5, 0)), (-5, 0));
    assert_eq!(parts(span(i64::MAX, -1)), (i64::MAX - 1, 999_999_999));
    assert_eq!(parts(span(i64::MIN, 1)), (i64::MIN + 1, -999_999_999));
    assert_eq!(span(i64::MAX, 999_999_999), SignedDuration::MAX);
    assert_eq!(span(i64::MIN, -999_999_999), SignedDuration::MIN);
}

#[test]
fn spans_order_from_the_most_negative_to_the_longest() {
    let ordered = [
        SignedDuration::MIN,
        span(i64::MIN, -999_999_998),
        SignedDuration::seconds(i64::MIN),
        span(i64::MIN + 1, -999_999_999),
        SignedDuration::seconds(-2),
        span(-1, -500_000_000),
        span(-1, -1),
        SignedDuration::seconds(-1),
        span(0, -999_999_999),
        span(0, -500_000_000),
        span(0, -1),
        SignedDuration::ZERO,
        span(0, 1),
        span(0, 500_000_000),
        span(0, 999_999_999),
        SignedDuration::seconds(1),
        span(1, 1),
        span(1, 500_000_000),
        SignedDuration::seconds(2),
        SignedDuration::seconds(i64::MAX),
        span(i64::MAX, 999_999_998),
        SignedDuration::MAX,
    ];
    for (index, shorter) in ordered.iter().enumerate() {
        for longer in &ordered[index + 1..] {
            assert!(shorter < longer, "{shorter:?} is below {longer:?}");
            assert!(longer > shorter);
            assert_ne!(shorter, longer);
        }
        assert_eq!(shorter.cmp(shorter), std::cmp::Ordering::Equal);
    }
}

#[test]
fn the_size_of_a_span_is_an_unsigned_span() {
    assert_eq!(SignedDuration::ZERO.unsigned_abs(), Duration::ZERO);
    assert_eq!(
        SignedDuration::seconds(5).unsigned_abs(),
        Duration::from_secs(5)
    );
    assert_eq!(
        SignedDuration::seconds(-5).unsigned_abs(),
        Duration::from_secs(5)
    );
    assert_eq!(
        span(-1, -500_000_000).unsigned_abs(),
        Duration::new(1, 500_000_000)
    );
    assert_eq!(
        span(1, 500_000_000).unsigned_abs(),
        Duration::new(1, 500_000_000)
    );
    assert_eq!(span(0, -1).unsigned_abs(), Duration::new(0, 1));
    assert_eq!(
        SignedDuration::MAX.unsigned_abs(),
        Duration::new(9_223_372_036_854_775_807, 999_999_999)
    );
    assert_eq!(
        SignedDuration::MIN.unsigned_abs(),
        Duration::new(9_223_372_036_854_775_808, 999_999_999)
    );
}

#[test]
fn only_a_span_that_runs_backwards_is_negative() {
    for negative in [
        SignedDuration::MIN,
        SignedDuration::seconds(-1),
        span(0, -1),
        span(-1, -1),
    ] {
        assert!(negative.is_negative(), "{negative:?}");
        assert!(!negative.is_zero());
    }
    for positive in [
        SignedDuration::MAX,
        SignedDuration::seconds(1),
        span(0, 1),
        span(1, 1),
    ] {
        assert!(!positive.is_negative(), "{positive:?}");
        assert!(!positive.is_zero());
    }
    assert!(!SignedDuration::ZERO.is_negative());
    assert!(SignedDuration::ZERO.is_zero());
}

#[test]
fn whole_units_round_towards_zero() {
    let cases = [
        (span(1, 999_999_999), 1, 1_999),
        (span(-1, -999_999_999), -1, -1_999),
        (span(0, 999_999), 0, 0),
        (span(0, -999_999), 0, 0),
        (span(0, 1_000_000), 0, 1),
        (span(0, -1_000_000), 0, -1),
        (span(0, 1_999_999), 0, 1),
        (span(0, -1_999_999), 0, -1),
        (span(-1, -500_000_000), -1, -1_500),
        (span(90, 0), 90, 90_000),
        (SignedDuration::MAX, i64::MAX, 9_223_372_036_854_775_807_999),
        (
            SignedDuration::MIN,
            i64::MIN,
            -9_223_372_036_854_775_808_999,
        ),
    ];
    for (span, seconds, milliseconds) in cases {
        assert_eq!(span.whole_seconds(), seconds, "{span:?}");
        assert_eq!(span.whole_milliseconds(), milliseconds, "{span:?}");
    }
}

#[test]
fn sums_carry_between_the_seconds_and_the_fraction() {
    let cases = [
        (
            span(0, 600_000_000),
            span(0, 600_000_000),
            Some((1, 200_000_000)),
        ),
        (
            span(0, -600_000_000),
            span(0, -600_000_000),
            Some((-1, -200_000_000)),
        ),
        (span(0, 500_000_000), span(0, 500_000_000), Some((1, 0))),
        (span(0, -500_000_000), span(0, -500_000_000), Some((-1, 0))),
        (span(1, 0), span(0, -250_000_000), Some((0, 750_000_000))),
        (span(-1, 0), span(0, 250_000_000), Some((0, -750_000_000))),
        (span(1, 500_000_000), span(-2, 0), Some((0, -500_000_000))),
        (span(-1, -500_000_000), span(2, 0), Some((0, 500_000_000))),
        (span(3, 1), span(-3, -1), Some((0, 0))),
        (
            SignedDuration::MAX,
            SignedDuration::ZERO,
            Some((i64::MAX, 999_999_999)),
        ),
        (
            SignedDuration::MIN,
            SignedDuration::ZERO,
            Some((i64::MIN, -999_999_999)),
        ),
        (SignedDuration::MAX, span(0, 1), None),
        (
            SignedDuration::MAX,
            span(0, -1),
            Some((i64::MAX, 999_999_998)),
        ),
        (SignedDuration::MIN, span(0, -1), None),
        (
            SignedDuration::MIN,
            span(0, 1),
            Some((i64::MIN, -999_999_998)),
        ),
        (SignedDuration::MAX, SignedDuration::MAX, None),
        (SignedDuration::MIN, SignedDuration::MIN, None),
        (SignedDuration::MAX, SignedDuration::MIN, Some((-1, 0))),
        (
            SignedDuration::seconds(i64::MAX),
            span(0, 999_999_999),
            Some((i64::MAX, 999_999_999)),
        ),
        (SignedDuration::seconds(i64::MAX), span(1, 0), None),
        (SignedDuration::seconds(i64::MIN), span(-1, 0), None),
        (span(i64::MAX, 500_000_000), span(0, 500_000_000), None),
        (span(i64::MIN, -500_000_000), span(0, -500_000_000), None),
    ];
    for (a, b, expected) in cases {
        assert_eq!(a.checked_add(b).map(parts), expected, "{a:?} + {b:?}");
        assert_eq!(b.checked_add(a).map(parts), expected, "{b:?} + {a:?}");
        assert_eq!(sum(a, b), expected, "the sum by hand of {a:?} and {b:?}");
    }
}

#[test]
fn differences_borrow_between_the_seconds_and_the_fraction() {
    let cases = [
        (
            span(1, 200_000_000),
            span(0, 600_000_000),
            Some((0, 600_000_000)),
        ),
        (
            span(0, 200_000_000),
            span(0, 600_000_000),
            Some((0, -400_000_000)),
        ),
        (
            span(-1, -200_000_000),
            span(0, -600_000_000),
            Some((0, -600_000_000)),
        ),
        (span(5, 0), span(5, 0), Some((0, 0))),
        (span(5, 0), span(7, 500_000_000), Some((-2, -500_000_000))),
        (
            SignedDuration::ZERO,
            SignedDuration::MAX,
            Some((-i64::MAX, -999_999_999)),
        ),
        (SignedDuration::ZERO, SignedDuration::MIN, None),
        (span(0, -1), SignedDuration::MIN, None),
        (
            span(-1, 0),
            SignedDuration::MIN,
            Some((i64::MAX, 999_999_999)),
        ),
        (
            span(-1, -1),
            SignedDuration::MIN,
            Some((i64::MAX, 999_999_998)),
        ),
        (SignedDuration::MIN, SignedDuration::MIN, Some((0, 0))),
        (SignedDuration::MAX, SignedDuration::MAX, Some((0, 0))),
        (SignedDuration::MAX, SignedDuration::MIN, None),
        (SignedDuration::MIN, SignedDuration::MAX, None),
        (SignedDuration::MIN, span(0, 1), None),
        (SignedDuration::MAX, span(0, -1), None),
        (
            SignedDuration::MAX,
            span(0, 1),
            Some((i64::MAX, 999_999_998)),
        ),
    ];
    for (a, b, expected) in cases {
        assert_eq!(a.checked_sub(b).map(parts), expected, "{a:?} - {b:?}");
    }
}

#[test]
fn a_span_taken_several_times_is_checked() {
    let cases = [
        (span(1, 500_000_000), 3, Some((4, 500_000_000))),
        (span(0, -500_000_000), 3, Some((-1, -500_000_000))),
        (span(1, 500_000_000), -3, Some((-4, -500_000_000))),
        (span(0, 999_999_999), 2, Some((1, 999_999_998))),
        (span(7, 7), 1, Some((7, 7))),
        (span(7, 7), 0, Some((0, 0))),
        (span(7, 7), -1, Some((-7, -7))),
        (SignedDuration::MAX, 1, Some((i64::MAX, 999_999_999))),
        (SignedDuration::MAX, 0, Some((0, 0))),
        (SignedDuration::MAX, -1, Some((-i64::MAX, -999_999_999))),
        (SignedDuration::MAX, 2, None),
        (SignedDuration::MAX, -2, None),
        (SignedDuration::MIN, 1, Some((i64::MIN, -999_999_999))),
        (SignedDuration::MIN, -1, None),
        (SignedDuration::MIN, 2, None),
        (SignedDuration::MAX, i32::MAX, None),
        (SignedDuration::MIN, i32::MIN, None),
        (SignedDuration::MAX, i32::MIN, None),
        (
            SignedDuration::seconds(i64::MAX / 2),
            2,
            Some((i64::MAX - 1, 0)),
        ),
        (SignedDuration::seconds(i64::MAX / 2 + 1), 2, None),
        (
            SignedDuration::seconds(i64::MIN / 2),
            2,
            Some((i64::MIN, 0)),
        ),
        (
            SignedDuration::seconds(1),
            i32::MAX,
            Some((2_147_483_647, 0)),
        ),
        (
            SignedDuration::seconds(1),
            i32::MIN,
            Some((-2_147_483_648, 0)),
        ),
        (span(0, 1), i32::MIN, Some((-2, -147_483_648))),
        (SignedDuration::ZERO, i32::MIN, Some((0, 0))),
    ];
    for (span, factor, expected) in cases {
        assert_eq!(
            span.checked_mul(factor).map(parts),
            expected,
            "{span:?} times {factor}"
        );
    }
}

#[test]
fn a_span_is_divided_exactly_and_rounded_towards_zero() {
    let cases = [
        (SignedDuration::hours(1), 100, Some((36, 0))),
        (SignedDuration::hours(1), -100, Some((-36, 0))),
        (SignedDuration::hours(-1), 100, Some((-36, 0))),
        (SignedDuration::hours(-1), -100, Some((36, 0))),
        (span(1, 0), 3, Some((0, 333_333_333))),
        (span(-1, 0), 3, Some((0, -333_333_333))),
        (span(1, 0), -3, Some((0, -333_333_333))),
        (span(2, 0), 3, Some((0, 666_666_666))),
        // The whole is divided, not each part: two seconds and two
        // nanoseconds in three parts.
        (span(2, 2), 3, Some((0, 666_666_667))),
        (span(1, 2), 3, Some((0, 333_333_334))),
        (span(-1, -999_999_999), 4, Some((0, -499_999_999))),
        (span(7, 500_000_000), 2, Some((3, 750_000_000))),
        (span(-7, -500_000_000), 2, Some((-3, -750_000_000))),
        (span(0, 1), 2, Some((0, 0))),
        (span(0, -1), 2, Some((0, 0))),
        (span(0, 3), 2, Some((0, 1))),
        (span(0, -3), 2, Some((0, -1))),
        (span(7, 7), 1, Some((7, 7))),
        (span(7, 7), -1, Some((-7, -7))),
        (span(7, 7), 0, None),
        (SignedDuration::ZERO, 0, None),
        (SignedDuration::ZERO, 5, Some((0, 0))),
        (SignedDuration::ZERO, i32::MIN, Some((0, 0))),
        (SignedDuration::MAX, 1, Some((i64::MAX, 999_999_999))),
        (SignedDuration::MAX, -1, Some((-i64::MAX, -999_999_999))),
        (SignedDuration::MIN, 1, Some((i64::MIN, -999_999_999))),
        // The size of the most negative span is past the longest one by a
        // second, and no divisor but one or minus one leaves it there.
        (SignedDuration::MIN, -1, None),
        (SignedDuration::MIN, 2, Some((i64::MIN / 2, -499_999_999))),
        (
            SignedDuration::MIN,
            -2,
            Some((-(i64::MIN / 2), 499_999_999)),
        ),
        (SignedDuration::MAX, 2, Some((i64::MAX / 2, 999_999_999))),
        (SignedDuration::MAX, i32::MAX, Some((4_294_967_298, 0))),
        (SignedDuration::MIN, i32::MIN, Some((4_294_967_296, 0))),
        (SignedDuration::seconds(1), i32::MAX, Some((0, 0))),
        (SignedDuration::seconds(-1), i32::MIN, Some((0, 0))),
        (
            SignedDuration::seconds(i32::MAX as i64),
            i32::MAX,
            Some((1, 0)),
        ),
    ];
    for (span, divisor, expected) in cases {
        assert_eq!(
            span.checked_div(divisor).map(parts),
            expected,
            "{span:?} in {divisor} parts"
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "tens of thousands of generated values are too slow to interpret; the fixed cases cover the division under Miri"
)]
fn a_quotient_times_its_divisor_is_within_the_divisor_of_the_span() {
    // Written apart from the code under test: the quotient taken back
    // `divisor` times differs from the span by less than `divisor`
    // nanoseconds, and never passes it.
    let mut generator = Generator::new(0xD1F1_DE00);
    for _ in 0..50_000 {
        let whole = generator.between(-4_000_000_000_000, 4_000_000_000_000);
        let fraction = generator.between(0, 999_999_999) as i32;
        let span = span(whole, if whole < 0 { -fraction } else { fraction });
        let divisor = match generator.between(0, 3) {
            0 => generator.between(1, 9),
            1 => generator.between(-9, -1),
            2 => generator.between(1, 1_000_000),
            _ => generator.between(-1_000_000, -1),
        } as i32;
        let quotient = span
            .checked_div(divisor)
            .expect("a divisor that is not zero");
        let back = quotient
            .checked_mul(divisor)
            .expect("no larger than the span");
        let short = span.checked_sub(back).expect("inside the range");
        assert_eq!(short.whole_seconds(), 0, "{span:?} in {divisor} parts");
        assert!(
            short.subsec_nanos().unsigned_abs() < divisor.unsigned_abs(),
            "{span:?} in {divisor} parts"
        );
        assert!(
            short.is_zero() || short.is_negative() == span.is_negative(),
            "{span:?} in {divisor} parts"
        );
    }
}

#[test]
fn a_span_prints_as_a_count_of_seconds() {
    let cases = [
        (SignedDuration::ZERO, "P0D"),
        (SignedDuration::seconds(1), "PT1S"),
        (SignedDuration::seconds(-1), "-PT1S"),
        (SignedDuration::hours(2), "PT7200S"),
        (SignedDuration::minutes(-5), "-PT300S"),
        (SignedDuration::days(1), "PT86400S"),
        (span(1, 500_000_000), "PT1.5S"),
        (span(-1, -500_000_000), "-PT1.5S"),
        (span(0, 250_000_000), "PT0.25S"),
        (span(0, -250_000_000), "-PT0.25S"),
        (span(0, 1), "PT0.000000001S"),
        (span(0, -1), "-PT0.000000001S"),
        (span(0, 10), "PT0.00000001S"),
        (span(0, 100_000_000), "PT0.1S"),
        (span(0, 999_999_999), "PT0.999999999S"),
        (span(3, 1_000), "PT3.000001S"),
        (span(3, 1_000_000), "PT3.001S"),
        (span(3, 120_000_000), "PT3.12S"),
        (span(3, 123_456_789), "PT3.123456789S"),
        (span(3, 123_456_780), "PT3.12345678S"),
        (span(10, 0), "PT10S"),
        (span(100, 50_000_000), "PT100.05S"),
        (SignedDuration::MAX, "PT9223372036854775807.999999999S"),
        (SignedDuration::MIN, "-PT9223372036854775808.999999999S"),
        (SignedDuration::seconds(i64::MIN), "-PT9223372036854775808S"),
    ];
    for (span, text) in cases {
        assert_eq!(span.to_string(), text, "{span:?}");
    }
    // Width, fill and precision are not applied.
    assert_eq!(format!("{:>12}", SignedDuration::seconds(5)), "PT5S");
    assert_eq!(format!("{:.1}", span(1, 250_000_000)), "PT1.25S");
}

#[test]
fn arithmetic_is_checked_in_constant_code() {
    const MINUTE: Option<SignedDuration> =
        SignedDuration::seconds(30).checked_add(SignedDuration::seconds(30));
    const PAST: Option<SignedDuration> = SignedDuration::MAX.checked_mul(2);
    const HUNDREDTH: Option<SignedDuration> = SignedDuration::hours(1).checked_div(100);
    const BY_NOTHING: Option<SignedDuration> = SignedDuration::hours(1).checked_div(0);
    assert_eq!(MINUTE, Some(SignedDuration::minutes(1)));
    assert_eq!(PAST, None);
    assert_eq!(HUNDREDTH, Some(SignedDuration::seconds(36)));
    assert_eq!(BY_NOTHING, None);
}

#[test]
fn an_unsigned_span_converts_while_it_fits() {
    assert_eq!(
        SignedDuration::try_from(Duration::ZERO),
        Ok(SignedDuration::ZERO)
    );
    assert_eq!(
        SignedDuration::try_from(Duration::new(1, 500_000_000)),
        Ok(span(1, 500_000_000))
    );
    assert_eq!(
        SignedDuration::try_from(Duration::new(0, 999_999_999)),
        Ok(span(0, 999_999_999))
    );
    assert_eq!(
        SignedDuration::try_from(Duration::new(9_223_372_036_854_775_807, 999_999_999)),
        Ok(SignedDuration::MAX)
    );
    assert_eq!(
        SignedDuration::try_from(Duration::new(9_223_372_036_854_775_808, 0)),
        Err(TimeError::OutOfRange)
    );
    assert_eq!(
        SignedDuration::try_from(Duration::MAX),
        Err(TimeError::OutOfRange)
    );
}

#[test]
fn a_signed_span_converts_unless_it_runs_backwards() {
    assert_eq!(Duration::try_from(SignedDuration::ZERO), Ok(Duration::ZERO));
    assert_eq!(
        Duration::try_from(span(1, 500_000_000)),
        Ok(Duration::new(1, 500_000_000))
    );
    assert_eq!(
        Duration::try_from(SignedDuration::MAX),
        Ok(Duration::new(9_223_372_036_854_775_807, 999_999_999))
    );
    for negative in [
        span(0, -1),
        SignedDuration::seconds(-1),
        span(-1, -500_000_000),
        SignedDuration::MIN,
    ] {
        assert_eq!(
            Duration::try_from(negative),
            Err(TimeError::Negative),
            "{negative:?}"
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of thousands of generated values are too slow to interpret; the tables of this module cover the same code under Miri"
)]
fn generated_spans_add_and_subtract_as_by_hand() {
    let mut generator = Generator::new(0x5EED_0001);
    let mut in_range = 0u32;
    for _ in 0..200_000 {
        let (a, b) = (generator.span(), generator.span());
        // The fields keep one sign and a fraction below one second.
        for span in [a, b] {
            let (secs, nanos) = parts(span);
            assert!(nanos.abs() < 1_000_000_000);
            assert!(secs.signum() * i64::from(nanos.signum()) >= 0, "{span:?}");
        }
        let added = a.checked_add(b);
        assert_eq!(added.map(parts), sum(a, b), "{a:?} + {b:?}");
        if let Some(added) = added {
            in_range += 1;
            assert_eq!(added.checked_sub(b), Some(a), "({a:?} + {b:?}) - {b:?}");
            assert_eq!(added.checked_sub(a), Some(b));
            assert_eq!(a.cmp(&added), SignedDuration::ZERO.cmp(&b));
        }
        // Order is the order of the spans as counts of nanoseconds.
        let count = |span: SignedDuration| {
            i128::from(span.whole_seconds()) * 1_000_000_000 + i128::from(span.subsec_nanos())
        };
        assert_eq!(a.cmp(&b), count(a).cmp(&count(b)), "{a:?} against {b:?}");
        // A round trip through the unsigned span keeps a span that fits it.
        match Duration::try_from(a) {
            Ok(unsigned) => {
                assert!(!a.is_negative());
                assert_eq!(SignedDuration::try_from(unsigned), Ok(a));
            }
            Err(error) => {
                assert!(a.is_negative());
                assert_eq!(error, TimeError::Negative);
            }
        }
    }
    assert!(in_range > 50_000, "{in_range} sums inside the range");
}
