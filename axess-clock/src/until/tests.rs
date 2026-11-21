use super::Until;
use crate::duration::SignedDuration;
use crate::error::TimeError;
use crate::timestamp::Timestamp;
use std::collections::HashSet;
use std::time::Duration;

/// The second `Forever` is stored as.
const FOREVER_SECONDS: i64 = 8_210_266_876_799;
/// 2026-01-01T00:00:00Z as Unix seconds.
const REFERENCE: i64 = 1_767_225_600;

fn at(secs: i64, nanos: u32) -> Timestamp {
    Timestamp::new(secs, nanos).expect("a reading inside the range")
}

/// The span from `now` to the end of the range, as a lifetime.
fn to_the_end(now: Timestamp) -> Duration {
    Duration::try_from(Timestamp::MAX.since(now)).expect("no reading is after the last one")
}

#[test]
fn forever_is_stored_as_the_latest_reading() {
    assert_eq!(Until::LEGACY_FOREVER, Timestamp::MAX);
    assert_eq!(Until::LEGACY_FOREVER.unix_seconds(), FOREVER_SECONDS);
    assert_eq!(Until::LEGACY_FOREVER.subsec_nanos(), 999_999_999);
    assert_eq!(
        Until::LEGACY_FOREVER.to_rfc3339(),
        "+262142-12-31T23:59:59.999999999Z"
    );
}

#[test]
fn every_end_at_a_reading_orders_before_forever() {
    let ordered = [
        Until::At(Timestamp::MIN),
        Until::At(at(-1, 999_999_999)),
        Until::At(Timestamp::UNIX_EPOCH),
        Until::At(at(REFERENCE, 0)),
        Until::At(at(REFERENCE, 1)),
        Until::At(at(FOREVER_SECONDS, 999_999_998)),
        Until::At(Timestamp::MAX),
        Until::Forever,
    ];
    for (index, earlier) in ordered.iter().enumerate() {
        for later in &ordered[index + 1..] {
            assert!(earlier < later, "{earlier:?} is before {later:?}");
            assert!(later > earlier);
        }
        assert_eq!(earlier.cmp(earlier), std::cmp::Ordering::Equal);
    }
    assert_eq!(ordered.iter().max(), Some(&Until::Forever));
    assert_eq!(ordered.iter().min(), Some(&Until::At(Timestamp::MIN)));
    let seen: HashSet<Until> = [Until::Forever, Until::Forever, Until::At(at(0, 0))]
        .into_iter()
        .collect();
    assert_eq!(seen.len(), 2);
}

#[test]
fn an_end_is_past_from_its_reading_onwards() {
    let end = Until::At(at(REFERENCE, 500));
    assert!(!end.is_past(Timestamp::MIN));
    assert!(!end.is_past(at(REFERENCE - 1, 500)));
    assert!(!end.is_past(at(REFERENCE, 0)));
    assert!(!end.is_past(at(REFERENCE, 499)));
    assert!(end.is_past(at(REFERENCE, 500)));
    assert!(end.is_past(at(REFERENCE, 501)));
    assert!(end.is_past(at(REFERENCE + 1, 0)));
    assert!(end.is_past(Timestamp::MAX));

    // Before the epoch, where the seconds are negative.
    let early = Until::At(at(-1, 500_000_000));
    assert!(!early.is_past(at(-1, 499_999_999)));
    assert!(early.is_past(at(-1, 500_000_000)));
    assert!(early.is_past(Timestamp::UNIX_EPOCH));
    assert!(!early.is_past(at(-2, 999_999_999)));

    assert!(Until::At(Timestamp::MIN).is_past(Timestamp::MIN));
    assert!(Until::At(Timestamp::MAX).is_past(Timestamp::MAX));
    assert!(!Until::At(Timestamp::MAX).is_past(at(FOREVER_SECONDS, 999_999_998)));
}

#[test]
fn forever_is_never_past() {
    for now in [
        Timestamp::MIN,
        Timestamp::UNIX_EPOCH,
        at(REFERENCE, 0),
        at(FOREVER_SECONDS, 999_999_998),
        Timestamp::MAX,
    ] {
        assert!(!Until::Forever.is_past(now), "{now}");
    }
}

#[test]
fn a_lifetime_ends_at_the_start_plus_the_lifetime() {
    let now = at(REFERENCE, 250_000_000);
    assert_eq!(
        Until::after(now, Duration::from_secs(900)),
        Until::At(at(REFERENCE + 900, 250_000_000))
    );
    assert_eq!(
        Until::after(now, Duration::from_millis(750)),
        Until::At(at(REFERENCE + 1, 0))
    );
    assert_eq!(
        Until::after(now, Duration::new(1, 999_999_999)),
        Until::At(at(REFERENCE + 2, 249_999_999))
    );
    assert_eq!(Until::after(now, Duration::ZERO), Until::At(now));
    assert!(Until::after(now, Duration::ZERO).is_past(now));
    assert!(!Until::after(now, Duration::from_nanos(1)).is_past(now));
    // Before the epoch, and from the first reading of the range.
    assert_eq!(
        Until::after(at(-2, 500_000_000), Duration::from_millis(750)),
        Until::At(at(-1, 250_000_000))
    );
    assert_eq!(
        Until::after(Timestamp::MIN, Duration::from_secs(1)),
        Until::At(at(-8_334_601_228_799, 0))
    );
}

#[test]
fn a_lifetime_that_reaches_the_end_of_the_range_is_forever() {
    let now = at(REFERENCE, 0);
    let exact = to_the_end(now);
    assert_eq!(
        Until::after(now, exact - Duration::from_nanos(1)),
        Until::At(at(FOREVER_SECONDS, 999_999_998))
    );
    assert_eq!(Until::after(now, exact), Until::Forever);
    assert_eq!(
        Until::after(now, exact + Duration::from_nanos(1)),
        Until::Forever
    );
    assert_eq!(
        Until::after(now, exact + Duration::from_secs(1)),
        Until::Forever
    );
    assert_eq!(Until::after(Timestamp::MAX, Duration::ZERO), Until::Forever);
    assert_eq!(
        Until::after(Timestamp::MAX, Duration::from_nanos(1)),
        Until::Forever
    );
    assert_eq!(
        Until::after(at(FOREVER_SECONDS, 999_999_998), Duration::ZERO),
        Until::At(at(FOREVER_SECONDS, 999_999_998))
    );
    assert_eq!(
        Until::after(Timestamp::MIN, to_the_end(Timestamp::MIN)),
        Until::Forever
    );
    assert_eq!(
        Until::after(
            Timestamp::MIN,
            to_the_end(Timestamp::MIN) - Duration::from_nanos(1)
        ),
        Until::At(at(FOREVER_SECONDS, 999_999_998))
    );
}

#[test]
fn a_lifetime_longer_than_any_signed_span_is_forever() {
    let longest_signed = Duration::new(9_223_372_036_854_775_807, 999_999_999);
    for now in [
        Timestamp::MIN,
        Timestamp::UNIX_EPOCH,
        at(REFERENCE, 0),
        Timestamp::MAX,
    ] {
        for lifetime in [
            longest_signed,
            Duration::new(9_223_372_036_854_775_808, 0),
            Duration::from_secs(u64::MAX),
            Duration::MAX,
        ] {
            assert_eq!(
                Until::after(now, lifetime),
                Until::Forever,
                "{now} and {lifetime:?}"
            );
        }
    }
}

#[test]
fn a_signed_lifetime_converts_first_and_a_negative_one_is_refused() {
    let now = at(REFERENCE, 0);
    let end =
        Duration::try_from(SignedDuration::minutes(15)).map(|lifetime| Until::after(now, lifetime));
    assert_eq!(end, Ok(Until::At(at(REFERENCE + 900, 0))));
    let never = Duration::try_from(SignedDuration::MAX).map(|lifetime| Until::after(now, lifetime));
    assert_eq!(never, Ok(Until::Forever));
    for negative in [
        SignedDuration::seconds(-60),
        SignedDuration::nanoseconds(-1),
        SignedDuration::MIN,
    ] {
        assert_eq!(
            Duration::try_from(negative).map(|lifetime| Until::after(now, lifetime)),
            Err(TimeError::Negative),
            "{negative:?}"
        );
    }
}

#[test]
fn exactly_the_stored_value_reads_as_forever() {
    assert_eq!(Until::from_timestamp(Until::LEGACY_FOREVER), Until::Forever);
    assert_eq!(Until::from_timestamp(Timestamp::MAX), Until::Forever);
    for stored in [
        at(FOREVER_SECONDS, 999_999_998),
        at(FOREVER_SECONDS, 0),
        at(FOREVER_SECONDS - 1, 999_999_999),
        at(REFERENCE, 0),
        Timestamp::UNIX_EPOCH,
        Timestamp::MIN,
    ] {
        assert_eq!(Until::from_timestamp(stored), Until::At(stored), "{stored}");
        assert_eq!(Until::from_timestamp(stored).to_timestamp(), stored);
    }
    assert_eq!(Until::Forever.to_timestamp(), Until::LEGACY_FOREVER);
    assert_eq!(
        Until::from_timestamp(Until::Forever.to_timestamp()),
        Until::Forever
    );
    // An end at the stored value itself is written as `Forever` is, and
    // reads back as `Forever`.
    assert_eq!(
        Until::from_timestamp(Until::At(Timestamp::MAX).to_timestamp()),
        Until::Forever
    );
}

#[test]
fn the_stored_text_of_forever_reads_as_forever() {
    let stored: Timestamp = "+262142-12-31T23:59:59.999999999Z"
        .parse()
        .expect("the text earlier releases stored");
    assert_eq!(Until::from_timestamp(stored), Until::Forever);
    assert_eq!(
        Until::Forever.to_timestamp().to_rfc3339(),
        "+262142-12-31T23:59:59.999999999Z"
    );
    let near: Timestamp = "+262142-12-31T23:59:59.999999998Z"
        .parse()
        .expect("a reading inside the range");
    assert_eq!(Until::from_timestamp(near), Until::At(near));
}

#[test]
fn the_stored_second_of_forever_reads_as_forever() {
    assert_eq!(
        Until::from_unix_seconds(FOREVER_SECONDS),
        Some(Until::Forever)
    );
    assert_eq!(
        Until::from_unix_seconds(FOREVER_SECONDS - 1),
        Some(Until::At(at(FOREVER_SECONDS - 1, 0)))
    );
    assert_eq!(Until::from_unix_seconds(FOREVER_SECONDS + 1), None);
    assert_eq!(Until::from_unix_seconds(i64::MAX), None);
    assert_eq!(
        Until::from_unix_seconds(REFERENCE),
        Some(Until::At(at(REFERENCE, 0)))
    );
    assert_eq!(
        Until::from_unix_seconds(0),
        Some(Until::At(Timestamp::UNIX_EPOCH))
    );
    assert_eq!(
        Until::from_unix_seconds(-8_334_601_228_800),
        Some(Until::At(Timestamp::MIN))
    );
    assert_eq!(Until::from_unix_seconds(-8_334_601_228_801), None);
    assert_eq!(Until::from_unix_seconds(i64::MIN), None);

    assert_eq!(Until::Forever.unix_seconds(), FOREVER_SECONDS);
    assert_eq!(
        Until::At(at(REFERENCE, 999_999_999)).unix_seconds(),
        REFERENCE
    );
    assert_eq!(Until::At(at(-1, 500_000_000)).unix_seconds(), -1);
    // The last second of the range is the second of `Forever`.
    let last_second = Until::At(at(FOREVER_SECONDS, 5));
    assert_eq!(last_second.unix_seconds(), FOREVER_SECONDS);
    assert_eq!(
        Until::from_unix_seconds(last_second.unix_seconds()),
        Some(Until::Forever)
    );
}

#[test]
fn an_end_tells_whether_it_comes() {
    let end = at(REFERENCE, 1);
    assert_eq!(Until::At(end).at(), Some(end));
    assert_eq!(Until::Forever.at(), None);
    assert!(Until::Forever.is_forever());
    assert!(!Until::At(end).is_forever());
    assert!(!Until::At(Timestamp::MAX).is_forever());
}

#[test]
fn an_end_is_computed_in_constant_code() {
    const START: Timestamp = Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap();
    const END: Until = Until::after(START, Duration::from_secs(3_600));
    const NEVER: Until = Until::after(START, Duration::MAX);
    const {
        assert!(!END.is_past(START));
        assert!(NEVER.is_forever());
        assert!(!NEVER.is_past(Timestamp::MAX));
    }
    assert_eq!(END, Until::At(at(REFERENCE + 3_600, 0)));
    assert_eq!(NEVER, Until::Forever);
}
