//! The issued-at window shared by JWT and back-channel logout token checks.

use std::time::Duration;

/// Whether a token issued at `iat` is acceptable at `now`, both Unix seconds:
/// issued no more than `max_future` ahead of `now` (clock skew) and no more
/// than `max_age` before it. An `iat` so far from `now` that the difference
/// does not fit an `i64` is outside the window, never an overflow.
///
/// The age is a whole count of seconds, and a whole count is within a span
/// exactly when it is within the span's whole seconds, so each span is read
/// as its whole seconds.
pub(crate) fn iat_within(iat: i64, now: i64, max_future: Duration, max_age: Duration) -> bool {
    let whole = |span: Duration| i64::try_from(span.as_secs()).unwrap_or(i64::MAX);
    now.checked_sub(iat)
        .is_some_and(|age| (-whole(max_future)..=whole(max_age)).contains(&age))
}

#[cfg(test)]
mod tests {
    use super::iat_within;
    use std::time::Duration;

    /// A span with a fraction admits the whole seconds it holds and no more:
    /// a 300.5 s age bound admits 300 s and refuses 301 s, and a 60.999 s
    /// skew admits an `iat` 60 s ahead and refuses one 61 s ahead.
    #[test]
    fn a_span_counts_its_whole_seconds() {
        let (future, age) = (
            Duration::from_millis(60_999),
            Duration::from_millis(300_500),
        );
        let now = 1_700_000_000;
        assert!(iat_within(now - 300, now, future, age));
        assert!(!iat_within(now - 301, now, future, age));
        assert!(iat_within(now + 60, now, future, age));
        assert!(!iat_within(now + 61, now, future, age));
    }

    /// A span past an `i64` of seconds is as wide as one, and a difference
    /// that does not fit an `i64` is outside the window, never an overflow.
    #[test]
    fn the_extremes_neither_overflow_nor_admit_too_much() {
        assert!(iat_within(0, i64::MAX, Duration::ZERO, Duration::MAX));
        assert!(!iat_within(
            i64::MIN,
            i64::MAX,
            Duration::MAX,
            Duration::MAX
        ));
        assert!(iat_within(i64::MAX, 0, Duration::MAX, Duration::ZERO));
    }
}
