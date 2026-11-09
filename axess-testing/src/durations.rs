//! A table of extreme durations for tests of configured lifetimes: the
//! values an operator's typo, or a "remember for ever" intent, puts into a
//! TTL, and which an unchecked `now + ttl` turns into a panic.

use std::time::Duration;

/// One extreme duration and what it is, for an assertion message.
#[derive(Debug, Clone, Copy)]
pub struct ExtremeDuration {
    /// What the value is.
    pub name: &'static str,
    /// The value.
    pub value: Duration,
}

/// Zero, the smallest step, the largest span `chrono::Duration` converts
/// (`i64::MAX` milliseconds), the first span past it, and [`Duration::MAX`].
///
/// The middle one passes `chrono::Duration::from_std` and still overflows
/// when added to a date, which is the shape of bug a clamp that only
/// handles the `from_std` failure misses.
pub fn extreme_durations() -> Vec<ExtremeDuration> {
    vec![
        ExtremeDuration {
            name: "zero",
            value: Duration::ZERO,
        },
        ExtremeDuration {
            name: "one nanosecond",
            value: Duration::from_nanos(1),
        },
        ExtremeDuration {
            name: "largest chrono-convertible span",
            value: Duration::from_millis(i64::MAX as u64),
        },
        ExtremeDuration {
            name: "first span past chrono's range",
            value: Duration::from_millis(i64::MAX as u64 + 1),
        },
        ExtremeDuration {
            name: "Duration::MAX",
            value: Duration::MAX,
        },
    ]
}
