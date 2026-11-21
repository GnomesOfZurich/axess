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

/// Zero, the smallest step, the largest span `chrono::Duration` converted
/// (`i64::MAX` milliseconds) and the first span past it, the longest span
/// `axess_clock::SignedDuration` holds (`i64::MAX` seconds and a fraction)
/// and the first span past it, and [`Duration::MAX`].
///
/// Each of the two "largest" values converts to its signed span and still
/// runs past the range of a reading when added to one, which is the shape
/// of bug a clamp that only handles the failed conversion misses.
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
            name: "longest signed span",
            value: Duration::new(i64::MAX as u64, 999_999_999),
        },
        ExtremeDuration {
            name: "first span past the longest signed span",
            value: Duration::from_secs(i64::MAX as u64 + 1),
        },
        ExtremeDuration {
            name: "Duration::MAX",
            value: Duration::MAX,
        },
    ]
}
