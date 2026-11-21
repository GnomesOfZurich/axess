//! An exact signed span of time.

use crate::error::TimeError;
use std::fmt;
use std::time::Duration;

/// Nanoseconds in a second.
const NANOS_PER_SECOND: i128 = 1_000_000_000;

/// An exact signed span of time: a count of seconds and nanoseconds, both
/// negative for a span that runs backwards.
///
/// The span is elapsed time, with no calendar in it. A minute is 60 seconds,
/// an hour 3,600 and a day exactly 86,400 seconds. Spans in calendar units
/// (months, years, business days) are not this type.
///
/// The range is the whole of an `i64` of seconds with a fraction below one
/// second on either side, from [`SignedDuration::MIN`] to
/// [`SignedDuration::MAX`]. Arithmetic is checked: a result outside the
/// range is `None`, never a wrapped or clamped value. Spans order from the
/// most negative to the most positive.
///
/// # Text
///
/// `Display` writes the span as a count of seconds in the ISO 8601 form
/// earlier releases printed: `PT7200S`, `PT1.5S`, `-PT0.25S`, and `P0D` for
/// the span of no time. The fraction has the fewest digits that hold it.
/// The text is for a message or a log line; no reader for it is provided.
///
/// ```
/// use axess_clock::SignedDuration;
///
/// let half_a_minute = SignedDuration::seconds(30);
/// assert_eq!(half_a_minute.checked_add(half_a_minute), Some(SignedDuration::minutes(1)));
/// assert!(SignedDuration::milliseconds(-500).is_negative());
/// assert_eq!(SignedDuration::days(1), SignedDuration::hours(24));
/// ```
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignedDuration {
    secs: i64,
    // Below one second in size, and never of the opposite sign to `secs`, so
    // the derived ordering is the ordering of the spans.
    nanos: i32,
}

impl SignedDuration {
    /// The span of no time.
    pub const ZERO: SignedDuration = SignedDuration { secs: 0, nanos: 0 };

    /// The most negative span: `i64::MIN` seconds and 999,999,999 nanoseconds
    /// more.
    pub const MIN: SignedDuration = SignedDuration {
        secs: i64::MIN,
        nanos: -999_999_999,
    };

    /// The longest span: `i64::MAX` seconds and 999,999,999 nanoseconds.
    pub const MAX: SignedDuration = SignedDuration {
        secs: i64::MAX,
        nanos: 999_999_999,
    };

    /// A span of whole seconds.
    pub const fn seconds(seconds: i64) -> SignedDuration {
        SignedDuration {
            secs: seconds,
            nanos: 0,
        }
    }

    /// A span of whole minutes of 60 seconds.
    pub const fn minutes(minutes: i32) -> SignedDuration {
        SignedDuration::seconds(minutes as i64 * 60)
    }

    /// A span of whole hours of 3,600 seconds.
    pub const fn hours(hours: i32) -> SignedDuration {
        SignedDuration::seconds(hours as i64 * 3_600)
    }

    /// A span of whole days. A day here is exactly 86,400 seconds: elapsed
    /// time, not a step of the calendar.
    pub const fn days(days: i32) -> SignedDuration {
        SignedDuration::seconds(days as i64 * 86_400)
    }

    /// A span of milliseconds.
    pub const fn milliseconds(milliseconds: i64) -> SignedDuration {
        SignedDuration {
            secs: milliseconds / 1_000,
            // Below 1,000 in size, so the product fits.
            nanos: (milliseconds % 1_000) as i32 * 1_000_000,
        }
    }

    /// A span of microseconds.
    pub const fn microseconds(microseconds: i64) -> SignedDuration {
        SignedDuration {
            secs: microseconds / 1_000_000,
            // Below 1,000,000 in size, so the product fits.
            nanos: (microseconds % 1_000_000) as i32 * 1_000,
        }
    }

    /// A span of nanoseconds.
    pub const fn nanoseconds(nanoseconds: i64) -> SignedDuration {
        SignedDuration {
            secs: nanoseconds / 1_000_000_000,
            nanos: (nanoseconds % 1_000_000_000) as i32,
        }
    }

    /// The span of a count of seconds and a count of nanoseconds below one
    /// second in size, whatever their signs: one second and minus a quarter
    /// is three quarters of a second.
    pub(crate) const fn from_mixed(secs: i64, nanos: i32) -> SignedDuration {
        if secs > 0 && nanos < 0 {
            SignedDuration {
                secs: secs - 1,
                nanos: nanos + 1_000_000_000,
            }
        } else if secs < 0 && nanos > 0 {
            SignedDuration {
                secs: secs + 1,
                nanos: nanos - 1_000_000_000,
            }
        } else {
            SignedDuration { secs, nanos }
        }
    }

    /// An unsigned span as a signed one, or `None` past
    /// [`SignedDuration::MAX`].
    pub(crate) const fn from_unsigned(span: Duration) -> Option<SignedDuration> {
        if span.as_secs() > i64::MAX as u64 {
            return None;
        }
        Some(SignedDuration {
            secs: span.as_secs() as i64,
            // Below one second, so it fits.
            nanos: span.subsec_nanos() as i32,
        })
    }

    /// The span as one count of nanoseconds.
    const fn total_nanoseconds(self) -> i128 {
        self.secs as i128 * NANOS_PER_SECOND + self.nanos as i128
    }

    /// The span of a count of nanoseconds, or `None` outside the range.
    const fn from_total_nanoseconds(total: i128) -> Option<SignedDuration> {
        let secs = total / NANOS_PER_SECOND;
        if secs < i64::MIN as i128 || secs > i64::MAX as i128 {
            return None;
        }
        Some(SignedDuration {
            secs: secs as i64,
            // The remainder is below one second in size and has the sign of
            // the total.
            nanos: (total % NANOS_PER_SECOND) as i32,
        })
    }

    /// The size of the span, without its sign, as the unsigned span of the
    /// standard library.
    ///
    /// Named as the integer method that returns the unsigned type is: the
    /// unsigned span holds the size of every signed span,
    /// [`SignedDuration::MIN`] included, which a signed span does not.
    pub const fn unsigned_abs(self) -> Duration {
        Duration::new(self.secs.unsigned_abs(), self.nanos.unsigned_abs())
    }

    /// Whether the span runs backwards. The span of no time does not.
    pub const fn is_negative(self) -> bool {
        self.secs < 0 || self.nanos < 0
    }

    /// Whether this is the span of no time.
    pub const fn is_zero(self) -> bool {
        self.secs == 0 && self.nanos == 0
    }

    /// The whole seconds of the span, rounded towards zero: minus one and a
    /// half seconds has -1.
    pub const fn whole_seconds(self) -> i64 {
        self.secs
    }

    /// The whole milliseconds of the span, rounded towards zero.
    pub const fn whole_milliseconds(self) -> i128 {
        self.secs as i128 * 1_000 + (self.nanos / 1_000_000) as i128
    }

    /// The part of the span below its whole seconds, in nanoseconds: below
    /// one second in size, and negative in a span that runs backwards.
    pub const fn subsec_nanos(self) -> i32 {
        self.nanos
    }

    /// The sum of two spans, or `None` outside the range.
    pub const fn checked_add(self, other: SignedDuration) -> Option<SignedDuration> {
        SignedDuration::from_total_nanoseconds(self.total_nanoseconds() + other.total_nanoseconds())
    }

    /// This span less another, or `None` outside the range.
    pub const fn checked_sub(self, other: SignedDuration) -> Option<SignedDuration> {
        SignedDuration::from_total_nanoseconds(self.total_nanoseconds() - other.total_nanoseconds())
    }

    /// The span taken `factor` times, or `None` outside the range.
    pub const fn checked_mul(self, factor: i32) -> Option<SignedDuration> {
        // Below 2^94 in size times below 2^32 in size: inside an `i128`.
        SignedDuration::from_total_nanoseconds(self.total_nanoseconds() * factor as i128)
    }

    /// The span divided into `divisor` equal parts, or `None` when the
    /// divisor is zero.
    ///
    /// The quotient is exact: the whole span is divided at once, in
    /// nanoseconds, and rounded towards zero, so it is never a nanosecond
    /// off, as a division of the seconds and the fraction apart can be. A
    /// third of one second is 333,333,333 nanoseconds, and a third of minus
    /// one second is the same span backwards. A negative divisor turns the
    /// span round. No quotient is outside the range.
    ///
    /// ```
    /// use axess_clock::SignedDuration;
    ///
    /// let lifetime = SignedDuration::hours(1);
    /// assert_eq!(lifetime.checked_div(100), Some(SignedDuration::seconds(36)));
    /// assert_eq!(lifetime.checked_div(0), None);
    /// ```
    pub const fn checked_div(self, divisor: i32) -> Option<SignedDuration> {
        if divisor == 0 {
            return None;
        }
        // A quotient is no larger than the span it is taken from.
        SignedDuration::from_total_nanoseconds(self.total_nanoseconds() / divisor as i128)
    }
}

/// The span as a count of seconds in the ISO 8601 form: `PT7200S`, with a
/// fraction of the fewest digits that hold it (`PT1.5S`), a leading `-` for
/// a span that runs backwards (`-PT0.25S`), and `P0D` for the span of no
/// time. Width, fill and precision in the format string are not applied.
impl fmt::Display for SignedDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return f.write_str("P0D");
        }
        let size = self.unsigned_abs();
        let sign = if self.is_negative() { "-" } else { "" };
        write!(f, "{sign}PT{}", size.as_secs())?;
        // The fraction without its trailing zeros: nine digits less one for
        // each zero dropped.
        let mut fraction = size.subsec_nanos();
        if fraction > 0 {
            let mut digits = 9;
            while fraction.is_multiple_of(10) {
                fraction /= 10;
                digits -= 1;
            }
            write!(f, ".{fraction:0digits$}")?;
        }
        f.write_str("S")
    }
}

/// An unsigned span as a signed one. Refused with
/// [`TimeError::OutOfRange`] past [`SignedDuration::MAX`].
impl TryFrom<Duration> for SignedDuration {
    type Error = TimeError;

    fn try_from(span: Duration) -> Result<SignedDuration, TimeError> {
        SignedDuration::from_unsigned(span).ok_or(TimeError::OutOfRange)
    }
}

/// A signed span as an unsigned one. A span that runs backwards is refused
/// with [`TimeError::Negative`].
impl TryFrom<SignedDuration> for Duration {
    type Error = TimeError;

    fn try_from(span: SignedDuration) -> Result<Duration, TimeError> {
        if span.is_negative() {
            Err(TimeError::Negative)
        } else {
            Ok(span.unsigned_abs())
        }
    }
}

#[cfg(test)]
mod tests;
