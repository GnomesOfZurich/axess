//! A UTC wall-clock reading.

use crate::date::{MAX_DAYS, MIN_DAYS, UtcDate};
use crate::duration::SignedDuration;
use crate::error::TimeError;
use std::time::{Duration, SystemTime};

/// Seconds in a day.
const SECONDS_PER_DAY: i64 = 86_400;
/// Nanoseconds in a second.
const NANOS_PER_SECOND: u32 = 1_000_000_000;
/// The first second of the range, as Unix seconds.
const MIN_SECONDS: i64 = MIN_DAYS * SECONDS_PER_DAY;
/// The last second of the range, as Unix seconds.
const MAX_SECONDS: i64 = MAX_DAYS * SECONDS_PER_DAY + (SECONDS_PER_DAY - 1);

/// A reading of the UTC wall clock: a point on the time line, to the
/// nanosecond.
///
/// The value is a count of seconds since 1970-01-01T00:00:00Z, rounded down,
/// and the nanoseconds past that second. Every minute has 60 seconds: there
/// is no leap second. Readings order from the earliest to the latest.
///
/// # Range
///
/// From [`Timestamp::MIN`], `-262143-01-01T00:00:00Z`, to
/// [`Timestamp::MAX`], `+262142-12-31T23:59:59.999999999Z`. Every
/// constructor refuses a value outside it, so every stored value reads as
/// itself. The two ends are the ends of the range and mean nothing else: an
/// end that may never come is an [`Until`](crate::Until).
///
/// # Arithmetic
///
/// There is no `+` or `-` with a span, since an operator could only panic
/// past the range. [`Timestamp::checked_add`] and [`Timestamp::checked_sub`]
/// return `None` there, and [`Timestamp::since`] is defined for every pair
/// of readings.
///
/// ```
/// use axess_clock::{SignedDuration, Timestamp};
///
/// const START: Timestamp = Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap();
///
/// assert_eq!(START.unix_seconds(), 1_767_225_600);
/// let later = START
///     .checked_add(SignedDuration::minutes(5))
///     .expect("inside the range");
/// assert_eq!(later.to_rfc3339(), "2026-01-01T00:05:00Z");
/// assert_eq!(later.since(START), SignedDuration::seconds(300));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    secs: i64,
    // Below one second, so the derived ordering is the ordering in time.
    nanos: u32,
}

impl Timestamp {
    /// 1970-01-01T00:00:00Z, the reading Unix time counts from.
    pub const UNIX_EPOCH: Timestamp = Timestamp { secs: 0, nanos: 0 };

    /// The earliest reading, `-262143-01-01T00:00:00Z`: Unix second
    /// -8,334,601,228,800.
    pub const MIN: Timestamp = Timestamp {
        secs: MIN_SECONDS,
        nanos: 0,
    };

    /// The latest reading, `+262142-12-31T23:59:59.999999999Z`: the last
    /// nanosecond of Unix second 8,210,266,876,799.
    pub const MAX: Timestamp = Timestamp {
        secs: MAX_SECONDS,
        nanos: NANOS_PER_SECOND - 1,
    };

    /// The reading `nanos` nanoseconds past the Unix second `secs`, or
    /// `None` when `nanos` is a whole second or more, or the reading is
    /// outside the range.
    ///
    /// The seconds are rounded down, also before 1970: half a second before
    /// the epoch is second -1 and 500,000,000 nanoseconds.
    pub const fn new(secs: i64, nanos: u32) -> Option<Timestamp> {
        if secs < MIN_SECONDS || secs > MAX_SECONDS || nanos >= NANOS_PER_SECOND {
            return None;
        }
        Some(Timestamp { secs, nanos })
    }

    /// The reading at a count of whole seconds since the Unix epoch, or
    /// `None` outside the range.
    pub const fn from_unix_seconds(seconds: i64) -> Option<Timestamp> {
        Timestamp::new(seconds, 0)
    }

    /// The reading at a count of milliseconds since the Unix epoch, or
    /// `None` outside the range.
    pub const fn from_unix_millis(milliseconds: i64) -> Option<Timestamp> {
        Timestamp::new(
            milliseconds.div_euclid(1_000),
            // 0 to 999, so the product is below one second.
            milliseconds.rem_euclid(1_000) as u32 * 1_000_000,
        )
    }

    /// The reading at a count of microseconds since the Unix epoch, or
    /// `None` outside the range.
    pub const fn from_unix_micros(microseconds: i64) -> Option<Timestamp> {
        Timestamp::new(
            microseconds.div_euclid(1_000_000),
            // 0 to 999,999, so the product is below one second.
            microseconds.rem_euclid(1_000_000) as u32 * 1_000,
        )
    }

    /// The reading at a count of nanoseconds since the Unix epoch, or
    /// `None` outside the range.
    pub const fn from_unix_nanos(nanoseconds: i128) -> Option<Timestamp> {
        let secs = nanoseconds.div_euclid(NANOS_PER_SECOND as i128);
        if secs < MIN_SECONDS as i128 || secs > MAX_SECONDS as i128 {
            return None;
        }
        Some(Timestamp {
            secs: secs as i64,
            nanos: nanoseconds.rem_euclid(NANOS_PER_SECOND as i128) as u32,
        })
    }

    /// The reading at a date and a time of day in UTC, or `None` when the
    /// calendar has no such day, the hour is past 23, the minute or the
    /// second is past 59, or the year is outside the range.
    ///
    /// A `const fn`, so a fixed reading is checked when the code is
    /// compiled:
    ///
    /// ```
    /// use axess_clock::Timestamp;
    ///
    /// const NEW_YEAR: Timestamp = Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap();
    /// assert_eq!(NEW_YEAR.to_rfc3339(), "2026-01-01T00:00:00Z");
    /// assert_eq!(Timestamp::from_utc(2026, 2, 30, 0, 0, 0), None);
    /// ```
    pub const fn from_utc(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Option<Timestamp> {
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        match UtcDate::new(year, month, day) {
            Some(date) => Timestamp::new(
                date.days_since_epoch() * SECONDS_PER_DAY
                    + hour as i64 * 3_600
                    + minute as i64 * 60
                    + second as i64,
                0,
            ),
            None => None,
        }
    }

    /// Whole seconds since the Unix epoch, rounded down: a reading in the
    /// second before the epoch is in second -1.
    pub const fn unix_seconds(self) -> i64 {
        self.secs
    }

    /// Whole milliseconds since the Unix epoch, rounded down, also before
    /// the epoch.
    pub const fn unix_millis(self) -> i64 {
        // The range is below 2^43 seconds in size, so the product fits.
        self.secs * 1_000 + (self.nanos / 1_000_000) as i64
    }

    /// Whole microseconds since the Unix epoch, rounded down, also before
    /// the epoch.
    pub const fn unix_micros(self) -> i64 {
        // The range is below 2^43 seconds in size, so the product is below
        // 2^63.
        self.secs * 1_000_000 + (self.nanos / 1_000) as i64
    }

    /// Nanoseconds since the Unix epoch. An `i128`, since the range is
    /// wider than an `i64` of nanoseconds, which ends in the year 2262.
    pub const fn unix_nanos(self) -> i128 {
        self.secs as i128 * NANOS_PER_SECOND as i128 + self.nanos as i128
    }

    /// The nanoseconds past the whole second, 0 to 999,999,999.
    pub const fn subsec_nanos(self) -> u32 {
        self.nanos
    }

    /// The calendar day in UTC the reading falls on.
    pub const fn utc_date(self) -> UtcDate {
        // A reading is inside the range, so its day is a day of the range.
        UtcDate::on_day_of_range(self.secs.div_euclid(SECONDS_PER_DAY))
    }

    /// The reading as a date and a time of day in UTC: the date, the hour
    /// (0 to 23), the minute and the second (0 to 59 each) and the
    /// nanosecond (0 to 999,999,999).
    pub const fn to_utc(self) -> (UtcDate, u8, u8, u8, u32) {
        // 0 to 86,399, so each part fits its type.
        let second_of_day = self.secs.rem_euclid(SECONDS_PER_DAY);
        (
            self.utc_date(),
            (second_of_day / 3_600) as u8,
            (second_of_day % 3_600 / 60) as u8,
            (second_of_day % 60) as u8,
            self.nanos,
        )
    }

    /// The reading a span later (earlier, for a negative span), or `None`
    /// when that is outside the range.
    pub const fn checked_add(self, span: SignedDuration) -> Option<Timestamp> {
        // A sum of seconds that overflows is further outside the range than
        // any fraction of a second could bring back.
        let Some(secs) = self.secs.checked_add(span.whole_seconds()) else {
            return None;
        };
        // Both parts are below one second in size.
        Timestamp::carried(secs, self.nanos as i64 + span.subsec_nanos() as i64)
    }

    /// The reading a span earlier (later, for a negative span), or `None`
    /// when that is outside the range.
    pub const fn checked_sub(self, span: SignedDuration) -> Option<Timestamp> {
        let Some(secs) = self.secs.checked_sub(span.whole_seconds()) else {
            return None;
        };
        Timestamp::carried(secs, self.nanos as i64 - span.subsec_nanos() as i64)
    }

    /// The reading at `secs` seconds and `nanos` nanoseconds, where `nanos`
    /// is within one second either side of the range of a fraction.
    const fn carried(secs: i64, nanos: i64) -> Option<Timestamp> {
        let whole = NANOS_PER_SECOND as i64;
        let (carry, nanos) = if nanos < 0 {
            (-1, nanos + whole)
        } else if nanos >= whole {
            (1, nanos - whole)
        } else {
            (0, nanos)
        };
        match secs.checked_add(carry) {
            Some(secs) => Timestamp::new(secs, nanos as u32),
            None => None,
        }
    }

    /// The reading a value of the system's clock type stands for: itself
    /// where a `Timestamp` holds it, and the nearer end of the range,
    /// [`Timestamp::MIN`] or [`Timestamp::MAX`], where it does not.
    ///
    /// Defined for every system time, so code that must have a reading and
    /// has no way to refuse (a log stamp, an error's time) takes this one.
    /// `Timestamp::try_from(time)` is the conversion that refuses a time
    /// outside the range. Neither reads a clock: the time is the caller's.
    ///
    /// ```
    /// use axess_clock::Timestamp;
    /// use std::time::{Duration, SystemTime};
    ///
    /// let a_minute_in = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    /// assert_eq!(
    ///     Timestamp::from_system_time(a_minute_in),
    ///     Timestamp::from_unix_seconds(60).expect("inside the range"),
    /// );
    /// ```
    pub fn from_system_time(time: SystemTime) -> Timestamp {
        match Timestamp::try_from(time) {
            Ok(reading) => reading,
            // Outside the range: after it when the time is after 1970, and
            // before it otherwise.
            Err(_) => match time.duration_since(SystemTime::UNIX_EPOCH) {
                Ok(_) => Timestamp::MAX,
                Err(_) => Timestamp::MIN,
            },
        }
    }

    /// The span from an earlier reading to this one: negative when
    /// `earlier` is in fact the later of the two. Defined for every pair of
    /// readings.
    pub const fn since(self, earlier: Timestamp) -> SignedDuration {
        // The range is below 2^44 seconds from end to end, so the difference
        // fits.
        SignedDuration::from_mixed(
            self.secs - earlier.secs,
            self.nanos as i32 - earlier.nanos as i32,
        )
    }
}

/// The reading of the system's clock type as a `Timestamp`. Refused with
/// [`TimeError::OutOfRange`] outside the range of a `Timestamp`;
/// [`Timestamp::from_system_time`] takes the nearer end of the range there.
impl TryFrom<SystemTime> for Timestamp {
    type Error = TimeError;

    fn try_from(time: SystemTime) -> Result<Timestamp, TimeError> {
        let (secs, nanos) = match time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(after) => (
                i64::try_from(after.as_secs()).map_err(|_| TimeError::OutOfRange)?,
                after.subsec_nanos(),
            ),
            Err(before) => {
                // The distance back from the epoch: the second holding the
                // reading is the one at or below it.
                let before = before.duration();
                let whole = i64::try_from(before.as_secs()).map_err(|_| TimeError::OutOfRange)?;
                match before.subsec_nanos() {
                    0 => (-whole, 0),
                    nanos => (-whole - 1, NANOS_PER_SECOND - nanos),
                }
            }
        };
        Timestamp::new(secs, nanos).ok_or(TimeError::OutOfRange)
    }
}

/// A `Timestamp` as the system's clock type. Refused with
/// [`TimeError::OutOfRange`] where that type cannot hold the reading: its
/// range is the platform's, and narrower than a `Timestamp`'s on some. A
/// platform whose clock type counts in steps longer than a nanosecond
/// rounds the reading down to its step.
impl TryFrom<Timestamp> for SystemTime {
    type Error = TimeError;

    fn try_from(at: Timestamp) -> Result<SystemTime, TimeError> {
        let fraction = Duration::new(0, at.nanos);
        let second = if at.secs >= 0 {
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(at.secs.unsigned_abs()))
        } else {
            SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(at.secs.unsigned_abs()))
        };
        second
            .and_then(|second| second.checked_add(fraction))
            .ok_or(TimeError::OutOfRange)
    }
}

#[cfg(test)]
mod tests;
