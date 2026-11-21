//! A calendar day in UTC, and the conversion between a day count and a date.

use crate::error::TimeError;
use std::fmt;
use std::str::FromStr;

/// The earliest year a [`UtcDate`] holds.
pub(crate) const MIN_YEAR: i32 = -262_143;
/// The latest year a [`UtcDate`] holds.
pub(crate) const MAX_YEAR: i32 = 262_142;
/// The day count of [`UtcDate::MIN`], in days since 1970-01-01.
pub(crate) const MIN_DAYS: i64 = days_from_civil(MIN_YEAR as i64, 1, 1);
/// The day count of [`UtcDate::MAX`], in days since 1970-01-01.
pub(crate) const MAX_DAYS: i64 = days_from_civil(MAX_YEAR as i64, 12, 31);

/// Days in the 400-year cycle of the Gregorian calendar.
const DAYS_PER_ERA: i64 = 146_097;
/// Days from 0000-03-01, the start of the cycle the conversion counts in, to
/// 1970-01-01.
const DAYS_TO_EPOCH: i64 = 719_468;

/// A calendar day in UTC: a year, a month and a day of the proleptic
/// Gregorian calendar.
///
/// The year 0 exists and is a leap year; the year before it is -1. The range
/// is `-262143-01-01` to `+262142-12-31`, the days a [`Timestamp`] can fall
/// on. Dates order by year, then month, then day.
///
/// A date is a projection of a [`Timestamp`]: it has no arithmetic. It is
/// written as `YYYY-MM-DD`, with a signed year outside 0 to 9999.
///
/// ```
/// use axess_clock::UtcDate;
///
/// let date = UtcDate::new(2026, 2, 28).expect("a day of the calendar");
/// assert_eq!((date.year(), date.month(), date.day()), (2026, 2, 28));
/// assert_eq!(date.to_string(), "2026-02-28");
/// assert_eq!(UtcDate::new(2026, 2, 29), None);
/// ```
///
/// [`Timestamp`]: crate::Timestamp
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcDate {
    year: i32,
    month: u8,
    day: u8,
}

impl UtcDate {
    /// The earliest date, `-262143-01-01`.
    pub const MIN: UtcDate = UtcDate {
        year: MIN_YEAR,
        month: 1,
        day: 1,
    };

    /// The latest date, `+262142-12-31`.
    pub const MAX: UtcDate = UtcDate {
        year: MAX_YEAR,
        month: 12,
        day: 31,
    };

    /// The date of a year, a month (1 to 12) and a day of that month (1 to
    /// 28, 29, 30 or 31), or `None` when the calendar has no such day or the
    /// year is outside the range.
    pub const fn new(year: i32, month: u8, day: u8) -> Option<UtcDate> {
        if year < MIN_YEAR || year > MAX_YEAR || month < 1 || month > 12 {
            return None;
        }
        if day < 1 || day > days_in_month(year, month) {
            return None;
        }
        Some(UtcDate { year, month, day })
    }

    /// The year. The year before year 1 is 0, and the one before that is -1.
    pub const fn year(self) -> i32 {
        self.year
    }

    /// The month, 1 to 12.
    pub const fn month(self) -> u8 {
        self.month
    }

    /// The day of the month, 1 to 31.
    pub const fn day(self) -> u8 {
        self.day
    }

    /// The count of whole days from 1970-01-01 to this date: 0 for that day,
    /// 1 for 1970-01-02 and -1 for 1969-12-31. Defined for every date, from
    /// -96,465,292 for [`UtcDate::MIN`] to 95,026,236 for [`UtcDate::MAX`].
    ///
    /// It is the day count a [`Timestamp`] of that date has in its Unix
    /// seconds: the seconds divided by 86,400 and rounded down.
    /// [`UtcDate::from_days_since_epoch`] is the way back.
    ///
    /// ```
    /// use axess_clock::UtcDate;
    ///
    /// let day = UtcDate::new(2026, 1, 1).expect("a day of the calendar");
    /// assert_eq!(day.days_since_epoch(), 20_454);
    /// assert_eq!(UtcDate::from_days_since_epoch(20_454), Some(day));
    /// ```
    ///
    /// [`Timestamp`]: crate::Timestamp
    pub const fn days_since_epoch(self) -> i64 {
        days_from_civil(self.year as i64, self.month as i64, self.day as i64)
    }

    /// The date a count of whole days from 1970-01-01 falls on, negative
    /// before it, or `None` when the count is outside the range: before
    /// -96,465,292, the count of [`UtcDate::MIN`], or after 95,026,236, the
    /// count of [`UtcDate::MAX`].
    ///
    /// The inverse of [`UtcDate::days_since_epoch`]: every date is the date
    /// of its own count.
    pub const fn from_days_since_epoch(days: i64) -> Option<UtcDate> {
        if days < MIN_DAYS || days > MAX_DAYS {
            return None;
        }
        Some(UtcDate::on_day_of_range(days))
    }

    /// The date of a day count inside the range. Both callers hold the
    /// count to the range: the checked constructor refuses any other, and
    /// every second of a `Timestamp` falls on a day of it.
    pub(crate) const fn on_day_of_range(days: i64) -> UtcDate {
        let (year, month, day) = civil_from_days(days);
        // In range, so the year fits an `i32` and the month and day a `u8`.
        UtcDate {
            year: year as i32,
            month: month as u8,
            day: day as u8,
        }
    }
}

/// Whether a year of the proleptic Gregorian calendar has a 29 February.
const fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// The number of days in a month, for a month of 1 to 12.
const fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
///
/// The count runs in years that start on 1 March, so the leap day is the
/// last day of its year, and in cycles of 400 years, each 146,097 days long.
/// Total for every year of an `i32`: the largest intermediate value is about
/// 365 times the year.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_from_march = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * DAYS_PER_ERA + day_of_era - DAYS_TO_EPOCH
}

/// The year, month and day a count of days since 1970-01-01 falls on: the
/// inverse of [`days_from_civil`]. Total for every count in the range of
/// [`UtcDate`], and far beyond it.
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + DAYS_TO_EPOCH;
    let era = days.div_euclid(DAYS_PER_ERA);
    let day_of_era = days.rem_euclid(DAYS_PER_ERA);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Writes `YYYY-MM-DD`. A year of 0 to 9999 is four digits; any other year
/// carries its sign and at least four digits (`-0001`, `+10000`).
impl fmt::Display for UtcDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if (0..=9999).contains(&self.year) {
            write!(f, "{:04}", self.year)?;
        } else {
            write!(f, "{:+05}", self.year)?;
        }
        write!(f, "-{:02}-{:02}", self.month, self.day)
    }
}

/// Reads exactly the text `Display` writes: `2026-02-28`, `-0001-12-31`,
/// `+10000-01-01`. Any other spelling of a date is refused.
impl FromStr for UtcDate {
    type Err = TimeError;

    fn from_str(text: &str) -> Result<UtcDate, TimeError> {
        // From the right, since a year may start with a minus sign.
        let mut fields = text.rsplitn(3, '-');
        let (Some(day), Some(month), Some(year)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(TimeError::Invalid);
        };
        let year: i32 = year.parse().map_err(|_| TimeError::Invalid)?;
        let month: u8 = month.parse().map_err(|_| TimeError::Invalid)?;
        let day: u8 = day.parse().map_err(|_| TimeError::Invalid)?;
        let date = UtcDate::new(year, month, day).ok_or(TimeError::OutOfRange)?;
        // The numbers read may have been spelled another way (`2026-2-28`,
        // `+2026-02-28`); only the written form is a date.
        if date.to_string() == text {
            Ok(date)
        } else {
            Err(TimeError::Invalid)
        }
    }
}

#[cfg(test)]
mod tests;
