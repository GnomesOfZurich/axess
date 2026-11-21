//! RFC 3339 text of a [`Timestamp`]: the two written forms and the reader.

use crate::date::UtcDate;
use crate::error::TimeError;
use crate::timestamp::Timestamp;
use std::fmt;
use std::str::FromStr;

/// Seconds in a day: an offset from UTC is smaller than this.
const SECONDS_PER_DAY: i64 = 86_400;

impl Timestamp {
    /// The reading as RFC 3339 text in UTC with a `Z`.
    ///
    /// Whole seconds have no fraction; a fraction has three, six or nine
    /// digits, the fewest that hold it. A year of 0 to 9999 is four digits,
    /// and any other year carries its sign. This is the stored form: a value
    /// written by one release is read by the next, so the text of a reading
    /// never changes.
    ///
    /// ```
    /// use axess_clock::Timestamp;
    ///
    /// let at = Timestamp::from_unix_millis(1_767_225_600_250).expect("inside the range");
    /// assert_eq!(at.to_rfc3339(), "2026-01-01T00:00:00.250Z");
    /// assert_eq!(Timestamp::MAX.to_rfc3339(), "+262142-12-31T23:59:59.999999999Z");
    /// ```
    pub fn to_rfc3339(&self) -> String {
        self.to_string()
    }

    /// The reading as RFC 3339 text with the numeric offset of UTC,
    /// `+00:00`, where [`Timestamp::to_rfc3339`] writes `Z`. The date, the
    /// time and the fraction are written the same way.
    ///
    /// ```
    /// use axess_clock::Timestamp;
    ///
    /// let at = Timestamp::from_unix_millis(1_767_225_600_250).expect("inside the range");
    /// assert_eq!(at.to_rfc3339_numeric_offset(), "2026-01-01T00:00:00.250+00:00");
    /// ```
    pub fn to_rfc3339_numeric_offset(&self) -> String {
        NumericOffset(*self).to_string()
    }

    /// Reads RFC 3339 text as the reading in UTC it names.
    ///
    /// # Accepted forms
    ///
    /// Stored rows and sent texts hold every form an earlier release wrote
    /// or read, so each of them reads as it did then:
    ///
    /// - The text of [`Timestamp::to_rfc3339`] and of
    ///   [`Timestamp::to_rfc3339_numeric_offset`], which read back as the
    ///   same reading.
    /// - A numeric offset: `2026-01-01T01:00:00+01:00` is
    ///   `2026-01-01T00:00:00Z`. The time is converted to UTC and the offset
    ///   is dropped. The offset is a sign, two digits of hours and two of
    ///   minutes, and is smaller than a day. The colon between them may be
    ///   missing (`+0100`) or stand with white space and further colons,
    ///   and the sign may be the minus sign U+2212.
    /// - `Z` or `z` for UTC, or `UTC` in any mix of upper and lower case
    ///   letters.
    /// - `T`, `t` or a space between the date and the time.
    /// - A fraction of any number of digits after a `.`. Digits past the
    ///   ninth are dropped, not rounded.
    /// - A year of one to four digits without a sign, and of any number of
    ///   digits with one.
    /// - A month, day, hour, minute and second of one digit or of two.
    /// - White space before each number, before each `-` and `:` separator,
    ///   before the offset and at either end.
    /// - A second of 60, the way RFC 3339 writes a leap second. It reads as
    ///   the last nanosecond of second 59 of its minute, whatever its
    ///   fraction: its Unix second is the one earlier releases gave it, it
    ///   orders after every earlier reading of that second and before the
    ///   next second, and it is written back as `:59.999999999`.
    ///
    /// # Errors
    ///
    /// [`TimeError::TooShort`] when the text ends early (an empty text, a
    /// date alone, a time with no offset), [`TimeError::Invalid`] for a
    /// character out of place (a `,` for the `.` of a fraction),
    /// [`TimeError::TrailingText`] for text after the offset, and
    /// [`TimeError::OutOfRange`] for a field outside its range (a month 13,
    /// an hour 24, an offset of `+24:00`), a day the calendar does not have
    /// (30 February), or a reading outside the range of a `Timestamp`, in
    /// the local time written or after its conversion to UTC.
    ///
    /// ```
    /// use axess_clock::{TimeError, Timestamp};
    ///
    /// let at = Timestamp::parse_rfc3339("2025-12-31T19:30:00-04:30")?;
    /// assert_eq!(at.to_rfc3339(), "2026-01-01T00:00:00Z");
    /// assert_eq!(
    ///     Timestamp::parse_rfc3339("2026-01-01T00:00:00"),
    ///     Err(TimeError::TooShort)
    /// );
    /// # Ok::<(), TimeError>(())
    /// ```
    pub fn parse_rfc3339(text: &str) -> Result<Timestamp, TimeError> {
        let mut text = Text { rest: text };

        let year = text.year()?;
        text.separator('-')?;
        let month = text.field(1, 12)?;
        text.separator('-')?;
        let day = text.field(1, 31)?;
        text.take(|c| matches!(c, 'T' | 't' | ' '))
            .ok_or_else(|| text.out_of_place())?;
        let hour = text.field(0, 23)?;
        text.separator(':')?;
        let minute = text.field(0, 59)?;
        text.separator(':')?;
        let second = text.field(0, 60)?;
        let fraction = text.fraction()?;
        text.skip_white_space();
        let offset = text.offset()?;
        text.skip_white_space();
        if !text.rest.is_empty() {
            return Err(TimeError::TrailingText);
        }

        let date = UtcDate::new(year, month, day).ok_or(TimeError::OutOfRange)?;
        if offset.abs() >= SECONDS_PER_DAY {
            return Err(TimeError::OutOfRange);
        }
        // A second of 60 is the last nanosecond of second 59.
        let (second, nanos) = match second {
            60 => (59, 999_999_999),
            second => (second, fraction),
        };
        // Bounded by the range of a date and of an offset, so the sum fits.
        let seconds = date.days_since_epoch() * SECONDS_PER_DAY
            + i64::from(hour) * 3_600
            + i64::from(minute) * 60
            + i64::from(second)
            - offset;
        Timestamp::new(seconds, nanos).ok_or(TimeError::OutOfRange)
    }
}

/// The text still to read.
struct Text<'a> {
    rest: &'a str,
}

impl Text<'_> {
    fn skip_white_space(&mut self) {
        self.rest = self.rest.trim_start();
    }

    /// Takes the next character if `wanted` holds for it.
    fn take(&mut self, wanted: impl Fn(char) -> bool) -> Option<char> {
        let mut chars = self.rest.chars();
        let next = chars.next().filter(|&c| wanted(c))?;
        self.rest = chars.as_str();
        Some(next)
    }

    /// The error for a character that was wanted and is not next: the text
    /// has ended, or another character stands there.
    fn out_of_place(&self) -> TimeError {
        if self.rest.is_empty() {
            TimeError::TooShort
        } else {
            TimeError::Invalid
        }
    }

    /// Takes the next character if it is a digit, as its value.
    fn digit(&mut self) -> Option<u32> {
        self.take(|c| c.is_ascii_digit())
            .and_then(|c| c.to_digit(10))
    }

    /// One to `most` digits as a number. Further digits stay unread.
    fn number(&mut self, most: usize) -> Result<i64, TimeError> {
        let mut value: i64 = 0;
        let mut read = 0;
        while read < most {
            let Some(digit) = self.digit() else {
                break;
            };
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(i64::from(digit)))
                .ok_or(TimeError::OutOfRange)?;
            read += 1;
        }
        if read == 0 {
            return Err(self.out_of_place());
        }
        Ok(value)
    }

    /// A year: one to four digits, or a sign and any number of digits.
    fn year(&mut self) -> Result<i32, TimeError> {
        self.skip_white_space();
        let year = match self.take(|c| matches!(c, '+' | '-')) {
            Some('-') => -self.number(usize::MAX)?,
            Some(_) => self.number(usize::MAX)?,
            None => self.number(4)?,
        };
        i32::try_from(year).map_err(|_| TimeError::OutOfRange)
    }

    /// A number of one or two digits within `least..=most`.
    fn field(&mut self, least: u8, most: u8) -> Result<u8, TimeError> {
        self.skip_white_space();
        let value = self.number(2)?;
        u8::try_from(value)
            .ok()
            .filter(|value| (least..=most).contains(value))
            .ok_or(TimeError::OutOfRange)
    }

    /// The `-` or `:` between two numbers, after any white space.
    fn separator(&mut self, mark: char) -> Result<(), TimeError> {
        self.skip_white_space();
        self.take(|c| c == mark)
            .map(|_| ())
            .ok_or_else(|| self.out_of_place())
    }

    /// The fraction of a second in nanoseconds: 0 when no `.` is next, and
    /// at least one digit after a `.`.
    fn fraction(&mut self) -> Result<u32, TimeError> {
        if self.take(|c| c == '.').is_none() {
            return Ok(0);
        }
        let mut nanos = self.digit().ok_or_else(|| self.out_of_place())? * 100_000_000;
        // The value of the next digit's place. Past the ninth digit it is
        // zero, so further digits are read and dropped.
        let mut place = 10_000_000;
        while let Some(digit) = self.digit() {
            nanos += digit * place;
            place /= 10;
        }
        Ok(nanos)
    }

    /// The offset from UTC in seconds, east positive: `Z`, `UTC`, or a sign,
    /// two digits of hours and two of minutes.
    fn offset(&mut self) -> Result<i64, TimeError> {
        if self.utc() || self.take(|c| matches!(c, 'Z' | 'z')).is_some() {
            return Ok(0);
        }
        let sign = match self.take(|c| matches!(c, '+' | '-' | '\u{2212}')) {
            Some('+') => 1,
            Some(_) => -1,
            None => return Err(self.out_of_place()),
        };
        let hours = self.two_digits()?;
        self.rest = self
            .rest
            .trim_start_matches(|c: char| c == ':' || c.is_whitespace());
        let minutes = self.two_digits()?;
        if minutes > 59 {
            return Err(TimeError::OutOfRange);
        }
        Ok(sign * (hours * 3_600 + minutes * 60))
    }

    /// Takes `UTC`, in upper or lower case letters, if it is next.
    fn utc(&mut self) -> bool {
        let mut chars = self.rest.chars();
        let name = [chars.next(), chars.next(), chars.next()];
        let found = matches!(name, [Some('U' | 'u'), Some('T' | 't'), Some('C' | 'c')]);
        if found {
            self.rest = chars.as_str();
        }
        found
    }

    /// Exactly two digits as a number.
    fn two_digits(&mut self) -> Result<i64, TimeError> {
        if self.rest.len() < 2 {
            return Err(TimeError::TooShort);
        }
        let tens = self.digit().ok_or(TimeError::Invalid)?;
        let ones = self.digit().ok_or(TimeError::Invalid)?;
        Ok(i64::from(tens * 10 + ones))
    }
}

/// Writes the date, the time and the fraction of a reading, without an
/// offset.
fn write_utc(at: Timestamp, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (date, hour, minute, second, nanos) = at.to_utc();
    write!(f, "{date}T{hour:02}:{minute:02}:{second:02}")?;
    if nanos == 0 {
        Ok(())
    } else if nanos.is_multiple_of(1_000_000) {
        write!(f, ".{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        write!(f, ".{:06}", nanos / 1_000)
    } else {
        write!(f, ".{nanos:09}")
    }
}

/// A reading written with `+00:00` for its offset.
struct NumericOffset(Timestamp);

impl fmt::Display for NumericOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_utc(self.0, f)?;
        f.write_str("+00:00")
    }
}

/// Writes the text of [`Timestamp::to_rfc3339`].
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_utc(*self, f)?;
        f.write_str("Z")
    }
}

/// Writes the text of [`Timestamp::to_rfc3339`], so a reading in a failed
/// assertion or a log line is read as a date and a time.
impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Reads what [`Timestamp::parse_rfc3339`] reads.
impl FromStr for Timestamp {
    type Err = TimeError;

    fn from_str(text: &str) -> Result<Timestamp, TimeError> {
        Timestamp::parse_rfc3339(text)
    }
}

#[cfg(test)]
mod tests;
