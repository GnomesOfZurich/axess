//! The error the time types return.

use std::fmt;

/// Why a text was not read as a time value, or why a value was refused.
///
/// One type serves the text readers ([`Timestamp::parse_rfc3339`], the
/// `FromStr` of [`Timestamp`] and [`UtcDate`]) and the conversions with
/// `std::time` types.
///
/// [`Timestamp`]: crate::Timestamp
/// [`Timestamp::parse_rfc3339`]: crate::Timestamp::parse_rfc3339
/// [`UtcDate`]: crate::UtcDate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeError {
    /// The text ended before a whole value was read.
    TooShort,
    /// A character stands where the format has no place for it.
    Invalid,
    /// Text follows a whole value.
    TrailingText,
    /// A field is outside its range (a month 13, an hour 24, an offset of a
    /// whole day), the date does not exist (30 February), or the value as a
    /// whole is outside the range its type holds.
    OutOfRange,
    /// A negative span was given where only a span of zero or more fits.
    Negative,
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TimeError::TooShort => "the text ends before the value is complete",
            TimeError::Invalid => "the text holds a character the format has no place for",
            TimeError::TrailingText => "the text continues after the value",
            TimeError::OutOfRange => "the value is outside the range the type holds",
            TimeError::Negative => "the span is negative and the target holds no negative span",
        })
    }
}

impl std::error::Error for TimeError {}

#[cfg(test)]
mod tests {
    use super::TimeError;

    #[test]
    fn each_kind_states_itself_in_one_sentence() {
        let cases = [
            (
                TimeError::TooShort,
                "the text ends before the value is complete",
            ),
            (
                TimeError::Invalid,
                "the text holds a character the format has no place for",
            ),
            (
                TimeError::TrailingText,
                "the text continues after the value",
            ),
            (
                TimeError::OutOfRange,
                "the value is outside the range the type holds",
            ),
            (
                TimeError::Negative,
                "the span is negative and the target holds no negative span",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    fn the_error_is_a_std_error_without_a_source() {
        let error: Box<dyn std::error::Error + Send + Sync> = Box::new(TimeError::OutOfRange);
        assert!(error.source().is_none());
        assert_eq!(
            error.to_string(),
            "the value is outside the range the type holds"
        );
    }
}
