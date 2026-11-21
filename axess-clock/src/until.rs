//! An end that may not come.

use crate::duration::SignedDuration;
use crate::timestamp::Timestamp;
use std::time::Duration;

/// When something ends: at a reading of the clock, or never.
///
/// An expiry, a lockout or a cooldown that can be set to "for ever" is an
/// `Until`, so code and tests tell "never" from a far year. Every `At`
/// orders before `Forever`.
///
/// [`Until::after`] is the one way an end is computed from a start and a
/// lifetime.
///
/// # Stored form
///
/// `Forever` has no text or number of its own: it is stored as
/// [`Until::LEGACY_FOREVER`], the value earlier releases stored for a
/// lifetime that did not fit, and exactly that value reads as `Forever`
/// ([`Until::to_timestamp`], [`Until::from_timestamp`], and the two
/// functions for a column of whole Unix seconds). Rows written by earlier
/// releases therefore read as themselves, and readers of either age agree.
///
/// ```
/// use axess_clock::{Timestamp, Until};
/// use std::time::Duration;
///
/// let now = Timestamp::from_utc(2026, 1, 1, 0, 0, 0).expect("a day of the calendar");
/// let end = Until::after(now, Duration::from_secs(900));
/// assert!(!end.is_past(now));
/// assert!(end < Until::Forever);
/// assert_eq!(Until::after(now, Duration::MAX), Until::Forever);
/// assert!(!Until::Forever.is_past(Timestamp::MAX));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Until {
    /// The end comes at this reading.
    At(Timestamp),
    /// The end never comes.
    Forever,
}

impl Until {
    /// The value `Forever` is stored as: the latest reading,
    /// `+262142-12-31T23:59:59.999999999Z`, in Unix second
    /// 8,210,266,876,799.
    pub const LEGACY_FOREVER: Timestamp = Timestamp::MAX;

    /// The end of a lifetime that starts at `now`.
    ///
    /// `At(now + lifetime)` while that is before
    /// [`Until::LEGACY_FOREVER`], and `Forever` when the lifetime reaches
    /// or runs past it.
    ///
    /// A lifetime is never negative, so it is the unsigned span of the
    /// standard library. A caller that holds a [`SignedDuration`] converts
    /// it first, and that conversion refuses a negative one.
    pub const fn after(now: Timestamp, lifetime: Duration) -> Until {
        // A lifetime past the longest signed span runs past the range from
        // any start.
        let Some(lifetime) = SignedDuration::from_unsigned(lifetime) else {
            return Until::Forever;
        };
        match now.checked_add(lifetime) {
            Some(end) => Until::from_timestamp(end),
            None => Until::Forever,
        }
    }

    /// Whether the end has come at `now`: true from the reading of the end
    /// onwards, and never for `Forever`.
    pub const fn is_past(self, now: Timestamp) -> bool {
        match self {
            // At or before `now`: the span from the end to `now` is not
            // negative.
            Until::At(end) => !now.since(end).is_negative(),
            Until::Forever => false,
        }
    }

    /// Whether the end never comes.
    pub const fn is_forever(self) -> bool {
        matches!(self, Until::Forever)
    }

    /// The reading the end comes at, or `None` for `Forever`.
    pub const fn at(self) -> Option<Timestamp> {
        match self {
            Until::At(end) => Some(end),
            Until::Forever => None,
        }
    }

    /// The end a stored reading stands for: `Forever` for exactly
    /// [`Until::LEGACY_FOREVER`], and `At` for every other reading.
    pub const fn from_timestamp(stored: Timestamp) -> Until {
        if stored.unix_nanos() == Until::LEGACY_FOREVER.unix_nanos() {
            Until::Forever
        } else {
            Until::At(stored)
        }
    }

    /// The reading the end is stored as: [`Until::LEGACY_FOREVER`] for
    /// `Forever`.
    pub const fn to_timestamp(self) -> Timestamp {
        match self {
            Until::At(end) => end,
            Until::Forever => Until::LEGACY_FOREVER,
        }
    }

    /// The end a stored count of whole Unix seconds stands for: `Forever`
    /// for 8,210,266,876,799, the second of [`Until::LEGACY_FOREVER`], and
    /// `At` for every other second of the range. `None` outside the range.
    pub const fn from_unix_seconds(stored: i64) -> Option<Until> {
        if stored == Until::LEGACY_FOREVER.unix_seconds() {
            return Some(Until::Forever);
        }
        match Timestamp::from_unix_seconds(stored) {
            Some(end) => Some(Until::At(end)),
            None => None,
        }
    }

    /// The whole Unix seconds the end is stored as, rounded down:
    /// 8,210,266,876,799 for `Forever`.
    ///
    /// A column of whole seconds cannot tell an end in the last second of
    /// the range from `Forever`: both are that number, and it reads back as
    /// `Forever`.
    pub const fn unix_seconds(self) -> i64 {
        self.to_timestamp().unix_seconds()
    }
}

#[cfg(test)]
mod tests;
