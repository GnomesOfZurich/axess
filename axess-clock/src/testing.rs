//! Deterministic [`MockClock`] for DST.
//!
//! Gated on the `testing` feature so production builds don't compile the
//! advanceable-time surface. Downstream crates that need the mock in
//! their integration tests enable it via:
//!
//! ```toml
//! [dev-dependencies]
//! axess-clock = { version = "0.20", features = ["testing"] }
//! ```
//!
//! Workspace crates that re-export the trait surface forward the feature
//! through their own `testing` feature (see `axess-core/Cargo.toml`).

use crate::{Clock, SignedDuration, SystemClock, Timestamp};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// 2026-01-01T00:00:00Z. The date is checked when the code is compiled.
const REFERENCE: Timestamp = Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap();

/// A clock whose current time is set by test code and moves only when the
/// test advances or sets it.
///
/// [`MockClock::at`] pins a reproducible start, and
/// [`MockClock::at_reference`] pins the one every test can share.
/// [`MockClock::now`] starts at the real time of the call and then stays
/// frozen there, so a run that uses it is not reproducible.
#[derive(Debug, Clone)]
pub struct MockClock {
    current: Arc<Mutex<Timestamp>>,
}

impl MockClock {
    /// Create a mock clock set to the given time.
    pub fn at(time: Timestamp) -> Self {
        Self {
            current: Arc::new(Mutex::new(time)),
        }
    }

    /// The instant [`MockClock::at_reference`] starts at:
    /// 2026-01-01T00:00:00Z.
    ///
    /// A fixture that stamps a record (a user's `created_at`, a status
    /// change) reads this, or the clock of the world it belongs to, rather
    /// than the wall clock, so the same test sees the same times on every run.
    pub fn reference_time() -> Timestamp {
        REFERENCE
    }

    /// Create a mock clock set to [`MockClock::reference_time`], the
    /// reproducible start a test world shares with its fixtures.
    ///
    /// ```
    /// use axess_clock::{Clock, testing::MockClock};
    ///
    /// let clock = MockClock::at_reference();
    /// assert_eq!(clock.now(), MockClock::reference_time());
    /// assert_eq!(clock.now().to_rfc3339(), "2026-01-01T00:00:00Z");
    /// ```
    pub fn at_reference() -> Self {
        Self::at(Self::reference_time())
    }

    /// Create a mock clock frozen at the real time of this call. Use
    /// [`MockClock::at`] or [`MockClock::at_reference`] when the run must be
    /// reproducible.
    pub fn now() -> Self {
        Self::at(SystemClock.now())
    }

    /// Advance the clock forward by `secs` seconds.
    ///
    /// # Panics
    ///
    /// When the new time is outside the range of a [`Timestamp`].
    #[track_caller]
    pub fn advance_secs(&self, secs: i64) {
        self.advance(SignedDuration::seconds(secs));
    }

    /// Advance the clock forward by a [`SignedDuration`] (back, for a
    /// negative one). Convenience over [`Self::advance_secs`] when callers
    /// already have a typed span (e.g. `SignedDuration::hours(2)`,
    /// `SignedDuration::days(30)`).
    ///
    /// # Panics
    ///
    /// When the new time is outside the range of a [`Timestamp`]. The clock
    /// keeps the time it had.
    #[track_caller]
    pub fn advance(&self, span: SignedDuration) {
        let mut current = self.current();
        *current = current.plus(span);
    }

    /// Set the clock to an exact time.
    pub fn set(&self, time: Timestamp) {
        *self.current() = time;
    }

    /// The time, locked. A test that panicked while it held the lock left
    /// the time whole (it is replaced in one step), so the lock is taken
    /// again.
    fn current(&self) -> MutexGuard<'_, Timestamp> {
        self.current.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Clock for MockClock {
    fn now(&self) -> Timestamp {
        *self.current()
    }
}

/// Arithmetic for test code that states its times: a reading shifted by a
/// span, as the reading itself.
///
/// Library code adds a span with [`Timestamp::checked_add`] and says what a
/// result outside the range means where it is computed. A test states times
/// it knows to be inside the range, so here a result outside it is a panic
/// that names the two operands.
///
/// ```
/// use axess_clock::SignedDuration;
/// use axess_clock::testing::{MockClock, Shift};
///
/// let start = MockClock::reference_time();
/// let later = start.plus(SignedDuration::minutes(5));
/// assert_eq!(later.since(start), SignedDuration::seconds(300));
/// assert_eq!(later.minus(SignedDuration::minutes(5)), start);
/// ```
pub trait Shift {
    /// The reading `span` later (earlier, for a negative span).
    ///
    /// # Panics
    ///
    /// When that is outside the range of a [`Timestamp`].
    #[must_use]
    fn plus(self, span: SignedDuration) -> Self;

    /// The reading `span` earlier (later, for a negative span).
    ///
    /// # Panics
    ///
    /// When that is outside the range of a [`Timestamp`].
    #[must_use]
    fn minus(self, span: SignedDuration) -> Self;
}

impl Shift for Timestamp {
    #[track_caller]
    fn plus(self, span: SignedDuration) -> Timestamp {
        match self.checked_add(span) {
            Some(shifted) => shifted,
            None => panic!("{self} plus {span:?} is outside the range of a Timestamp"),
        }
    }

    #[track_caller]
    fn minus(self, span: SignedDuration) -> Timestamp {
        match self.checked_sub(span) {
            Some(shifted) => shifted,
            None => panic!("{self} minus {span:?} is outside the range of a Timestamp"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Timestamp = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    const T1: Timestamp = Timestamp::from_unix_seconds(1_800_000_000).unwrap();

    fn seconds(of: Timestamp) -> i64 {
        of.unix_seconds()
    }

    #[test]
    fn at_pins_initial_time() {
        let clock = MockClock::at(T0);
        assert_eq!(clock.now(), T0);
    }

    #[test]
    fn the_reference_time_is_the_first_second_of_2026() {
        assert_eq!(seconds(MockClock::reference_time()), 1_767_225_600);
        assert_eq!(
            MockClock::reference_time().to_rfc3339(),
            "2026-01-01T00:00:00Z"
        );
        assert_eq!(MockClock::at_reference().now(), MockClock::reference_time());
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "reads the host's clock, which Miri's isolation refuses"
    )]
    fn now_starts_at_the_real_time_and_stays_there() {
        let floor = Timestamp::from_utc(2024, 1, 1, 0, 0, 0).unwrap();
        let clock = MockClock::now();
        let first = clock.now();
        assert!(first > floor, "{first}");
        assert_eq!(clock.now(), first, "a mock moves only when it is moved");
    }

    #[test]
    fn advance_secs_moves_forward() {
        let clock = MockClock::at(T0);
        clock.advance_secs(7);
        assert_eq!(
            seconds(clock.now()),
            1_700_000_007,
            "advance_secs must add forward (kills `+= → -=` and body-`()`)"
        );
        clock.advance_secs(-10);
        assert_eq!(seconds(clock.now()), 1_699_999_997);
    }

    #[test]
    fn advance_duration_moves_forward() {
        let clock = MockClock::at(T0);
        clock.advance(SignedDuration::hours(2));
        assert_eq!(
            seconds(clock.now()),
            1_700_007_200,
            "advance must add forward (kills `+= -> -=` and body-`()`)"
        );
        clock.advance(SignedDuration::milliseconds(-250));
        assert_eq!(clock.now().unix_millis(), 1_700_007_199_750);
    }

    #[test]
    fn set_replaces_current_time() {
        let clock = MockClock::at(T0);
        clock.set(T1);
        assert_eq!(
            clock.now(),
            T1,
            "set must replace the current value (kills body-`()` mutation)"
        );
    }

    #[test]
    fn a_clone_shares_the_time() {
        let clock = MockClock::at(T0);
        let handle = clock.clone();
        clock.advance_secs(60);
        assert_eq!(seconds(handle.now()), 1_700_000_060);
    }

    #[test]
    fn an_advance_past_the_range_panics_and_leaves_the_clock_where_it_was() {
        let clock = MockClock::at(T0);
        let moved = clock.clone();
        let outcome = std::panic::catch_unwind(move || moved.advance(SignedDuration::MAX));
        assert!(outcome.is_err(), "no reading is that far ahead");
        assert_eq!(clock.now(), T0);
        clock.advance_secs(1);
        assert_eq!(seconds(clock.now()), 1_700_000_001);
    }

    #[test]
    fn a_shifted_reading_is_the_checked_sum() {
        let five = SignedDuration::minutes(5);
        assert_eq!(seconds(T0.plus(five)), 1_700_000_300);
        assert_eq!(seconds(T0.minus(five)), 1_699_999_700);
        assert_eq!(T0.plus(five).minus(five), T0);
        assert_eq!(T0.plus(SignedDuration::seconds(-300)), T0.minus(five));
        assert_eq!(Timestamp::MAX.minus(SignedDuration::ZERO), Timestamp::MAX);
        assert_eq!(Timestamp::MIN.plus(SignedDuration::ZERO), Timestamp::MIN);
    }

    #[test]
    #[should_panic(
        expected = "+262142-12-31T23:59:59.999999999Z plus SignedDuration { secs: 0, nanos: 1 } is outside the range of a Timestamp"
    )]
    fn a_shift_past_the_last_reading_panics() {
        let _ = Timestamp::MAX.plus(SignedDuration::nanoseconds(1));
    }

    #[test]
    #[should_panic(
        expected = "-262143-01-01T00:00:00Z minus SignedDuration { secs: 0, nanos: 1 } is outside the range of a Timestamp"
    )]
    fn a_shift_before_the_first_reading_panics() {
        let _ = Timestamp::MIN.minus(SignedDuration::nanoseconds(1));
    }
}
