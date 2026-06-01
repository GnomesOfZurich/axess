//! Deterministic [`MockClock`] for DST.
//!
//! Gated on the `testing` feature so production builds don't compile the
//! advanceable-time surface. Downstream crates that need the mock in
//! their integration tests enable it via:
//!
//! ```toml
//! [dev-dependencies]
//! axess-clock = { version = "0.1", features = ["testing"] }
//! ```
//!
//! Workspace crates that re-export the trait surface forward the feature
//! through their own `testing` feature (see `axess-core/Cargo.toml`).

use crate::Clock;
use chrono::{DateTime, Utc};
use std::sync::{Arc, Mutex};

/// A clock whose current time can be set from test code.
///
/// Default: `Utc::now()` at the time of construction.
#[derive(Debug, Clone)]
pub struct MockClock {
    current: Arc<Mutex<DateTime<Utc>>>,
}

impl MockClock {
    /// Create a mock clock set to the given time.
    pub fn at(time: DateTime<Utc>) -> Self {
        Self {
            current: Arc::new(Mutex::new(time)),
        }
    }

    /// Create a mock clock set to the current real time.
    pub fn now() -> Self {
        Self::at(Utc::now())
    }

    /// Advance the clock forward by `secs` seconds.
    pub fn advance_secs(&self, secs: i64) {
        let mut guard = self.current.lock().unwrap();
        *guard += chrono::Duration::seconds(secs);
    }

    /// Advance the clock forward by a [`chrono::Duration`]. Convenience over
    /// [`Self::advance_secs`] when callers already have a typed `Duration`
    /// (e.g. `chrono::Duration::hours(2)`, `chrono::Duration::days(30)`).
    pub fn advance(&self, duration: chrono::Duration) {
        let mut guard = self.current.lock().unwrap();
        *guard += duration;
    }

    /// Set the clock to an exact time.
    pub fn set(&self, time: DateTime<Utc>) {
        *self.current.lock().unwrap() = time;
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        *self.current.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_pins_initial_time() {
        let t = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let clock = MockClock::at(t);
        assert_eq!(clock.now(), t);
    }

    #[test]
    fn advance_secs_moves_forward() {
        let t0 = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let clock = MockClock::at(t0);
        clock.advance_secs(7);
        assert_eq!(
            clock.now(),
            t0 + chrono::Duration::seconds(7),
            "advance_secs must add forward (kills `+= → -=` and body-`()`)"
        );
    }

    #[test]
    fn advance_duration_moves_forward() {
        let t0 = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let clock = MockClock::at(t0);
        clock.advance(chrono::Duration::hours(2));
        assert_eq!(
            clock.now(),
            t0 + chrono::Duration::hours(2),
            "advance must add forward (kills `+= -> -=` and body-`()`)"
        );
    }

    #[test]
    fn set_replaces_current_time() {
        let t0 = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let t1 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let clock = MockClock::at(t0);
        clock.set(t1);
        assert_eq!(
            clock.now(),
            t1,
            "set must replace the current value (kills body-`()` mutation)"
        );
    }
}
