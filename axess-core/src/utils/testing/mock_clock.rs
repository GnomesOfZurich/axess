//! Deterministic clock for DST — injectable into AuthnService.

use crate::utils::time::Clock;
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
        *guard = *guard + chrono::Duration::seconds(secs);
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
