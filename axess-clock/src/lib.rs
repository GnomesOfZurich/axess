#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Injectable [`Clock`] trait for deterministic simulation testing (DST).
//!
//! Production code depends on the trait, not on `chrono::Utc::now()` directly,
//! so tests can swap in a [`testing::MockClock`] and advance time
//! deterministically. This crate is a foundational primitive used by
//! [`axess`](https://crates.io/crates/axess) and other crates that want their
//! time-dependent behaviour to be reproducible.
//!
//! # Quick start
//!
//! ```rust
//! use axess_clock::{Clock, SystemClock};
//!
//! fn timestamp_now<C: Clock>(clock: &C) -> i64 {
//!     clock.now().timestamp()
//! }
//!
//! let production = SystemClock;
//! let _ = timestamp_now(&production);
//! ```
//!
//! And in tests (requires the `testing` feature):
//!
//! ```rust,ignore
//! use axess_clock::Clock;
//! use axess_clock::testing::MockClock;
//! use chrono::{TimeZone, Utc};
//!
//! let clock = MockClock::at(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
//! assert_eq!(clock.now().timestamp(), 1_767_225_600);
//! clock.advance_secs(60);
//! assert_eq!(clock.now().timestamp(), 1_767_225_660);
//! ```

use chrono::{DateTime, TimeZone, Utc};

#[cfg(any(test, feature = "testing"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

/// Top-level alias for [`testing::MockClock`]. Crates that prefer the
/// "deterministic clock" naming can reach for `axess_clock::DeterministicClock`
/// without spelling out the `testing::` path. Same type, same `::at(time)` /
/// `advance` / `set` surface, different name. Gated on the `testing` feature
/// like the underlying mock.
#[cfg(any(test, feature = "testing"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub use testing::MockClock as DeterministicClock;

/// Clock trait to enable deterministic simulation/testing.
pub trait Clock: Send + Sync + 'static {
    /// Return the current wall-clock time in UTC.
    fn now(&self) -> DateTime<Utc>;
}

/// Production [`Clock`] backed by [`chrono::Utc::now`].
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Return current time as RFC3339 string (UTC).
pub fn now_rfc3339<C: Clock>(clock: &C) -> String {
    clock.now().to_rfc3339()
}

/// Return current time as unix epoch seconds (i64).
pub fn now_epoch<C: Clock>(clock: &C) -> i64 {
    clock.now().timestamp()
}

/// Parse a flexible datetime representation:
/// - If `txt` is Some and a valid RFC3339 string -> parsed `DateTime<Utc>`
/// - Else if `secs` is Some -> treat as unix epoch seconds
/// - Else -> None
pub fn parse_datetime_flexible(txt: Option<&str>, secs: Option<i64>) -> Option<DateTime<Utc>> {
    if let Some(s) = txt
        && let Ok(dt) = DateTime::parse_from_rfc3339(s)
    {
        return Some(dt.with_timezone(&Utc));
    }
    secs.and_then(|ts| Utc.timestamp_opt(ts, 0).single())
}

/// Convert epoch seconds -> RFC3339 string
pub fn epoch_to_rfc3339(secs: i64) -> Option<String> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
}

#[cfg(test)]
mod time_tests {
    use super::*;
    use chrono::Datelike;

    /// `SystemClock::now()` returns a wall-clock timestamp
    /// distinct from the unix epoch. Pins the four
    /// `now -> DateTime::*(Default::default())` body mutations; each
    /// would return `1970-01-01T00:00:00Z` instead of the current time,
    /// silently breaking every consumer that relies on `Clock::now()`
    /// monotonicity (token issuance, audit timestamps, replay caches).
    #[test]
    fn system_clock_now_returns_recent_wall_clock_time() {
        let clock = SystemClock;
        let now = clock.now();
        // Any timestamp
        // earlier than 2024 has either come from a Default-mutated body
        // (`1970-01-01T00:00:00Z`) or means the host clock is broken.
        let floor = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).single().unwrap();
        assert!(
            now > floor,
            "SystemClock::now() must return wall-clock time, not Default (got {now})"
        );
    }

    /// `now_rfc3339` produces a parseable RFC3339 string in the
    /// current era. Pins both `String::new()` (empty body) and
    /// `"xyzzy".into()` (literal-replace body) mutations.
    #[test]
    fn now_rfc3339_returns_parseable_recent_timestamp() {
        let s = now_rfc3339(&SystemClock);
        assert!(!s.is_empty(), "now_rfc3339 must not be empty");
        let parsed = DateTime::parse_from_rfc3339(&s)
            .expect("now_rfc3339 must produce a valid RFC3339 string (got: {s})");
        let floor = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).single().unwrap();
        assert!(
            parsed.with_timezone(&Utc) > floor,
            "now_rfc3339 must reflect wall-clock time, not Default"
        );
    }

    /// `now_epoch` returns a positive Unix timestamp in the
    /// current era. Pins the `0`, `1`, `-1` body mutations. A floor of
    /// 1.7e9 (≈ 2023-11-15) catches all three since each constant is
    /// orders of magnitude smaller.
    #[test]
    fn now_epoch_returns_recent_timestamp() {
        let t = now_epoch(&SystemClock);
        assert!(
            t > 1_700_000_000,
            "now_epoch must return wall-clock seconds (got {t})"
        );
    }

    /// `parse_datetime_flexible` exercises every branch of
    /// `(txt, secs)`:
    /// - txt valid → returns parsed (uses txt path),
    /// - txt invalid + secs Some → falls through to secs,
    /// - txt valid + secs Some → txt wins (precedence),
    /// - both None → None,
    /// - txt None + secs None → None.
    ///
    /// Pins the body replacements (None / Some(Default)), the
    /// `&& → ||` mutation on the let-chain (which would short-circuit
    /// to "valid txt" on any non-None txt regardless of parse success),
    /// and the function-body replacements.
    #[test]
    fn parse_datetime_flexible_branches() {
        let valid_rfc3339 = "2026-04-01T12:00:00Z";
        let parsed = parse_datetime_flexible(Some(valid_rfc3339), None)
            .expect("valid RFC3339 must parse to Some");
        assert_eq!(parsed.year(), 2026);
        assert_eq!(parsed.month(), 4);

        // txt invalid → falls through to secs.
        let from_secs = parse_datetime_flexible(Some("not-a-date"), Some(1_700_000_000))
            .expect("invalid txt with valid secs must fall through to secs");
        assert_eq!(from_secs.timestamp(), 1_700_000_000);

        // txt valid + secs present → txt wins (precedence).
        let txt_wins = parse_datetime_flexible(Some(valid_rfc3339), Some(1))
            .expect("valid txt + secs must prefer txt");
        assert_eq!(txt_wins.year(), 2026);
        assert_ne!(
            txt_wins.timestamp(),
            1,
            "&& → || would have used the secs fallback"
        );

        // txt missing → use secs.
        let only_secs = parse_datetime_flexible(None, Some(0))
            .expect("txt None with valid secs must parse from secs");
        assert_eq!(only_secs.timestamp(), 0);

        // both None → None.
        assert!(
            parse_datetime_flexible(None, None).is_none(),
            "both None must return None"
        );
    }

    /// `epoch_to_rfc3339` produces a parseable RFC3339 string
    /// for valid input. Pins the `None`, `Some(String::new())`, and
    /// `Some("xyzzy")` body mutations.
    #[test]
    fn epoch_to_rfc3339_returns_parseable_iso_string() {
        let s = epoch_to_rfc3339(1_700_000_000).expect("valid epoch must produce Some(rfc3339)");
        let parsed = DateTime::parse_from_rfc3339(&s)
            .expect("epoch_to_rfc3339 must produce a valid RFC3339 string");
        assert_eq!(parsed.timestamp(), 1_700_000_000);
        assert!(s.starts_with("2023-"), "1.7e9 maps to 2023 (got: {s})");
    }
}
