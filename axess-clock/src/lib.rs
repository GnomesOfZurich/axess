#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Injectable [`Clock`] trait for deterministic simulation testing (DST).
//!
//! Production code depends on the trait, not on a read of the system clock,
//! so tests can swap in a [`testing::MockClock`] and advance time
//! deterministically. [`SystemClock`] is the one place the system clock is
//! read. This crate is a foundational primitive used by
//! [`axess`](https://crates.io/crates/axess) and other crates that want their
//! time-dependent behaviour to be reproducible.
//!
//! # Time types
//!
//! The crate also holds the base time types, on the standard library alone:
//!
//! - [`Timestamp`], a reading of the UTC wall clock to the nanosecond, with
//!   its RFC 3339 text;
//! - [`SignedDuration`], an exact signed span of elapsed time;
//! - [`Until`], an end that comes at a reading or never;
//! - [`UtcDate`], the calendar day in UTC a reading falls on.
//!
//! Their arithmetic is checked and none of them reads a clock. With the
//! `serde` feature a `Timestamp`, an `Until` and a `UtcDate` are written as
//! their text and read back through their readers.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use axess_clock::{Clock, SystemClock};
//!
//! fn seconds_now<C: Clock>(clock: &C) -> i64 {
//!     clock.now().unix_seconds()
//! }
//!
//! let production = SystemClock;
//! let _ = seconds_now(&production);
//! ```
//!
//! And in tests (requires the `testing` feature):
//!
#![cfg_attr(feature = "testing", doc = "```rust")]
#![cfg_attr(not(feature = "testing"), doc = "```rust,ignore")]
//! use axess_clock::testing::MockClock;
//! use axess_clock::{Clock, SignedDuration, Timestamp};
//!
//! const NEW_YEAR: Timestamp = Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap();
//!
//! let clock = MockClock::at(NEW_YEAR);
//! assert_eq!(clock.now().unix_seconds(), 1_767_225_600);
//! clock.advance(SignedDuration::seconds(60));
//! assert_eq!(clock.now().unix_seconds(), 1_767_225_660);
//! ```

// The `testing` feature compiles deterministic clocks and random sources and
// constructors that skip key checks. A release build that links it ships
// those in a production binary, and cargo feature unification lets any one
// dependent switch it on for the whole build, so the build refuses by name.
// `allow-testing-in-release` is the named opt-out for a build that means it.
#[cfg(all(
    feature = "testing",
    not(debug_assertions),
    not(feature = "allow-testing-in-release")
))]
compile_error!(
    "the `testing` feature of axess-clock is enabled in a release build; it ships test doubles in a \
     production binary. Remove the feature from the release build, or enable \
     `allow-testing-in-release` to keep it on purpose."
);

use std::time::SystemTime;

mod date;
mod duration;
mod error;
mod rfc3339;
#[cfg(test)]
mod sample;
#[cfg(feature = "serde")]
mod serde_impl;
mod timestamp;
mod until;

pub use date::UtcDate;
pub use duration::SignedDuration;
pub use error::TimeError;
pub use timestamp::Timestamp;
pub use until::Until;

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

/// Doctests: the examples of the README compile and run.
#[cfg(all(doctest, feature = "testing"))]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;

/// Clock trait to enable deterministic simulation/testing.
pub trait Clock: Send + Sync + 'static {
    /// Return the current reading of the wall clock in UTC.
    fn now(&self) -> Timestamp;
}

/// A shared clock is a clock, so an `Arc<dyn Clock>` can be handed to any
/// API that takes `impl Clock`.
impl<C: Clock + ?Sized> Clock for std::sync::Arc<C> {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

/// Production [`Clock`] backed by [`std::time::SystemTime::now`], the one
/// read of the system clock in the crate.
///
/// A host whose clock is set outside the range of a [`Timestamp`] (before
/// the year -262143 or after 262142) reads as the nearer end of the range,
/// [`Timestamp::MIN`] or [`Timestamp::MAX`]: the read does not fail and
/// does not panic ([`Timestamp::from_system_time`]).
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_system_time(SystemTime::now())
    }
}

/// Return the current time as RFC 3339 text in UTC with the numeric offset
/// `+00:00` ([`Timestamp::to_rfc3339_numeric_offset`]).
pub fn now_rfc3339<C: Clock>(clock: &C) -> String {
    clock.now().to_rfc3339_numeric_offset()
}

/// Return current time as unix epoch seconds (i64).
pub fn now_epoch<C: Clock>(clock: &C) -> i64 {
    clock.now().unix_seconds()
}

/// Parse a flexible datetime representation:
/// - If `txt` is Some and text [`Timestamp::parse_rfc3339`] reads -> the
///   reading it names
/// - Else if `secs` is Some -> treat as unix epoch seconds
/// - Else -> None
///
/// A count of seconds outside the range of a [`Timestamp`] is `None`.
pub fn parse_datetime_flexible(txt: Option<&str>, secs: Option<i64>) -> Option<Timestamp> {
    if let Some(s) = txt
        && let Ok(at) = Timestamp::parse_rfc3339(s)
    {
        return Some(at);
    }
    secs.and_then(Timestamp::from_unix_seconds)
}

/// Convert epoch seconds -> RFC 3339 text in UTC with the numeric offset
/// `+00:00`, or `None` outside the range of a [`Timestamp`].
pub fn epoch_to_rfc3339(secs: i64) -> Option<String> {
    Timestamp::from_unix_seconds(secs).map(|at| at.to_rfc3339_numeric_offset())
}

#[cfg(test)]
mod clock_tests;
