//! Time utilities for Axess.
//!
//! Exposes the [`Clock`] trait for deterministic simulation/testing, the OS-backed
//! [`SystemClock`] implementation, and helpers for common conversions such as RFC3339
//! formatting and Unix epoch parsing.

use chrono::{DateTime, TimeZone, Utc};

/// Clock trait to enable deterministic simulation/testing.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> DateTime<Utc>;
}

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
/// - If `txt` is Some and a valid RFC3339 string -> parsed DateTime<Utc>
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
