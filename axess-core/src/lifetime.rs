//! Instants a configured lifetime reaches, without a panic: a TTL an
//! operator sets to "for ever" must clamp, not abort the request that reads
//! it.

use chrono::{DateTime, Duration, Utc};

/// `now` plus `ttl`, or the latest instant chrono holds when the sum does
/// not fit.
pub(crate) fn expiry_after(now: DateTime<Utc>, ttl: std::time::Duration) -> DateTime<Utc> {
    Duration::from_std(ttl)
        .ok()
        .and_then(|d| now.checked_add_signed(d))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// `now` plus `ttl`, or the latest instant chrono holds when the sum does
/// not fit.
pub(crate) fn expiry_after_signed(now: DateTime<Utc>, ttl: Duration) -> DateTime<Utc> {
    now.checked_add_signed(ttl)
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}
