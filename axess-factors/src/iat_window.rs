//! The issued-at window shared by JWT and back-channel logout token checks.

/// Whether a token issued at `iat` is acceptable at `now`: issued no more than
/// `max_future_secs` ahead of `now` (clock skew) and no more than
/// `max_age_secs` before it. An `iat` so far from `now` that the difference
/// does not fit an `i64` is outside the window, never an overflow.
pub(crate) fn iat_within(iat: i64, now: i64, max_future_secs: i64, max_age_secs: i64) -> bool {
    now.checked_sub(iat)
        .is_some_and(|age| (-max_future_secs..=max_age_secs).contains(&age))
}
