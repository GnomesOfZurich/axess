//! The bounds of a [`LockoutPolicy`] and the instants it derives.
//!
//! The policy's fields are public so a store can build one from a tenant
//! row, so they are checked here, between the row and the verdict: a
//! `duration` past the range of a reading would fail the request that adds
//! it to now, and a `max_attempts` of `u32::MAX` or an `attempt_window` of zero
//! would turn the lock off without a word. A lockout end counted from now
//! ([`LockoutPolicy::lockout_until`]) and one counted from the last failure
//! ([`LockoutPolicy::derived_lockout`]) are both [`Until::after`] the start,
//! so a duration past the range never ends ([`Until::Forever`]), and the two
//! agree. The service reads every policy through
//! [`LockoutPolicy::bounded`], which clamps a value past its bound to the
//! bound. The clamp reaches what the service
//! applies: the count and the duration a lockout is derived from, and the
//! policy handed to the store's `reserve_attempt`. A store that applies
//! `attempt_window` itself when it counts failures reads its own row, so a
//! zero window there still expires every failure as it is recorded; such a
//! store calls [`LockoutPolicy::validate`] where it loads the row, as the
//! SQLite example does at start-up. `validate` is the refusal by name, for
//! the place a policy is loaded.

use super::LockoutPolicy;
use axess_clock::{Timestamp, Until};
use std::time::Duration;

/// Why [`LockoutPolicy::validate`] refuses a policy: the field and the bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LockoutPolicyError {
    /// `duration` is above [`LockoutPolicy::MAX_DURATION`]. A lockout meant
    /// to last until an administrator acts is `duration: None`.
    #[error("lockout duration of {duration:?} is above the longest allowed, {max:?}")]
    DurationAboveMax {
        /// The configured duration.
        duration: Duration,
        /// The bound.
        max: Duration,
    },
    /// `max_attempts` is above [`LockoutPolicy::MAX_ATTEMPTS`], a count no
    /// guesser reaches, so the lock would never hold.
    #[error("lockout max_attempts of {max_attempts} is above the most allowed, {max}")]
    MaxAttemptsAboveMax {
        /// The configured count.
        max_attempts: u32,
        /// The bound.
        max: u32,
    },
    /// `attempt_window` is zero, so every failure would expire as it is
    /// recorded and the lock would never hold.
    #[error("lockout attempt_window is zero, so no failure would ever count")]
    AttemptWindowZero,
    /// `attempt_window` is above [`LockoutPolicy::MAX_DURATION`].
    #[error("lockout attempt_window of {window:?} is above the longest allowed, {max:?}")]
    AttemptWindowAboveMax {
        /// The configured window.
        window: Duration,
        /// The bound.
        max: Duration,
    },
}

impl LockoutPolicy {
    /// The longest `duration` and `attempt_window` a policy may hold: one
    /// hundred years. A lockout meant to last until an administrator resets
    /// the counter is `duration: None`, which says so by name; anything
    /// longer than this is that intent written as a number, and numbers far
    /// enough past it do not fit a date.
    pub const MAX_DURATION: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

    /// The most `max_attempts` a policy may ask for: one thousand. A limit
    /// above it is one no guesser meets, so the lock would never hold, and
    /// the throttle alone would slow the guessing.
    pub const MAX_ATTEMPTS: u32 = 1000;

    /// When a lockout that begins at `now` ends under this policy: `now +
    /// duration`, or [`Until::Forever`] when the sum runs past the range of
    /// a [`Timestamp`]; `None` for a policy without a duration, whose
    /// lockout lasts until an administrator resets the counter.
    ///
    /// A status holds the end as it is
    /// ([`StatusDetail::until`](super::StatusDetail)). A store that keeps
    /// it in a column of its own writes the reading
    /// [`Until::to_timestamp`] gives, the one a for-ever end is stored as.
    pub fn lockout_until(&self, now: Timestamp) -> Option<Until> {
        self.duration.map(|duration| Until::after(now, duration))
    }

    /// Refuse a policy with a value past its bound, naming the first.
    ///
    /// Call it where a policy is loaded (a tenant table reader, a
    /// configuration file, start-up) so a mistyped value is refused there.
    /// The service does not refuse: it reads every policy through
    /// [`bounded`](Self::bounded) and reports a fault once.
    ///
    /// # Errors
    ///
    /// [`LockoutPolicyError`] for the first field past its bound.
    pub fn validate(&self) -> Result<(), LockoutPolicyError> {
        if let Some(duration) = self.duration
            && duration > Self::MAX_DURATION
        {
            return Err(LockoutPolicyError::DurationAboveMax {
                duration,
                max: Self::MAX_DURATION,
            });
        }
        if self.max_attempts > Self::MAX_ATTEMPTS {
            return Err(LockoutPolicyError::MaxAttemptsAboveMax {
                max_attempts: self.max_attempts,
                max: Self::MAX_ATTEMPTS,
            });
        }
        if self.attempt_window.is_zero() {
            return Err(LockoutPolicyError::AttemptWindowZero);
        }
        if self.attempt_window > Self::MAX_DURATION {
            return Err(LockoutPolicyError::AttemptWindowAboveMax {
                window: self.attempt_window,
                max: Self::MAX_DURATION,
            });
        }
        Ok(())
    }

    /// This policy with every value past its bound brought to the bound:
    /// the policy the service applies. A `duration` or `attempt_window`
    /// above [`MAX_DURATION`](Self::MAX_DURATION) becomes it, a
    /// `max_attempts` above [`MAX_ATTEMPTS`](Self::MAX_ATTEMPTS) becomes
    /// it, and a zero `attempt_window` becomes the default window. Each
    /// bounded value locks at least as much as the one asked for, so the
    /// request is served under it rather than refused; the caller reports
    /// what [`validate`](Self::validate) says.
    ///
    /// The clamp reaches the policy the service applies, not a store's own
    /// reading of its row: a store that applies `attempt_window` when it
    /// counts failures validates where it loads the policy.
    #[must_use]
    pub fn bounded(&self) -> LockoutPolicy {
        let mut policy = self.clone();
        policy.duration = policy
            .duration
            .map(|duration| duration.min(Self::MAX_DURATION));
        policy.max_attempts = policy.max_attempts.min(Self::MAX_ATTEMPTS);
        if policy.attempt_window.is_zero() {
            policy.attempt_window = LockoutPolicy::default().attempt_window;
        }
        policy.attempt_window = policy.attempt_window.min(Self::MAX_DURATION);
        policy
    }
}

#[cfg(test)]
mod tests;
