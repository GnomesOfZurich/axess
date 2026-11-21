//! Progressive throttling of consecutive wrong guesses, beside the
//! per-account lockout of [`LockoutPolicy`](super::LockoutPolicy).
//!
//! The lockout counts failures against the account, so anyone who knows a
//! username can keep that account locked. The throttle answers the same
//! attack from the other side: it slows one guesser down without touching
//! the account's standing. After `n` consecutive failures under one key, a
//! guess before `last_failure + min(first_delay * 2^(n-1), max_delay)` is
//! refused with the time left; it is a refusal, never a sleep, so a
//! throttled request holds no connection and runs no verifier. A right
//! guess clears the key. The per-account lock stays the ceiling: an
//! attacker cycling addresses still meets it.

use crate::authn::ids::{TenantId, UserId};
use std::net::IpAddr;
use std::time::Duration;

/// How consecutive wrong guesses are slowed down before the account's lock
/// is reached.
///
/// The default, on in every [`LockoutPolicy`](super::LockoutPolicy), waits
/// one second after the first failure and doubles per failure to a cap of
/// sixty-four seconds, keyed on the account and the client address, so one
/// guesser's failures do not delay the account's owner on another address.
/// A key that has not failed for `2 * max_delay` is as good as absent.
/// [`LockoutPolicy::without_throttle`](super::LockoutPolicy::without_throttle)
/// is the opt-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Throttle {
    /// The delay after the first consecutive failure. Default: 1 second.
    pub first_delay: Duration,
    /// The delay the doubling stops at. Default: 64 seconds.
    pub max_delay: Duration,
    /// What the consecutive failures are counted under. Default:
    /// [`ThrottleKey::AccountAndAddress`].
    pub key: ThrottleKey,
}

impl Default for Throttle {
    fn default() -> Self {
        Self {
            first_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(64),
            key: ThrottleKey::AccountAndAddress,
        }
    }
}

/// What a [`Throttle`] counts consecutive failures under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThrottleKey {
    /// The tenant, the user and the client address the request resolved,
    /// so one address's failures delay that address only. A request with no
    /// resolved address is keyed on the account alone, and the pipeline
    /// logs an error once when the address is unknown because
    /// `client_ip::layer` is not installed. The default.
    #[default]
    AccountAndAddress,
    /// The tenant and the user: every address shares one delay. The
    /// account's owner is delayed by a stranger's failures, which is the
    /// lockout's weakness in a milder form; choose it where the client
    /// address is not meaningful (one gateway, one address).
    Account,
}

/// What a store holds for one [`ThrottleSubject`]: the consecutive failures
/// and when the last one was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottleState {
    /// Consecutive wrong guesses since the key was last cleared or forgotten.
    pub failures: u32,
    /// When the last of them was recorded, on the store's clock.
    pub last_failure_at: axess_clock::Timestamp,
}

/// The key one throttle entry is read and recorded under: built by
/// [`Throttle::subject`] from the request, so a store never decides what
/// the policy keys on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThrottleSubject {
    /// The tenant of the account.
    pub tenant_id: TenantId,
    /// The account.
    pub user_id: UserId,
    /// The client address, under [`ThrottleKey::AccountAndAddress`] when
    /// the request resolved one: an IPv6 address as its /64 prefix, one that
    /// carries an IPv4 client (IPv4-mapped, NAT64, IPv4-translated or
    /// -compatible, 6to4, Teredo) as that IPv4 address. `None` under
    /// [`ThrottleKey::Account`] and for a request with no resolved address.
    pub address: Option<IpAddr>,
}

impl Throttle {
    /// The delay after `failures` consecutive wrong guesses:
    /// `first_delay * 2^(failures - 1)`, capped at `max_delay`; zero for no
    /// failures and for a zero `first_delay`.
    pub fn delay_after(&self, failures: u32) -> Duration {
        if failures == 0 || self.first_delay.is_zero() {
            return Duration::ZERO;
        }
        let doublings = failures - 1;
        let delay = if doublings >= 32 {
            self.max_delay
        } else {
            self.first_delay
                .checked_mul(1u32 << doublings)
                .unwrap_or(self.max_delay)
        };
        delay.min(self.max_delay)
    }

    /// How long after its last failure a key is as good as absent: twice
    /// `max_delay`. A store forgets keys older than this; the library reads
    /// one as no state.
    pub fn forget_after(&self) -> Duration {
        self.max_delay.saturating_mul(2)
    }

    /// Whether `state` is older than [`forget_after`](Self::forget_after)
    /// at `now`.
    pub fn is_stale(&self, state: &ThrottleState, now: axess_clock::Timestamp) -> bool {
        match axess_clock::SignedDuration::try_from(self.forget_after()) {
            Ok(keep) => now.since(state.last_failure_at) > keep,
            // A span too long to represent is never exceeded.
            Err(_) => false,
        }
    }

    /// How long a guess at `now` must wait under `state`, or `None` when it
    /// may run: no state, a stale one, or the delay has run.
    ///
    /// The refusal is strict: at the retry time itself the guess runs. The
    /// duration carries the exact remainder; the HTTP mapping rounds it up
    /// to whole seconds.
    pub fn retry_after(
        &self,
        state: Option<&ThrottleState>,
        now: axess_clock::Timestamp,
    ) -> Option<Duration> {
        let state = state?;
        if self.is_stale(state, now) {
            return None;
        }
        let wait = self.delay_after(state.failures);
        // A delay or a retry time too large to represent is a guess that
        // waits for it, not one that runs: the throttle refuses and names
        // the delay it could not add up.
        let Ok(delay) = axess_clock::SignedDuration::try_from(wait) else {
            return Some(wait);
        };
        let Some(retry_at) = state.last_failure_at.checked_add(delay) else {
            return Some(wait);
        };
        if now >= retry_at {
            None
        } else {
            Some(Duration::try_from(retry_at.since(now)).unwrap_or(wait))
        }
    }

    /// The key a request for `user_id` of `tenant_id` from `address` is
    /// throttled under: the address is kept only under
    /// [`ThrottleKey::AccountAndAddress`], and then as its network (an IPv6
    /// address as its /64 prefix, one that carries an IPv4 client as that
    /// client), so rotating inside one /64 is one guesser and the clients of
    /// one NAT64 gateway are as many guessers as they are clients.
    pub fn subject(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        address: Option<IpAddr>,
    ) -> ThrottleSubject {
        ThrottleSubject {
            tenant_id: *tenant_id,
            user_id: *user_id,
            address: match self.key {
                ThrottleKey::AccountAndAddress => {
                    address.map(|a| crate::client_ip::network::ClientNetwork::of(a).address())
                }
                ThrottleKey::Account => None,
            },
        }
    }
}

#[cfg(test)]
mod tests;
