//! [`IdentityAuthnLog`]: the per-attempt writes of the login pipeline.

use super::IdentityLookup;
use crate::authn::{
    event::AuthEvent,
    ids::UserId,
    types::{Throttle, ThrottleState, ThrottleSubject},
};

// ── IdentityAuthnLog ─────────────────────────────────────────────────────────

/// What an audit sink did with an event.
///
/// Distinguishes "I deliberately dropped this" from "I am broken", which
/// `Result<(), E>` alone cannot express: an `Err` fails the login, and an
/// `Ok(())` claims a write that may not have happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditOutcome {
    /// The event was durably recorded.
    #[default]
    Recorded,
    /// The event was deliberately dropped under load.
    ///
    /// The flow continues and `AuditMetrics::audit_event_shed` fires. A
    /// gap in the trail is the cost; it is bounded and observable, where
    /// an exhausted store is neither.
    Shed,
}

/// Per-authn-attempt writes the login pipeline emits: audit events,
/// failed-attempt lockout counter, the throttle entry per guesser,
/// last-login timestamp.
///
/// Required by `AuthnService::new`; any backend that drives a live login
/// flow must implement this tier. SCIM-provisioned deployments that handle
/// user lifecycle out-of-band still implement this so login can record
/// audit + enforce lockout, but skip [`IdentityAdmin`](super::IdentityAdmin) entirely.
///
/// Adopters that explicitly do NOT want audit / lockout / throttle /
/// last-login can wrap their [`IdentityLookup`] in
/// [`NoopAuthnLog`](super::NoopAuthnLog) (see the testing module) to satisfy
/// the bound with no-op behaviour.
pub trait IdentityAuthnLog: IdentityLookup {
    /// Record an authentication event (audit log).
    ///
    /// Returning `Err` **fails the authentication**: an authentication that
    /// leaves no evidence has not, for evidence purposes, happened. Reserve
    /// it for a sink that is genuinely broken.
    ///
    /// Returning [`AuditOutcome::Shed`] says the event was deliberately
    /// dropped under load, and the flow continues. That is the valve for
    /// the one hazard this design creates: every failed login writes a row,
    /// including for identifiers that do not exist, so an unauthenticated
    /// caller can drive writes at your storage, and with no way to shed,
    /// exhausting it turns every login into a failure for every user.
    ///
    /// **Shed on a criterion independent of the identifier**: a global
    /// rate, a queue depth, a disk watermark. Shedding based on anything
    /// derived from *which* identifier was tried makes the drop observable
    /// per-identifier and reintroduces the user-enumeration oracle that
    /// emitting unattributed events exists to close.
    ///
    /// Note what shedding costs under attack: the flood that triggers it
    /// is the thing you least want unrecorded. If you shed selectively,
    /// prefer dropping by
    /// [`event_status`](crate::authn::event::AuthEvent::event_status) or
    /// [`event_type`](crate::authn::event::AuthEvent::event_type)
    /// successes before failures, say, because both are independent of
    /// the identifier and keep the security-relevant signal. Dropping
    /// uniformly is safe too, and simpler.
    fn record_event(
        &self,
        event: AuthEvent,
    ) -> impl std::future::Future<Output = Result<AuditOutcome, Self::Error>> + Send;

    /// Increment the failed attempt counter for a user. Returns the new count.
    ///
    /// The returned value is compared directly against
    /// [`LockoutPolicy::max_attempts`](crate::authn::types::LockoutPolicy),
    /// so the increment and the read **MUST** be atomic with respect to other
    /// writes: a single `UPDATE ... SET n = n + 1 RETURNING n`, or an
    /// equivalent the backend guarantees. A read-modify-write that loads the
    /// count, adds one and stores it back loses updates under concurrent
    /// failures, and an attacker running parallel attempts gets more of them
    /// than the policy allows.
    fn record_failed_attempt(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<u32, Self::Error>> + Send;

    /// The failed attempt counter for a user and when the last failure was
    /// recorded: `(count, last_failure_at)`.
    ///
    /// This is what makes a lockout enforceable. The library derives the
    /// lockout from it with the tenant's
    /// [`LockoutPolicy`](crate::authn::types::LockoutPolicy), so a store need
    /// not (and a conforming one does not have to) flip
    /// [`account_status`](IdentityLookup::account_status) to suspended. Return
    /// `(0, None)` for a user with no failures. Failures older than the
    /// policy's `attempt_window` should be reported as zero while the count
    /// is below `policy.effective_max_attempts()`, the same expiry
    /// [`record_failed_attempt`](Self::record_failed_attempt) applies when it
    /// counts. At or above the limit the raw count and time are returned
    /// whatever their age: the window bounds how long failures accumulate,
    /// and the library derives the lockout's end from `policy.duration`, so
    /// a store that zeroed an at-limit count after the window would end a
    /// lockout that is indefinite (`duration` is `None`) or longer than the
    /// window.
    ///
    /// [`record_failed_attempt`](Self::record_failed_attempt) must store the
    /// time of the failure it counts, and
    /// [`reset_failed_attempts`](Self::reset_failed_attempts) must clear it.
    /// There is deliberately no default body: a store that silently reported
    /// zero would leave every account unlockable.
    fn failed_attempts(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<
        Output = Result<(u32, Option<chrono::DateTime<chrono::Utc>>), Self::Error>,
    > + Send;

    /// Reserve one guess against the failure counter **before** the
    /// credential is checked.
    ///
    /// Returns `Some(count)` with the counter already incremented (and the
    /// time of the attempt stored, as
    /// [`record_failed_attempt`](Self::record_failed_attempt) does) while the
    /// account is under its limit, and `None`, changing nothing, when it is
    /// at it. The test and the increment **MUST** be one atomic step
    /// (`UPDATE ... SET n = n + 1 WHERE ... RETURNING n`, a Lua script, a
    /// locked entry): with a read followed by a write, N parallel guesses all
    /// read a count below the limit and all run their verifier, so an
    /// attacker gets N guesses past `max_attempts`, and a read replica
    /// widens the window further.
    ///
    /// The rule, in terms of the stored `(count, last_failure_at)` and the
    /// `policy` of the user's tenant, at the store's `now`:
    ///
    /// 1. The count is **fresh**, that is zero, when there is no failure,
    ///    when the last one is older than `policy.attempt_window` and the
    ///    count is below `policy.effective_max_attempts()`, or when the count
    ///    has reached `policy.effective_max_attempts()` and a timed lockout
    ///    (`policy.duration` is `Some`) has run out. A lockout that has ended
    ///    starts the account over rather than relocking it on the next guess.
    ///    A count at the limit is never freshened by the window alone: with
    ///    `duration` `None`, or longer than the window, the lockout outlives
    ///    the window and ends only with the timed lockout or
    ///    [`reset_failed_attempts`](Self::reset_failed_attempts).
    /// 2. A fresh count is replaced by one. Otherwise the guess is granted
    ///    (count plus one) while the count is below
    ///    `policy.effective_max_attempts()`, and refused with `None` once it
    ///    is not.
    ///
    /// The library calls this once per credential check. A wrong credential
    /// keeps the reservation, and the library does not call
    /// [`record_failed_attempt`](Self::record_failed_attempt) for it; a right
    /// one gives it back with [`release_attempt`](Self::release_attempt). A
    /// request cancelled between the two therefore still counts as a guess.
    fn reserve_attempt(
        &self,
        user_id: &UserId,
        policy: &crate::authn::types::LockoutPolicy,
    ) -> impl std::future::Future<Output = Result<Option<u32>, Self::Error>> + Send;

    /// Give back one reservation made by
    /// [`reserve_attempt`](Self::reserve_attempt), after the credential
    /// verified. Never takes the counter below zero, and clears the stored
    /// failure time when the counter reaches zero. Failures that preceded the
    /// reservation stay counted until
    /// [`reset_failed_attempts`](Self::reset_failed_attempts) runs at the end
    /// of a successful login.
    fn release_attempt(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// The throttle entry under `key`: the consecutive wrong guesses and
    /// when the last was recorded, or `None` when nothing is recorded.
    ///
    /// The library reads it before every guess and applies the tenant's
    /// [`Throttle`]; an entry older than
    /// [`Throttle::forget_after`] reads as no state whatever a store
    /// returns, so a store may return a stale entry or have forgotten it.
    /// There is deliberately no default body, for the reason
    /// [`failed_attempts`](Self::failed_attempts) gives: a store that
    /// silently reported nothing would leave every account unthrottled.
    fn throttle_state(
        &self,
        key: &ThrottleSubject,
    ) -> impl std::future::Future<Output = Result<Option<ThrottleState>, Self::Error>> + Send;

    /// Record one more consecutive wrong guess under `key`, at the store's
    /// now.
    ///
    /// The read and the increment **MUST** be one atomic step, as
    /// [`record_failed_attempt`](Self::record_failed_attempt) is: an upsert
    /// (`INSERT ... ON CONFLICT DO UPDATE SET failures = failures + 1`), a
    /// locked entry. A read followed by a write loses updates under parallel
    /// failures, and a guesser running parallel guesses earns a shorter
    /// delay than the policy sets. An entry older than
    /// `throttle.forget_after()` starts over at one rather than adding to a
    /// count that no longer applies. Entries must not grow without bound:
    /// forget those older than `throttle.forget_after()` here, in the same
    /// statement or a sweep beside it, as the sqlite example does.
    fn record_throttle_failure(
        &self,
        key: &ThrottleSubject,
        throttle: &Throttle,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Forget the entry under `key`: a right guess clears the throttle.
    fn clear_throttle(
        &self,
        key: &ThrottleSubject,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Reset the failed attempt counter (call after successful authentication).
    fn reset_failed_attempts(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Record the timestamp of a successful authentication for a user.
    ///
    /// Called automatically by `complete_factor_step` when all factors pass.
    /// A store without a "last login" column answers `Ok(())`; a decorator
    /// forwards to the store it wraps.
    fn record_last_login(
        &self,
        user_id: &UserId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}
