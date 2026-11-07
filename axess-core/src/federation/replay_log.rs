//! [`LogoutReplayLog`]: the replay log of back-channel logout tokens, behind a
//! trait so instances can share it.
//!
//! The handler refuses a logout token whose `(issuer, jti)` it has seen
//! inside the `iat` acceptance window. The in-process log (the default) is
//! per instance: a captured token can be replayed to another instance inside
//! the window, and the log empties on restart. Replaying a logout token only
//! logs the user out again, but the shared implementation closes it: the
//! Valkey one, `ValkeyReplayLog` (behind the `valkey` feature), is read by
//! every instance, and its keys expire with the window.
//!
//! Wire it with
//! [`BackChannelLogoutHandler::with_replay_log`](super::backchannel_logout::BackChannelLogoutHandler::with_replay_log).

use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, Utc};

/// A [`LogoutReplayLog`] call in flight.
pub type ReplayFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ReplayLogError>> + Send + 'a>>;

/// The backing store of a [`LogoutReplayLog`] failed. The handler answers a
/// retryable `503`: the token was not recorded, so the IdP's retry is acted
/// on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("logout replay log: {0}")]
pub struct ReplayLogError(pub String);

/// What recording a pair did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    /// The pair was new and is now held.
    New,
    /// The log still holds the pair and the token it came from has been
    /// acted on: a replay.
    Replay,
    /// The log holds the pair, and the first delivery of the token is still
    /// being acted on: it may yet fail and leave the pair forgotten, so the
    /// resend is asked to come again, not refused.
    InFlight,
    /// The pair is new but the issuer's partition is full of live entries
    /// and has no room. Nothing was recorded or forgotten.
    Full,
}

/// The `(issuer, jti)` pairs of recently seen logout tokens.
pub trait LogoutReplayLog: Send + Sync + 'static {
    /// Record the pair as seen at `now`. A new pair is in flight until
    /// [`settle`](Self::settle) or [`forget`](Self::forget); a second
    /// delivery meanwhile is [`Recorded::InFlight`]. Entries older than the
    /// logout-token retention window are no longer held.
    fn record<'a>(
        &'a self,
        issuer: &'a str,
        jti: &'a str,
        now: DateTime<Utc>,
    ) -> ReplayFuture<'a, Recorded>;

    /// The action on the pair's token ended: its pair is a replay from now on.
    fn settle<'a>(&'a self, issuer: &'a str, jti: &'a str) -> ReplayFuture<'a, ()>;

    /// Forget the pair, so the same token is accepted again: the handler
    /// could not carry the logout out, and the IdP's retry must not be
    /// refused as a replay.
    fn forget<'a>(&'a self, issuer: &'a str, jti: &'a str) -> ReplayFuture<'a, ()>;
}
