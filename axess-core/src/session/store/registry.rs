//! The [`SessionRegistry`] trait: which sessions of a user are valid, the
//! one-step move of a session to a new key, and the records a move leaves.

use crate::authn::ids::UserId;
use crate::session::id::SessionKey;
use std::future::Future;

/// What [`SessionRegistry::move_session`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum MoveOutcome {
    /// The registry holds the session under `new` and no longer under `old`.
    Moved,
    /// The registry held no live entry under `old`. Nothing was changed.
    OldGone,
    /// The user holds [`MAX_MOVE_RECORDS_PER_USER`] move records and every
    /// one is the first former key of a live session, so none can be given
    /// up. Nothing was changed: the session is still under `old`.
    Full,
}

/// What [`SessionRegistry::invalidate_other_sessions`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum CutOff {
    /// The registry holds the session to keep: every other session of the
    /// user was ended, and these are their keys.
    KeptOne(Vec<SessionKey>),
    /// The session to keep had been moved to another key before this step
    /// ran, so every session of the user was ended, that one included; these
    /// are their keys.
    KeptNone(Vec<SessionKey>),
    /// The registry holds no session under the key to keep and no record
    /// of a move from it. Nothing was ended.
    NotHeld,
}

/// How many move records a registry keeps for one user. It bounds the work
/// of every registry step that reads a user's records, whatever a session
/// does. At the bound a move gives up the oldest record that is not the
/// first former key of its session (the key its entry was registered
/// under, which a provider's logout looks a session up by), so a session
/// that rotates on every request is never ended for it.
pub const MAX_MOVE_RECORDS_PER_USER: usize = 1024;

/// Tracks which sessions are valid for each user, enabling forced logout.
///
/// Implementors: [`MemorySessionRegistry`](super::MemorySessionRegistry),
/// `ValkeySessionRegistry`.
///
/// A session is named by its [`SessionKey`], the name the session store and
/// the audit records give it, never by the value its cookie carries: a
/// registry's members, and every list it returns, hold no credential.
///
/// All methods accept the typed [`UserId`] so the trait surface cannot
/// accidentally degrade to `&str` at the storage boundary; implementations
/// that need the underlying string can call `.as_str()`.
///
/// # Moves and their records
///
/// A rotation moves a session to a new key in one step,
/// [`move_session`](Self::move_session). The move leaves a record per user:
/// "the session that was under this former key is under that key now". Each
/// record has its place in the order the user's moves were made. A record's
/// target is always the key the session is under at present: a move
/// re-points every record that led to the key it moves, so resolving a
/// former key is one hop, never a chain, and no ring can form. The records
/// whose target is one key are the former keys of one session; the earliest
/// of them is the session's first former key, the key its entry was
/// registered under, which is what a provider's logout and the sid store
/// know it by.
///
/// A record lives as long as the entry it leads to, unless the bound
/// [`MAX_MOVE_RECORDS_PER_USER`] gives it up first (never a first former
/// key). It is removed in the step that removes that entry: an ending by
/// key, the cut-off of a user's other sessions, the removal of all of a
/// user's sessions. A record whose target has lapsed is not followed, and
/// is removed by the user's next move, cut-off or ending by key. Its
/// lifetime has no setting of its own: it is the entry's, which the
/// registry's own lifetime governs. [`register`](Self::register) removes a
/// record kept under the key it registers: a registered key is not a former
/// one.
///
/// What a holder of a former key can rely on: the first former key of a
/// session finds it for as long as the session lives; any other former key
/// finds it until the session has rotated past the bound since, which a
/// holder of a key read a moment ago (a request in flight, a list just read)
/// does not reach.
///
/// A record never grants anything. It is written only by a move from a live
/// entry, it is per user, and it leads only along the moves of one session.
/// [`is_valid`](Self::is_valid) and
/// [`watch_revocation`](Self::watch_revocation) never read one: a moved key
/// is not valid.
///
/// `testing::registry_contract::assert_registry_contract` holds a registry
/// to this.
pub trait SessionRegistry: Send + Sync + Clone + 'static {
    /// The error type returned by registry operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Register a session as belonging to a user. A move record kept under
    /// `session` as a former key is removed.
    fn register(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Return `true` if the given session is still valid for the user. A
    /// key the session was moved away from is not valid.
    fn is_valid(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Invalidate all sessions for a user (e.g. global logout, credential
    /// rotation), and every move record of the user with them.
    fn invalidate_user(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// End one session of a user, by the key it is under or by a key it was
    /// under before a move, as one step of the store: the entry
    /// [`current_key`](Self::current_key) names is ended when there is one,
    /// anything left under `session` itself is removed, and so are the
    /// records that led to what was ended. So an ending that names a key the
    /// session held before a rotation (the session limit's eviction from a
    /// list read a moment earlier, a provider's logout by the key it knows)
    /// ends the session.
    fn invalidate_session(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// End every session of a user but `keep`, as one step of the store.
    ///
    /// - `keep` is a live entry: every other entry of the user is ended, and
    ///   every record that does not lead to `keep`;
    ///   [`CutOff::KeptOne`] with their keys.
    /// - `keep` is not live, and the record kept under it leads to a live
    ///   entry: every entry of the user is ended, that one included, and
    ///   every record of the user is removed; [`CutOff::KeptNone`] with
    ///   their keys.
    /// - Otherwise nothing is ended: [`CutOff::NotHeld`].
    ///
    /// Why a moved `keep` ends the moved session too: a cut-off names the
    /// session to keep by the key the caller's request holds. When that key
    /// was moved meanwhile, another request that carried the same cookie
    /// rotated the session, and the new cookie went to whoever sent that
    /// request. A second tab of the same person and someone who copied the
    /// cookie hold the same value, and nothing the registry holds tells them
    /// apart. A credential change is the moment a person evicts a thief; it
    /// must not leave a copied cookie's session as the one that survives. So
    /// the step ends it with the rest and says so with an answer of its own,
    /// and the person signs in again with the new credential. An honest race
    /// of two tabs costs one sign-in.
    ///
    /// The caller is kept when its own request holds the current key: a
    /// cut-off that names the key the registry holds the session under
    /// finds a live entry and answers `KeptOne`, whatever the session's
    /// earlier keys were. After a cut-off that answers `KeptOne` or
    /// `KeptNone`, no session of the user that was registered before the
    /// step remains except, for `KeptOne`, the entry under `keep`.
    ///
    /// The step is the cut-off of a credential change, so no other registry
    /// call may fall inside it: every session the registry holds for the
    /// user when it runs is ended or kept as above when it returns, and a
    /// session registered after it is a sign-in that came later. A listing
    /// followed by one invalidation per session does not do: a session that
    /// registers, or moves to a new key, between the listing and its turn
    /// would outlive the cut-off. Take one lock, or run one server-side
    /// script, over the user's whole set.
    ///
    /// **This method is required**: a registry that ended the other
    /// sessions one by one would report a cut-off it had not made.
    fn invalidate_other_sessions(
        &self,
        user_id: &UserId,
        keep: &SessionKey,
    ) -> impl Future<Output = Result<CutOff, Self::Error>> + Send;

    /// Move the session under `old` to `new`, as one step of the store: no
    /// other call on the same user falls inside it.
    ///
    /// - When the registry holds a live entry under `old` for the user, it
    ///   holds the session under `new` and nothing under `old` afterwards.
    ///   `new` takes the registration time `old` had, so its place in the
    ///   oldest-first order of [`active_sessions`](Self::active_sessions)
    ///   (which the session limit evicts by) does not move among sessions
    ///   registered at other times, and is last seen
    ///   now. A record from `old` to `new` is written, every record that led
    ///   to `old` leads to `new`, and no record is kept under `new` as a
    ///   former key. The answer is [`MoveOutcome::Moved`], whether or not
    ///   `new` was registered already: an entry found under `new` takes
    ///   `old`'s registration time.
    /// - When it holds no live entry under `old` (never registered, revoked,
    ///   lapsed), nothing changes, `new` included, and the answer is
    ///   [`MoveOutcome::OldGone`]: a session that was revoked is not brought
    ///   back by moving it.
    /// - When `old == new`, the answer is `Moved` with the last-seen time
    ///   renewed for a live entry, `OldGone` otherwise, and no record is
    ///   written.
    /// - When the user already holds [`MAX_MOVE_RECORDS_PER_USER`] records
    ///   whose targets are live, the move first gives up one record, then
    ///   proceeds as above: the earliest record of the user, in the order
    ///   the moves were made, that is not the first former key of its
    ///   session, whichever session's it is. Only when every record is the
    ///   first former key of a live session does nothing change, and the
    ///   answer is [`MoveOutcome::Full`].
    ///
    /// A move publishes nothing and wakes no watcher: a watcher of `old`
    /// finds it no longer valid at its next check.
    ///
    /// **This method is required**: a registration of `new` followed by a
    /// removal of `old` holds both keys between the two, and a cut-off or a
    /// revocation that lands there misses one of them.
    fn move_session(
        &self,
        user_id: &UserId,
        old: &SessionKey,
        new: &SessionKey,
    ) -> impl Future<Output = Result<MoveOutcome, Self::Error>> + Send;

    /// The key a session is under now: `session` itself when the registry
    /// holds a live entry under it; otherwise the target of the move record
    /// kept under `session`, when that target is live; otherwise `None`. It
    /// reads and changes nothing, and does not renew the entry.
    ///
    /// **This method is required**: a caller that holds a key from before a
    /// rotation (a provider's logout, the sid store) finds the session by it.
    fn current_key(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> impl Future<Output = Result<Option<SessionKey>, Self::Error>> + Send;

    /// Return the keys of all active sessions of a user, ordered oldest
    /// first: by the time each was registered, a moved session by the time
    /// of the key it left. Two sessions registered at the same time, to the
    /// resolution of the registry's clock, are equally old and in no
    /// promised order between them.
    ///
    /// Used by the concurrent-session-limit enforcement on
    /// [`AuthnServiceBuilder::with_max_sessions_per_user`](crate::authn::service::AuthnServiceBuilder::with_max_sessions_per_user)
    /// to FIFO-evict the oldest session when a new login would cross the
    /// cap. **This method is required**: a silent empty result here
    /// disables the limit without any warning, which is a security
    /// regression on every deployment using the cap. Backends that
    /// genuinely cannot enumerate (rare) should panic with
    /// `unimplemented!` so misconfiguration surfaces loudly, not
    /// silently.
    fn active_sessions(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<Vec<SessionKey>, Self::Error>> + Send;

    /// Resolve when the named session is invalidated (on this or another
    /// node), otherwise stay pending. Lets long-lived connections
    /// (WebSocket, SSE) react proactively to revocation rather than
    /// discovering it on the next message attempt. The future never
    /// resolves except on actual revocation, so `select!` callers don't
    /// need to guard against spurious wakeups.
    ///
    /// The default impl returns `std::future::pending()`; backends
    /// without push support (memory, SQLite without LISTEN/NOTIFY) thus
    /// compile but won't surface revocations. `ValkeySessionRegistry`
    /// overrides via Redis pub/sub.
    fn watch_revocation(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> impl Future<Output = ()> + Send {
        let _ = (user_id, session);
        std::future::pending()
    }
}
