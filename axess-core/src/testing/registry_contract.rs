//! Conformance checks for a [`SessionRegistry`]: the one-step move of a
//! session to a new key, the key a session is under now, an ending by a key
//! the session held before, and the cut-off of a user's other sessions. They
//! hold the registries the crate ships and a registry of your own to the
//! contract the session layer and the authentication service rely on.
//!
//! Run [`assert_registry_contract`] against a fresh registry. Each check
//! uses users and keys of its own, so the registry may hold other users'
//! sessions, and reads no clock: what needs time (a lapsed entry, the bound
//! on a user's move records) is for a registry's own tests, which can move
//! its clock.

use crate::authn::ids::UserId;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{CutOff, MoveOutcome, SessionRegistry};
use axess_rng::SystemRng;

/// A user of the check's own.
fn user() -> UserId {
    UserId::new(&SystemRng)
}

/// A key of the check's own.
fn key() -> SessionKey {
    SessionKey::of(&SessionId::new(&SystemRng))
}

/// `keys` in a fixed order, so two lists compare as sets.
fn sorted(keys: &[SessionKey]) -> Vec<SessionKey> {
    let mut keys = keys.to_vec();
    keys.sort_by_key(ToString::to_string);
    keys
}

/// A cut-off's answer with its keys in a fixed order.
fn sorted_cut(cut: CutOff) -> CutOff {
    match cut {
        CutOff::KeptOne(keys) => CutOff::KeptOne(sorted(&keys)),
        CutOff::KeptNone(keys) => CutOff::KeptNone(sorted(&keys)),
        CutOff::NotHeld => CutOff::NotHeld,
    }
}

/// The registry's answer, or a panic naming the call that failed.
fn answer<T, E: std::fmt::Display>(result: Result<T, E>, call: &str) -> T {
    result.unwrap_or_else(|e| panic!("{call} failed: {e}"))
}

async fn register<R: SessionRegistry>(registry: &R, user: &UserId) -> SessionKey {
    let session = key();
    answer(registry.register(user, &session).await, "register");
    session
}

async fn valid<R: SessionRegistry>(registry: &R, user: &UserId, session: &SessionKey) -> bool {
    answer(registry.is_valid(user, session).await, "is_valid")
}

async fn listed<R: SessionRegistry>(registry: &R, user: &UserId) -> Vec<SessionKey> {
    answer(registry.active_sessions(user).await, "active_sessions")
}

async fn moved<R: SessionRegistry>(
    registry: &R,
    user: &UserId,
    old: &SessionKey,
    new: &SessionKey,
) -> MoveOutcome {
    answer(registry.move_session(user, old, new).await, "move_session")
}

async fn current<R: SessionRegistry>(
    registry: &R,
    user: &UserId,
    session: &SessionKey,
) -> Option<SessionKey> {
    answer(registry.current_key(user, session).await, "current_key")
}

async fn ended<R: SessionRegistry>(registry: &R, user: &UserId, session: &SessionKey) {
    answer(
        registry.invalidate_session(user, session).await,
        "invalidate_session",
    );
}

async fn cut<R: SessionRegistry>(registry: &R, user: &UserId, keep: &SessionKey) -> CutOff {
    sorted_cut(answer(
        registry.invalidate_other_sessions(user, keep).await,
        "invalidate_other_sessions",
    ))
}

/// Everything a registry of your own must do for the session layer and
/// the service: run it against a fresh registry.
///
/// It runs [`assert_move_contract`], [`assert_current_key_contract`],
/// [`assert_ending_by_key_contract`] and [`assert_cut_off_contract`].
///
/// # Panics
///
/// On the first rule the registry breaks, or on a registry error.
pub async fn assert_registry_contract<R: SessionRegistry>(registry: &R) {
    assert_move_contract(registry).await;
    assert_current_key_contract(registry).await;
    assert_ending_by_key_contract(registry).await;
    assert_cut_off_contract(registry).await;
}

/// [`SessionRegistry::move_session`]:
///
/// - a registered session moves, in one step, to the place it had among the
///   user's sessions, and the key it left is not valid;
/// - a session never registered, or revoked, does not move, and nothing of
///   the user changes, a session already under the new key included;
/// - a session moved to a key that was registered already takes the place
///   of the key it left, and is held once;
/// - a move to the same key renews a live entry and is `OldGone` for none.
///
/// # Panics
///
/// On the first rule the registry breaks, or on a registry error.
pub async fn assert_move_contract<R: SessionRegistry>(registry: &R) {
    // A registered session moves and keeps its place among three.
    let alice = user();
    let first = register(registry, &alice).await;
    let old = register(registry, &alice).await;
    let last = register(registry, &alice).await;
    let new = key();
    assert_eq!(
        moved(registry, &alice, &old, &new).await,
        MoveOutcome::Moved,
        "a registered session moves"
    );
    assert!(
        !valid(registry, &alice, &old).await,
        "the key a session was moved away from is not valid"
    );
    assert!(
        valid(registry, &alice, &new).await,
        "the key a session was moved to is valid"
    );
    // The order is by registration time, and this check reads no clock: the
    // three may be registered in one tick, where the order between them is
    // not promised. A registry's own tests, which move its clock, hold the
    // place a moved session keeps.
    assert_eq!(
        sorted(&listed(registry, &alice).await),
        sorted(&[first, new, last]),
        "a moved session is listed under its new key, with the others"
    );

    // A session never registered, or revoked, does not move.
    let bob = user();
    let held = register(registry, &bob).await;
    let waiting = register(registry, &bob).await;
    let before = listed(registry, &bob).await;
    let (never, target) = (key(), key());
    assert_eq!(
        moved(registry, &bob, &never, &target).await,
        MoveOutcome::OldGone,
        "a session never registered does not move"
    );
    assert!(
        !valid(registry, &bob, &target).await,
        "a move from a key never registered registers nothing"
    );
    assert_eq!(
        moved(registry, &bob, &never, &waiting).await,
        MoveOutcome::OldGone,
        "a session never registered does not move onto a registered key"
    );
    assert!(
        valid(registry, &bob, &waiting).await,
        "a key registered before a refused move stays valid"
    );
    let revoked = register(registry, &bob).await;
    answer(
        registry.invalidate_session(&bob, &revoked).await,
        "invalidate_session",
    );
    assert_eq!(
        moved(registry, &bob, &revoked, &target).await,
        MoveOutcome::OldGone,
        "a revoked session is not brought back by moving it"
    );
    assert!(
        !valid(registry, &bob, &target).await,
        "a move of a revoked session registers nothing"
    );
    assert_eq!(
        listed(registry, &bob).await,
        before,
        "a refused move changes none of the user's sessions"
    );
    assert!(valid(registry, &bob, &held).await);

    // A key that was registered already takes the place of the key it left.
    let carol = user();
    let moving = register(registry, &carol).await;
    let between = register(registry, &carol).await;
    let taken = register(registry, &carol).await;
    assert_eq!(
        moved(registry, &carol, &moving, &taken).await,
        MoveOutcome::Moved,
        "a session moves onto a key registered already"
    );
    assert_eq!(
        sorted(&listed(registry, &carol).await),
        sorted(&[taken, between]),
        "the session is held once, under the key it moved to"
    );
    assert!(!valid(registry, &carol, &moving).await);

    // A move to the same key.
    let dave = user();
    let same = register(registry, &dave).await;
    assert_eq!(
        moved(registry, &dave, &same, &same).await,
        MoveOutcome::Moved,
        "a live session moved to its own key is moved"
    );
    assert!(valid(registry, &dave, &same).await);
    assert_eq!(current(registry, &dave, &same).await, Some(same));
    let unknown = key();
    assert_eq!(
        moved(registry, &dave, &unknown, &unknown).await,
        MoveOutcome::OldGone,
        "a key never registered moved to itself is gone"
    );
    assert!(!valid(registry, &dave, &unknown).await);
    assert_eq!(listed(registry, &dave).await, vec![same]);
}

/// [`SessionRegistry::current_key`]: a live key answers itself, an unknown
/// key `None`; every key a session was moved away from answers the key it
/// is under now, after any number of moves; once the session is ended none
/// of them answers; and the records of one user's moves are not another
/// user's.
///
/// # Panics
///
/// On the first rule the registry breaks, or on a registry error.
pub async fn assert_current_key_contract<R: SessionRegistry>(registry: &R) {
    let alice = user();
    let a = register(registry, &alice).await;
    let (b, c) = (key(), key());
    assert_eq!(current(registry, &alice, &a).await, Some(a));
    assert_eq!(current(registry, &alice, &b).await, None, "an unknown key");

    assert_eq!(moved(registry, &alice, &a, &b).await, MoveOutcome::Moved);
    assert_eq!(
        current(registry, &alice, &a).await,
        Some(b),
        "a former key answers the key its session moved to"
    );
    assert_eq!(current(registry, &alice, &b).await, Some(b));

    assert_eq!(moved(registry, &alice, &b, &c).await, MoveOutcome::Moved);
    assert_eq!(
        current(registry, &alice, &a).await,
        Some(c),
        "a first former key follows every later move of its session"
    );
    assert_eq!(current(registry, &alice, &b).await, Some(c));
    assert_eq!(current(registry, &alice, &c).await, Some(c));
    for former in [a, b] {
        assert!(
            !valid(registry, &alice, &former).await,
            "a former key is not valid"
        );
    }

    // Another user knows nothing of these records.
    let mallory = user();
    let own = register(registry, &mallory).await;
    assert_eq!(
        current(registry, &mallory, &a).await,
        None,
        "a record is the user's own"
    );
    assert_eq!(
        moved(registry, &mallory, &a, &own).await,
        MoveOutcome::OldGone,
        "another user cannot move a session by its former key"
    );
    answer(
        registry.invalidate_session(&mallory, &a).await,
        "invalidate_session",
    );
    assert!(
        valid(registry, &alice, &c).await,
        "an ending by another user does not follow this user's records"
    );
    assert!(valid(registry, &mallory, &own).await);

    answer(
        registry.invalidate_session(&alice, &c).await,
        "invalidate_session",
    );
    for former in [a, b, c] {
        assert_eq!(
            current(registry, &alice, &former).await,
            None,
            "an ended session is under no key"
        );
    }
}

/// [`SessionRegistry::invalidate_session`] follows a move: an ending that
/// names a key the session held before a rotation ends the session, and
/// takes the records that led to it, so the key registered again is a
/// session of its own; an ending that names the session's present key does
/// the same.
///
/// # Panics
///
/// On the first rule the registry breaks, or on a registry error.
pub async fn assert_ending_by_key_contract<R: SessionRegistry>(registry: &R) {
    let alice = user();
    let a = register(registry, &alice).await;
    let other = register(registry, &alice).await;
    let b = key();
    assert_eq!(moved(registry, &alice, &a, &b).await, MoveOutcome::Moved);
    ended(registry, &alice, &a).await;
    assert!(
        !valid(registry, &alice, &b).await,
        "an ending by a former key ends the session"
    );
    assert_eq!(
        listed(registry, &alice).await,
        vec![other],
        "the ended session is listed no more, and the other one is"
    );
    assert_eq!(current(registry, &alice, &a).await, None);
    answer(registry.register(&alice, &b).await, "register");
    assert_eq!(
        current(registry, &alice, &a).await,
        None,
        "the ending took the record that led to the session it ended"
    );

    let bob = user();
    let first = register(registry, &bob).await;
    let (second, third) = (key(), key());
    assert_eq!(
        moved(registry, &bob, &first, &second).await,
        MoveOutcome::Moved
    );
    assert_eq!(
        moved(registry, &bob, &second, &third).await,
        MoveOutcome::Moved
    );
    ended(registry, &bob, &third).await;
    answer(registry.register(&bob, &third).await, "register");
    for former in [first, second] {
        assert_eq!(
            current(registry, &bob, &former).await,
            None,
            "an ending by the present key takes the records that led to it"
        );
    }
}

/// [`SessionRegistry::invalidate_other_sessions`]:
///
/// - a cut-off that keeps a live session ends exactly the others and the
///   records that led to them, and keeps the records of the kept one;
/// - a cut-off whose session to keep was moved by another request ends
///   every session of the user, that one included, and says so;
/// - a cut-off that names the key the session is under now keeps it,
///   however it moved before;
/// - a session moved and then revoked is not followed: nothing is ended;
/// - a key the registry does not hold for the user ends nothing.
///
/// # Panics
///
/// On the first rule the registry breaks, or on a registry error.
pub async fn assert_cut_off_contract<R: SessionRegistry>(registry: &R) {
    // A held session is kept, and only the others end.
    let alice = user();
    let keep = register(registry, &alice).await;
    let x0 = register(registry, &alice).await;
    let y = register(registry, &alice).await;
    let x = key();
    assert_eq!(moved(registry, &alice, &x0, &x).await, MoveOutcome::Moved);
    assert_eq!(
        cut(registry, &alice, &keep).await,
        CutOff::KeptOne(sorted(&[x, y])),
        "a cut-off ends exactly the other sessions"
    );
    assert!(valid(registry, &alice, &keep).await);
    for other in [x, y, x0] {
        assert!(!valid(registry, &alice, &other).await);
    }
    answer(registry.register(&alice, &x).await, "register");
    assert_eq!(
        current(registry, &alice, &x0).await,
        None,
        "the cut-off took the records of the sessions it ended"
    );

    // A session to keep that another request moved ends with the rest.
    let bob = user();
    let a = register(registry, &bob).await;
    let x = register(registry, &bob).await;
    let y = register(registry, &bob).await;
    let b = key();
    assert_eq!(moved(registry, &bob, &a, &b).await, MoveOutcome::Moved);
    assert_eq!(
        cut(registry, &bob, &a).await,
        CutOff::KeptNone(sorted(&[b, x, y])),
        "a cut-off whose session to keep was moved ends every session, that one included"
    );
    for session in [a, b, x, y] {
        assert!(!valid(registry, &bob, &session).await);
    }
    assert_eq!(listed(registry, &bob).await, Vec::new());
    assert_eq!(current(registry, &bob, &a).await, None);

    // A cut-off that names the key the session is under now keeps it.
    let carol = user();
    let a = register(registry, &carol).await;
    let x = register(registry, &carol).await;
    let y = register(registry, &carol).await;
    let b = key();
    assert_eq!(moved(registry, &carol, &a, &b).await, MoveOutcome::Moved);
    assert_eq!(
        cut(registry, &carol, &b).await,
        CutOff::KeptOne(sorted(&[x, y])),
        "a cut-off that names the present key keeps the caller"
    );
    assert!(valid(registry, &carol, &b).await);
    assert_eq!(
        current(registry, &carol, &a).await,
        Some(b),
        "the kept session keeps the records that lead to it"
    );

    // A session moved and then revoked is not followed.
    let dave = user();
    let a = register(registry, &dave).await;
    let x = register(registry, &dave).await;
    let b = key();
    assert_eq!(moved(registry, &dave, &a, &b).await, MoveOutcome::Moved);
    ended(registry, &dave, &b).await;
    assert_eq!(
        cut(registry, &dave, &a).await,
        CutOff::NotHeld,
        "a record whose session was revoked is not followed"
    );
    assert!(valid(registry, &dave, &x).await, "nothing was ended");

    // A key the registry does not hold for the user ends nothing.
    let erin = user();
    let held = register(registry, &erin).await;
    let theirs = register(registry, &user()).await;
    for stranger in [key(), theirs] {
        assert_eq!(cut(registry, &erin, &stranger).await, CutOff::NotHeld);
        assert!(valid(registry, &erin, &held).await, "nothing was ended");
    }
}
