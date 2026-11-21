use super::*;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{CutOff, CycleOutcome};
use axess_rng::SystemRng;

fn uid(s: &str) -> crate::authn::ids::UserId {
    axess_identity::testing::user(s)
}

/// `active_sessions` returns sessions in registration order, oldest
/// first. The `max_sessions_per_user` eviction loop in
/// `complete_factor_step` takes from the head and depends on this
/// ordering to evict the oldest session, so the Vec representation
/// in `MemorySessionRegistry` is load-bearing.
#[tokio::test]
async fn active_sessions_returns_oldest_first() {
    let registry = MemorySessionRegistry::new();
    let user = uid("u1");
    let rng = SystemRng;
    let s1 = SessionKey::of(&SessionId::new(&rng));
    let s2 = SessionKey::of(&SessionId::new(&rng));
    let s3 = SessionKey::of(&SessionId::new(&rng));

    registry.register(&user, &s1).await.unwrap();
    registry.register(&user, &s2).await.unwrap();
    registry.register(&user, &s3).await.unwrap();

    let active = registry.active_sessions(&user).await.unwrap();
    assert_eq!(
        active,
        vec![s1, s2, s3],
        "registration order must be preserved (oldest first)"
    );
}

/// Re-registering an already-present session id is a no-op,
/// not an append. Otherwise concurrent legitimate session-touches
/// would each push a duplicate, breaking the FIFO eviction contract
/// (the duplicate would advance the id to the tail, making it look
/// "newest" relative to its earlier siblings).
#[tokio::test]
async fn active_sessions_dedup_on_reregister() {
    let registry = MemorySessionRegistry::new();
    let user = uid("u1");
    let rng = SystemRng;
    let s1 = SessionKey::of(&SessionId::new(&rng));
    let s2 = SessionKey::of(&SessionId::new(&rng));

    registry.register(&user, &s1).await.unwrap();
    registry.register(&user, &s2).await.unwrap();
    registry.register(&user, &s1).await.unwrap();

    let active = registry.active_sessions(&user).await.unwrap();
    assert_eq!(
        active,
        vec![s1, s2],
        "re-register of s1 must keep the original FIFO position, not push a duplicate"
    );
}

/// Invalidating a single session removes it from the order,
/// leaving the rest intact and re-`active_sessions` reflects the
/// shorter list.
#[tokio::test]
async fn invalidate_session_removes_from_order() {
    let registry = MemorySessionRegistry::new();
    let user = uid("u1");
    let rng = SystemRng;
    let s1 = SessionKey::of(&SessionId::new(&rng));
    let s2 = SessionKey::of(&SessionId::new(&rng));
    let s3 = SessionKey::of(&SessionId::new(&rng));

    registry.register(&user, &s1).await.unwrap();
    registry.register(&user, &s2).await.unwrap();
    registry.register(&user, &s3).await.unwrap();

    registry.invalidate_session(&user, &s2).await.unwrap();

    let active = registry.active_sessions(&user).await.unwrap();
    assert_eq!(
        active,
        vec![s1, s3],
        "invalidate_session removes the named id while preserving the rest in order"
    );
    assert!(!registry.is_valid(&user, &s2).await.unwrap());
}

/// `active_sessions` for an unknown user returns the empty vec, not
/// an error; the eviction loop should treat "no registered
/// sessions" as a fresh slate.
#[tokio::test]
async fn active_sessions_unknown_user_returns_empty() {
    let registry = MemorySessionRegistry::new();
    let active = registry.active_sessions(&uid("ghost")).await.unwrap();
    assert!(active.is_empty());
}

/// `invalidate_user` removes ALL sessions for the user.
#[tokio::test]
async fn invalidate_user_removes_all_sessions() {
    let registry = MemorySessionRegistry::new();
    let user = uid("u1");
    let rng = SystemRng;
    let s1 = SessionKey::of(&SessionId::new(&rng));
    let s2 = SessionKey::of(&SessionId::new(&rng));

    registry.register(&user, &s1).await.unwrap();
    registry.register(&user, &s2).await.unwrap();
    assert!(registry.is_valid(&user, &s1).await.unwrap());
    assert!(registry.is_valid(&user, &s2).await.unwrap());

    registry.invalidate_user(&user).await.unwrap();

    assert!(
        !registry.is_valid(&user, &s1).await.unwrap(),
        "invalidate_user must remove s1"
    );
    assert!(
        !registry.is_valid(&user, &s2).await.unwrap(),
        "invalidate_user must remove s2"
    );
    assert!(
        registry.active_sessions(&user).await.unwrap().is_empty(),
        "active_sessions must be empty after invalidate_user"
    );
}

/// `invalidate_user` for one user must not affect another.
#[tokio::test]
async fn invalidate_user_does_not_affect_other_users() {
    let registry = MemorySessionRegistry::new();
    let alice = uid("alice");
    let bob = uid("bob");
    let rng = SystemRng;
    let s_alice = SessionKey::of(&SessionId::new(&rng));
    let s_bob = SessionKey::of(&SessionId::new(&rng));

    registry.register(&alice, &s_alice).await.unwrap();
    registry.register(&bob, &s_bob).await.unwrap();

    registry.invalidate_user(&alice).await.unwrap();

    assert!(!registry.is_valid(&alice, &s_alice).await.unwrap());
    assert!(
        registry.is_valid(&bob, &s_bob).await.unwrap(),
        "bob's session must survive alice's invalidate_user"
    );
}

/// MemorySessionStore HealthCheck returns Healthy.
#[tokio::test]
async fn memory_store_health_check_returns_healthy() {
    use crate::health::HealthCheck;
    let store = MemorySessionStore::new();
    let status = store.check().await;
    assert_eq!(status, HealthStatus::Healthy);
}

/// MemorySessionRegistry HealthCheck returns Healthy.
#[tokio::test]
async fn memory_registry_health_check_returns_healthy() {
    use crate::health::HealthCheck;
    let registry = MemorySessionRegistry::new();
    let status = registry.check().await;
    assert_eq!(status, HealthStatus::Healthy);
}

/// Cycle atomically moves session data to a new id.
#[tokio::test]
async fn cycle_moves_data_to_new_id() {
    let store = MemorySessionStore::new();
    let rng = SystemRng;
    let old_id = SessionKey::of(&SessionId::new(&rng));
    let new_id = SessionKey::of(&SessionId::new(&rng));
    let data = SessionData::default();

    store
        .save(&old_id, &data, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(
        store
            .cycle(&old_id, &new_id, &data, Duration::from_secs(60), true)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );

    assert!(
        store.load(&old_id).await.unwrap().is_none(),
        "old id must be gone after cycle"
    );
    assert!(
        store.load(&new_id).await.unwrap().is_some(),
        "new id must have the data after cycle"
    );
}

/// A user whose last session is invalidated leaves no entry behind, so a
/// long-running process that sees many users does not keep an empty list for
/// each.
#[tokio::test]
async fn invalidating_the_last_session_of_a_user_drops_the_users_entry() {
    let registry = MemorySessionRegistry::new();
    let user = uid("u1");
    let s1 = SessionKey::of(&SessionId::new(&SystemRng));

    registry.register(&user, &s1).await.unwrap();
    registry.invalidate_session(&user, &s1).await.unwrap();

    assert!(
        crate::locked::lock(&registry.valid).is_empty(),
        "no empty per-user list is kept"
    );
}

fn registry_on(
    clock: &axess_clock::testing::MockClock,
    ttl: std::time::Duration,
) -> MemorySessionRegistry {
    MemorySessionRegistry::new()
        .with_ttl(ttl)
        .with_clock(Arc::new(clock.clone()))
}

fn mock_clock() -> axess_clock::testing::MockClock {
    axess_clock::testing::MockClock::at(
        axess_clock::Timestamp::from_unix_seconds(1_800_000_000).expect("in range"),
    )
}

/// An entry nobody used is not valid once the TTL has passed, and is not
/// listed either.
#[tokio::test]
async fn an_unused_entry_is_not_valid_past_the_ttl() {
    let clock = mock_clock();
    let registry = registry_on(&clock, std::time::Duration::from_secs(3600));
    let user = uid("u1");
    let s1 = SessionKey::of(&SessionId::new(&SystemRng));
    registry.register(&user, &s1).await.unwrap();
    clock.advance_secs(3599);
    assert!(registry.is_valid(&user, &s1).await.unwrap());
    // The check above renewed the entry (half the TTL had gone); stay unused.
    clock.advance_secs(3601);
    assert!(!registry.is_valid(&user, &s1).await.unwrap());
    assert!(registry.active_sessions(&user).await.unwrap().is_empty());
}

/// An expired entry is gone once a new session registers.
#[tokio::test]
async fn an_expired_entry_is_dropped_by_the_next_register() {
    let clock = mock_clock();
    let registry = registry_on(&clock, std::time::Duration::from_secs(3600));
    let user = uid("u1");
    let rng = SystemRng;
    let old = SessionKey::of(&SessionId::new(&rng));
    let fresh = SessionKey::of(&SessionId::new(&rng));
    registry.register(&user, &old).await.unwrap();
    clock.advance_secs(3601);
    registry.register(&user, &fresh).await.unwrap();
    assert_eq!(
        crate::locked::lock(&registry.valid)
            .get(user.to_string().as_str())
            .unwrap()
            .sessions
            .len(),
        1
    );
    assert_eq!(registry.active_sessions(&user).await.unwrap(), vec![fresh]);
}

/// A session that is used keeps its entry past the TTL it was registered with.
#[tokio::test]
async fn a_used_session_outlives_the_ttl() {
    let clock = mock_clock();
    let registry = registry_on(&clock, std::time::Duration::from_secs(3600));
    let user = uid("u1");
    let s1 = SessionKey::of(&SessionId::new(&SystemRng));
    registry.register(&user, &s1).await.unwrap();
    for _ in 0..4 {
        clock.advance_secs(1900);
        assert!(registry.is_valid(&user, &s1).await.unwrap());
    }
}

/// Entries of users who never come back are dropped by other users'
/// registrations: the map does not keep one entry per user ever seen.
#[tokio::test]
async fn expired_entries_of_users_who_never_return_are_pruned() {
    use crate::testing::mock_clock::MockClock;
    let clock = Arc::new(MockClock::at_reference());
    let registry = MemorySessionRegistry::new()
        .with_ttl(Duration::from_secs(60))
        .with_clock(clock.clone());
    for batch in 0..10 {
        for n in 0..100 {
            registry
                .register(
                    &uid(&format!("u{batch}-{n}")),
                    &SessionKey::of(&SessionId::new(&SystemRng)),
                )
                .await
                .unwrap();
        }
        clock.advance_secs(120);
    }
    let held = lock(&registry.valid).len();
    assert!(held <= 200, "{held} users held after 1000 one-off logins");
}

/// The memory store lists the live sessions of one user, newest first, up to
/// the limit, and no one else's.
#[tokio::test]
async fn the_memory_store_lists_the_sessions_of_one_user() {
    use crate::session::data::{AuthState, SessionData};
    let store = MemorySessionStore::new();
    let ttl = Duration::from_secs(60);
    let data = |user: &str| SessionData {
        auth_state: AuthState::Identifying {
            user_id: uid(user),
            tenant_id: axess_identity::testing::tenant("t"),
        },
        ..SessionData::default()
    };
    let (a1, a2, b1) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    store.save(&a1, &data("alice"), ttl).await.unwrap();
    store.save(&a2, &data("alice"), ttl).await.unwrap();
    store.save(&b1, &data("bob"), ttl).await.unwrap();

    let alice = store
        .find_sessions_for_user(&uid("alice"), 10)
        .await
        .unwrap();
    // Each session is listed under the key it was saved under.
    let mut keys: Vec<_> = alice.iter().map(|(key, _)| *key).collect();
    keys.sort();
    let mut want = vec![a1, a2];
    want.sort();
    assert_eq!(keys, want);
    assert_eq!(
        store
            .find_sessions_for_user(&uid("alice"), 1)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        store
            .find_sessions_for_user(&uid("carol"), 10)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A registry that reads the time from a clock of the test's own.
fn registry_on_a_test_clock() -> MemorySessionRegistry {
    MemorySessionRegistry::new()
        .with_clock(Arc::new(axess_clock::testing::MockClock::at_reference()))
}

/// Ending the other sessions keeps the one named, returns the rest, and
/// leaves another user's sessions alone.
#[tokio::test]
async fn ending_the_other_sessions_keeps_one_and_returns_the_rest() {
    let registry = registry_on_a_test_clock();
    let (alice, bob) = (uid("alice"), uid("bob"));
    let rng = SystemRng;
    let sessions: Vec<SessionKey> = (0..4)
        .map(|_| SessionKey::of(&SessionId::new(&rng)))
        .collect();
    for s in &sessions {
        registry.register(&alice, s).await.unwrap();
    }
    let bobs = SessionKey::of(&SessionId::new(&rng));
    registry.register(&bob, &bobs).await.unwrap();

    let ended = registry
        .invalidate_other_sessions(&alice, &sessions[1])
        .await
        .unwrap();

    // A cut-off's list of the sessions it ended has no promised order.
    let CutOff::KeptOne(ended) = ended else {
        panic!("the session to keep is held");
    };
    assert_eq!(
        sorted(&ended),
        sorted(&[sessions[0], sessions[2], sessions[3]]),
        "every other session"
    );
    assert_eq!(
        registry.active_sessions(&alice).await.unwrap(),
        vec![sessions[1]]
    );
    assert_eq!(registry.active_sessions(&bob).await.unwrap(), vec![bobs]);

    // The one kept is alone now: ending the others again ends nothing.
    assert_eq!(
        registry
            .invalidate_other_sessions(&alice, &sessions[1])
            .await
            .unwrap(),
        CutOff::KeptOne(Vec::new())
    );
}

/// A session to keep that the registry does not hold for the user ends
/// nothing: an id never registered, another user's session, a user with no
/// session at all.
#[tokio::test]
async fn ending_the_other_sessions_around_a_session_not_held_ends_nothing() {
    let registry = registry_on_a_test_clock();
    let (alice, bob) = (uid("alice"), uid("bob"));
    let rng = SystemRng;
    let (a1, a2, bobs, stranger) = (
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
    );
    registry.register(&alice, &a1).await.unwrap();
    registry.register(&alice, &a2).await.unwrap();
    registry.register(&bob, &bobs).await.unwrap();

    for keep in [stranger, bobs] {
        assert_eq!(
            registry
                .invalidate_other_sessions(&alice, &keep)
                .await
                .unwrap(),
            CutOff::NotHeld
        );
        assert_eq!(
            registry.active_sessions(&alice).await.unwrap(),
            vec![a1, a2]
        );
    }
    assert_eq!(
        registry
            .invalidate_other_sessions(&uid("nobody"), &a1)
            .await
            .unwrap(),
        CutOff::NotHeld
    );
}

/// A session to keep whose entry has lapsed is not held: nothing is ended
/// around it.
#[tokio::test]
async fn ending_the_other_sessions_around_a_lapsed_session_ends_nothing() {
    let clock = axess_clock::testing::MockClock::at_reference();
    let registry = MemorySessionRegistry::new()
        .with_ttl(Duration::from_secs(60))
        .with_clock(Arc::new(clock.clone()));
    let alice = uid("alice");
    let rng = SystemRng;
    let (lapsed, other) = (
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
    );
    registry.register(&alice, &lapsed).await.unwrap();
    registry.register(&alice, &other).await.unwrap();
    assert_eq!(
        registry
            .invalidate_other_sessions(&alice, &lapsed)
            .await
            .unwrap(),
        CutOff::KeptOne(vec![other]),
        "the control: while it is live, the session is kept and the other ended"
    );
    registry.register(&alice, &other).await.unwrap();
    clock.advance_secs(61);

    assert_eq!(
        registry
            .invalidate_other_sessions(&alice, &lapsed)
            .await
            .unwrap(),
        CutOff::NotHeld
    );
}

/// Registrations that race the step are each ended by it or land after it:
/// no session is removed without being reported, none is reported and still
/// held, and the one kept is always held. Every session registered before
/// the step began is ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registrations_racing_the_step_are_ended_or_come_after_it() {
    let alice = uid("alice");
    let rng = SystemRng;
    for round in 0..200 {
        let registry = registry_on_a_test_clock();
        let keep = SessionKey::of(&SessionId::new(&rng));
        let before: Vec<SessionKey> = (0..3)
            .map(|_| SessionKey::of(&SessionId::new(&rng)))
            .collect();
        let racing: Vec<SessionKey> = (0..8)
            .map(|_| SessionKey::of(&SessionId::new(&rng)))
            .collect();
        registry.register(&alice, &keep).await.unwrap();
        for s in &before {
            registry.register(&alice, s).await.unwrap();
        }
        let registrar = {
            let (registry, racing) = (registry.clone(), racing.clone());
            tokio::spawn(async move {
                for s in &racing {
                    registry.register(&alice, s).await.unwrap();
                    tokio::task::yield_now().await;
                }
            })
        };
        let cutter = {
            let registry = registry.clone();
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                registry.invalidate_other_sessions(&alice, &keep).await
            })
        };
        registrar.await.unwrap();
        let CutOff::KeptOne(ended) = cutter.await.unwrap().unwrap() else {
            panic!("round {round}: the kept one is held");
        };
        let held = registry.active_sessions(&alice).await.unwrap();

        assert!(held.contains(&keep), "round {round}: the kept session");
        for s in &before {
            assert!(
                ended.contains(s),
                "round {round}: registered before the step"
            );
        }
        for s in before.iter().chain(&racing) {
            assert!(
                ended.contains(s) != held.contains(s),
                "round {round}: a session is ended or held, never both and never neither"
            );
        }
    }
}

/// Two keys that share their first four bytes, and so print alike in a log
/// line, are two sessions: the registry names an entry by the whole key.
#[tokio::test]
async fn two_keys_that_log_alike_are_two_sessions() {
    let registry = registry_on_a_test_clock();
    let user = uid("alike");
    let mut other = [0x5a; 32];
    other[31] = 0x5b;
    let (one, two) = (
        SessionKey::from_bytes([0x5a; 32]),
        SessionKey::from_bytes(other),
    );
    assert!(one.prefix() == two.prefix(), "the two log alike");
    registry.register(&user, &one).await.unwrap();
    registry.register(&user, &two).await.unwrap();
    assert!(registry.is_valid(&user, &one).await.unwrap());
    assert!(registry.is_valid(&user, &two).await.unwrap());
    assert_eq!(
        registry.active_sessions(&user).await.unwrap(),
        vec![one, two]
    );
    registry.invalidate_session(&user, &one).await.unwrap();
    assert!(!registry.is_valid(&user, &one).await.unwrap());
    assert!(
        registry.is_valid(&user, &two).await.unwrap(),
        "ending one ends one"
    );
    assert_eq!(registry.active_sessions(&user).await.unwrap(), vec![two]);
}

// ── Moves ───────────────────────────────────────────────────────────────────

/// The memory registry keeps the whole registry contract.
#[tokio::test]
async fn the_memory_registry_keeps_the_registry_contract() {
    crate::testing::registry_contract::assert_registry_contract(&registry_on_a_test_clock()).await;
}

/// A moved session keeps its place in the order, onto a new key and onto a
/// key registered already. The memory registry orders by registration
/// itself, so the place holds even for sessions registered in one tick.
#[tokio::test]
async fn a_moved_session_keeps_its_place() {
    let registry = registry_on_a_test_clock();
    let key = || SessionKey::of(&SessionId::new(&SystemRng));
    let alice = uid("place-alice");
    let (first, old, last, new) = (key(), key(), key(), key());
    for k in [&first, &old, &last] {
        registry.register(&alice, k).await.unwrap();
    }
    assert_eq!(
        registry.move_session(&alice, &old, &new).await.unwrap(),
        MoveOutcome::Moved
    );
    assert_eq!(
        registry.active_sessions(&alice).await.unwrap(),
        vec![first, new, last]
    );

    let carol = uid("place-carol");
    let (moving, between, taken) = (key(), key(), key());
    for k in [&moving, &between, &taken] {
        registry.register(&carol, k).await.unwrap();
    }
    assert_eq!(
        registry
            .move_session(&carol, &moving, &taken)
            .await
            .unwrap(),
        MoveOutcome::Moved
    );
    assert_eq!(
        registry.active_sessions(&carol).await.unwrap(),
        vec![taken, between]
    );
}

/// A lifetime unlike any default, so a test cannot pass on the default by
/// chance.
const MOVE_TTL: Duration = Duration::from_secs(90);

fn new_key() -> SessionKey {
    SessionKey::of(&SessionId::new(&SystemRng))
}

/// The move records the registry holds for `user`, read from its map, in
/// the order the moves were made.
fn records(
    registry: &MemorySessionRegistry,
    user: &crate::authn::ids::UserId,
) -> Vec<(SessionKey, SessionKey)> {
    lock(&registry.valid)
        .get(user.to_string().as_str())
        .map(|entry| {
            entry
                .moves
                .iter()
                .map(|record| (record.former, record.target))
                .collect()
        })
        .unwrap_or_default()
}

async fn moved(
    registry: &MemorySessionRegistry,
    user: &crate::authn::ids::UserId,
    old: &SessionKey,
    new: &SessionKey,
) -> MoveOutcome {
    let Ok(outcome) = registry.move_session(user, old, new).await;
    outcome
}

async fn current(
    registry: &MemorySessionRegistry,
    user: &crate::authn::ids::UserId,
    session: &SessionKey,
) -> Option<SessionKey> {
    let Ok(current) = registry.current_key(user, session).await;
    current
}

/// A session whose entry has lapsed does not move, and nothing is
/// registered under the new key.
#[tokio::test]
async fn a_lapsed_session_does_not_move() {
    let clock = mock_clock();
    let registry = registry_on(&clock, MOVE_TTL);
    let user = uid("lapsed");
    let (old, new) = (new_key(), new_key());
    registry.register(&user, &old).await.unwrap();
    clock.advance_secs(91);
    assert_eq!(
        moved(&registry, &user, &old, &new).await,
        MoveOutcome::OldGone
    );
    assert!(!registry.is_valid(&user, &new).await.unwrap());
    assert_eq!(current(&registry, &user, &old).await, None);
}

/// A move to the same key writes no record.
#[tokio::test]
async fn a_move_to_the_same_key_writes_no_record() {
    let registry = registry_on_a_test_clock();
    let user = uid("same");
    let session = new_key();
    registry.register(&user, &session).await.unwrap();
    assert_eq!(
        moved(&registry, &user, &session, &session).await,
        MoveOutcome::Moved
    );
    assert_eq!(records(&registry, &user), Vec::new());
}

/// A record lives as long as the entry it leads to, however long that is,
/// and goes once that entry has lapsed: the next move of the user drops it.
#[tokio::test]
async fn a_record_lives_with_its_target() {
    let clock = mock_clock();
    let registry = registry_on(&clock, MOVE_TTL);
    let user = uid("record");
    let (a, b) = (new_key(), new_key());
    registry.register(&user, &a).await.unwrap();
    assert_eq!(moved(&registry, &user, &a, &b).await, MoveOutcome::Moved);
    // Three lifetimes, the session used at each half of one.
    for _ in 0..6 {
        clock.advance_secs(45);
        assert!(registry.is_valid(&user, &b).await.unwrap());
    }
    assert_eq!(
        current(&registry, &user, &a).await,
        Some(b),
        "the record lives while the session it leads to is used"
    );

    clock.advance_secs(91);
    assert_eq!(
        current(&registry, &user, &a).await,
        None,
        "a record whose target lapsed is not followed"
    );
    let (c, d) = (new_key(), new_key());
    registry.register(&user, &c).await.unwrap();
    assert_eq!(moved(&registry, &user, &c, &d).await, MoveOutcome::Moved);
    assert_eq!(
        records(&registry, &user),
        vec![(c, d)],
        "the next move dropped the record whose target lapsed"
    );
}

/// A cut-off does not follow a record to a session that lapsed: the key to
/// keep names no live session, so nothing is ended.
#[tokio::test]
async fn a_cut_off_does_not_follow_a_record_to_a_lapsed_session() {
    let clock = mock_clock();
    let registry = registry_on(&clock, MOVE_TTL);
    let user = uid("lapsed-target");
    let (a, b, other) = (new_key(), new_key(), new_key());
    registry.register(&user, &a).await.unwrap();
    assert_eq!(moved(&registry, &user, &a, &b).await, MoveOutcome::Moved);
    clock.advance_secs(45);
    registry.register(&user, &other).await.unwrap();
    clock.advance_secs(46);
    let Ok(cut) = registry.invalidate_other_sessions(&user, &a).await;
    assert_eq!(cut, CutOff::NotHeld);
    assert!(
        registry.is_valid(&user, &other).await.unwrap(),
        "nothing ended"
    );
}

/// A key registered again is a session of its own, not a former key of the
/// session it once moved to.
#[tokio::test]
async fn a_registered_key_is_not_a_former_key() {
    let clock = mock_clock();
    let registry = registry_on(&clock, MOVE_TTL);
    let user = uid("reregistered");
    let (a, b) = (new_key(), new_key());
    registry.register(&user, &a).await.unwrap();
    assert_eq!(moved(&registry, &user, &a, &b).await, MoveOutcome::Moved);
    registry.register(&user, &a).await.unwrap();
    clock.advance_secs(45);
    assert!(registry.is_valid(&user, &b).await.unwrap());
    clock.advance_secs(46);
    assert!(!registry.is_valid(&user, &a).await.unwrap(), "a lapsed");
    assert_eq!(
        current(&registry, &user, &a).await,
        None,
        "the two are different sessions now"
    );
}

/// A session that rotates on every request, twice past the bound, stays
/// signed in: every move answers `Moved`, the user holds exactly the bound
/// of records, and the session's first key and its latest former keys
/// still find it while its second key no longer does.
#[tokio::test]
async fn a_session_that_rotates_past_the_bound_stays_signed_in() {
    let registry = registry_on_a_test_clock();
    let user = uid("rotating");
    let keys: Vec<SessionKey> = (0..2 * MAX_MOVE_RECORDS_PER_USER + 6)
        .map(|_| new_key())
        .collect();
    registry.register(&user, &keys[0]).await.unwrap();
    for (n, pair) in keys.windows(2).enumerate() {
        assert_eq!(
            moved(&registry, &user, &pair[0], &pair[1]).await,
            MoveOutcome::Moved,
            "move {n}"
        );
    }
    let last = keys[keys.len() - 1];
    assert!(registry.is_valid(&user, &last).await.unwrap());
    assert_eq!(records(&registry, &user).len(), MAX_MOVE_RECORDS_PER_USER);
    assert_eq!(current(&registry, &user, &keys[0]).await, Some(last));
    assert_eq!(
        current(&registry, &user, &keys[keys.len() - 2]).await,
        Some(last)
    );
    assert_eq!(current(&registry, &user, &keys[1]).await, None);
}

/// A move at the bound gives up another session's record before it would
/// refuse: the session that never moved moves, and the other session's
/// first key still finds it.
#[tokio::test]
async fn another_sessions_record_is_given_up_before_a_move_is_refused() {
    let registry = registry_on_a_test_clock();
    let user = uid("two-sessions");
    let a: Vec<SessionKey> = (0..=MAX_MOVE_RECORDS_PER_USER).map(|_| new_key()).collect();
    registry.register(&user, &a[0]).await.unwrap();
    let (b, b_new) = (new_key(), new_key());
    registry.register(&user, &b).await.unwrap();
    for pair in a.windows(2) {
        assert_eq!(
            moved(&registry, &user, &pair[0], &pair[1]).await,
            MoveOutcome::Moved
        );
    }
    assert_eq!(
        moved(&registry, &user, &b, &b_new).await,
        MoveOutcome::Moved
    );
    let a_now = a[MAX_MOVE_RECORDS_PER_USER];
    assert_eq!(current(&registry, &user, &a[0]).await, Some(a_now));
    assert_eq!(current(&registry, &user, &a[1]).await, None);
    assert_eq!(current(&registry, &user, &b).await, Some(b_new));
}

/// The record given up at the bound is the earliest of the user that is
/// not a first former key, whichever session's it is.
#[tokio::test]
async fn the_earliest_record_goes_whichever_sessions_it_is() {
    let registry = registry_on_a_test_clock();
    let user = uid("earliest");
    let a: Vec<SessionKey> = (0..3).map(|_| new_key()).collect();
    let b: Vec<SessionKey> = (0..MAX_MOVE_RECORDS_PER_USER - 1)
        .map(|_| new_key())
        .collect();
    registry.register(&user, &a[0]).await.unwrap();
    registry.register(&user, &b[0]).await.unwrap();
    for pair in a.windows(2) {
        assert_eq!(
            moved(&registry, &user, &pair[0], &pair[1]).await,
            MoveOutcome::Moved
        );
    }
    for pair in b.windows(2) {
        assert_eq!(
            moved(&registry, &user, &pair[0], &pair[1]).await,
            MoveOutcome::Moved
        );
    }
    assert_eq!(records(&registry, &user).len(), MAX_MOVE_RECORDS_PER_USER);
    let b_last = new_key();
    let b_now = b[MAX_MOVE_RECORDS_PER_USER - 2];
    assert_eq!(
        moved(&registry, &user, &b_now, &b_last).await,
        MoveOutcome::Moved
    );
    assert_eq!(
        current(&registry, &user, &a[1]).await,
        None,
        "the other session's second key, the earliest that is not a first, went"
    );
    assert_eq!(current(&registry, &user, &a[0]).await, Some(a[2]));
    assert_eq!(current(&registry, &user, &b[1]).await, Some(b_last));
}

/// A move is refused only when every record of the user is the first
/// former key of a live session, and then nothing changes.
#[tokio::test]
async fn a_move_is_refused_only_when_every_record_is_a_first_former_key() {
    let registry = registry_on_a_test_clock();
    let user = uid("full");
    let mut firsts = Vec::new();
    for _ in 0..MAX_MOVE_RECORDS_PER_USER {
        let (old, new) = (new_key(), new_key());
        registry.register(&user, &old).await.unwrap();
        assert_eq!(
            moved(&registry, &user, &old, &new).await,
            MoveOutcome::Moved
        );
        firsts.push((old, new));
    }
    let (old, new) = (new_key(), new_key());
    registry.register(&user, &old).await.unwrap();
    assert_eq!(moved(&registry, &user, &old, &new).await, MoveOutcome::Full);
    assert!(registry.is_valid(&user, &old).await.unwrap());
    assert!(!registry.is_valid(&user, &new).await.unwrap());
    for (first, now) in firsts {
        assert_eq!(current(&registry, &user, &first).await, Some(now));
    }
}

/// How many times each race runs, with fresh users.
const RACE_RUNS: usize = 200;

/// Two moves of one key to two different keys: exactly one moves the
/// session, and the session is under that one's key alone. Built to catch a
/// move made of a registration and a removal under two takings of the lock,
/// where both can register before either removes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn of_two_moves_of_one_key_exactly_one_moves_it() {
    let registry = registry_on_a_test_clock();
    for run in 0..RACE_RUNS {
        let user = crate::authn::ids::UserId::new(&SystemRng);
        let (old, one, two) = (new_key(), new_key(), new_key());
        registry.register(&user, &old).await.unwrap();
        let racer = |new: SessionKey| {
            let registry = registry.clone();
            tokio::spawn(async move { moved(&registry, &user, &old, &new).await })
        };
        let (first, second) = (racer(one), racer(two));
        let answers = [first.await.unwrap(), second.await.unwrap()];
        let moves = answers.iter().filter(|a| **a == MoveOutcome::Moved).count();
        assert_eq!(moves, 1, "run {run}: {answers:?}");
        let held = registry.active_sessions(&user).await.unwrap();
        assert_eq!(held.len(), 1, "run {run}: one session, under one key");
    }
}

/// A move racing the removal of all of a user's sessions leaves nothing of
/// the user valid. Built to catch a move made of two takings of the lock,
/// where the new key registers after the removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_move_racing_the_end_of_every_session_leaves_none() {
    let registry = registry_on_a_test_clock();
    for run in 0..RACE_RUNS {
        let user = crate::authn::ids::UserId::new(&SystemRng);
        let (old, new) = (new_key(), new_key());
        registry.register(&user, &old).await.unwrap();
        let mover = {
            let registry = registry.clone();
            tokio::spawn(async move { moved(&registry, &user, &old, &new).await })
        };
        let ender = {
            let registry = registry.clone();
            tokio::spawn(async move { registry.invalidate_user(&user).await })
        };
        let outcome = mover.await.unwrap();
        ender.await.unwrap().unwrap();
        assert!(
            matches!(outcome, MoveOutcome::Moved | MoveOutcome::OldGone),
            "run {run}: {outcome:?}"
        );
        assert!(
            !registry.is_valid(&user, &new).await.unwrap(),
            "run {run}: the new key outlived the end of every session"
        );
        assert!(!registry.is_valid(&user, &old).await.unwrap(), "run {run}");
    }
}

fn sorted(keys: &[SessionKey]) -> Vec<SessionKey> {
    let mut keys = keys.to_vec();
    keys.sort_by_key(ToString::to_string);
    keys
}

/// A move racing a cut-off that keeps the key moved from, with two other
/// sessions of the user: every run ends in one of two states, the cut-off
/// first (it keeps the session, the move then moves it) or the move first
/// (the cut-off finds the session to keep moved and ends all three). Built
/// to catch a move made of a registration and a removal under two takings
/// of the lock: a cut-off between them answers that it kept the session
/// and ends its new key, a third state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_move_racing_a_cut_off_ends_in_one_of_two_states() {
    let registry = registry_on_a_test_clock();
    for run in 0..RACE_RUNS {
        let user = crate::authn::ids::UserId::new(&SystemRng);
        let (old, x, y, new) = (new_key(), new_key(), new_key(), new_key());
        for session in [&old, &x, &y] {
            registry.register(&user, session).await.unwrap();
        }
        let mover = {
            let registry = registry.clone();
            tokio::spawn(async move { moved(&registry, &user, &old, &new).await })
        };
        let cutter = {
            let registry = registry.clone();
            tokio::spawn(async move { registry.invalidate_other_sessions(&user, &old).await })
        };
        let outcome = mover.await.unwrap();
        let Ok(cut) = cutter.await.unwrap();
        assert_eq!(outcome, MoveOutcome::Moved, "run {run}");
        let new_valid = registry.is_valid(&user, &new).await.unwrap();
        match cut {
            CutOff::KeptOne(ended) if sorted(&ended) == sorted(&[x, y]) => {
                assert!(new_valid, "run {run}: the kept session moved");
            }
            CutOff::KeptNone(ended) if sorted(&ended) == sorted(&[new, x, y]) => {
                assert!(!new_valid, "run {run}: the moved session was ended");
            }
            other => panic!("run {run}: a third state: {other:?}"),
        }
        for session in [old, x, y] {
            assert!(
                !registry.is_valid(&user, &session).await.unwrap(),
                "run {run}"
            );
        }
    }
}

/// A move racing an ending by the key moved from leaves nothing of the
/// session valid, whichever ran first. Built to catch a move made of two
/// takings of the lock, where the ending lands between them and the new key
/// survives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_move_racing_an_ending_by_the_old_key_leaves_none() {
    let registry = registry_on_a_test_clock();
    for run in 0..RACE_RUNS {
        let user = crate::authn::ids::UserId::new(&SystemRng);
        let (old, new) = (new_key(), new_key());
        registry.register(&user, &old).await.unwrap();
        let mover = {
            let registry = registry.clone();
            tokio::spawn(async move { moved(&registry, &user, &old, &new).await })
        };
        let ender = {
            let registry = registry.clone();
            tokio::spawn(async move { registry.invalidate_session(&user, &old).await })
        };
        let outcome = mover.await.unwrap();
        ender.await.unwrap().unwrap();
        assert!(
            matches!(outcome, MoveOutcome::Moved | MoveOutcome::OldGone),
            "run {run}: {outcome:?}"
        );
        assert!(
            !registry.is_valid(&user, &new).await.unwrap(),
            "run {run}: the new key outlived the ending"
        );
    }
}
