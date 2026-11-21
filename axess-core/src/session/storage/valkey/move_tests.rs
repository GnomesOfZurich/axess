//! The move of a session to a new key on a live Valkey: the registry
//! contract, the records' lifetime and their bound, what a move publishes,
//! and the races the one step closes. Every test writes under a prefix of
//! its own and removes what it wrote, also when it fails.
//!
//! The races and the cluster's own rows run on the cluster too, from
//! `cluster_tests.rs`, through the functions here that take the registries
//! they race.

use super::SUBSCRIBER_TESTS;
use super::fallback_tests::with_scripting_refused;
use super::internal::{ValkeyStoreError, revocation_session_channel, user_keys};
use super::registry::ValkeySessionRegistry;
use super::registry_tests::connect;
use super::subscriber::connection_name;
use super::watch_tests::{eventually, subscriber_connections};
use crate::authn::ids::UserId;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{CutOff, MAX_MOVE_RECORDS_PER_USER, MoveOutcome, SessionRegistry};
use crate::testing::valkey_cluster::cluster_client;
use crate::testing::valkey_sweep::{self, KeySweep, Swept};
use axess_clock::testing::MockClock;
use axess_rng::SystemRng;
use axess_testing::mock_tracing::TracingCapture;
use fred::prelude::*;
use std::sync::Arc;
use std::time::Duration;

/// A lifetime unlike any default, so a test cannot pass on the default by
/// chance.
const TTL: Duration = Duration::from_secs(90);

/// How many times each race runs, with fresh users.
pub(super) const RACE_RUNS: usize = 200;

/// How long each of two racers waits before it calls, in run `run`: the
/// one that waits alternates, and its wait steps from 0 to 2.85 ms, so that
/// over the runs the second call lands at every phase of the first (each
/// takes a few round trips: the time, then the script).
fn stagger(run: usize) -> (Duration, Duration) {
    let wait = Duration::from_micros((run / 2 % 20) as u64 * 150);
    if run.is_multiple_of(2) {
        (Duration::ZERO, wait)
    } else {
        (wait, Duration::ZERO)
    }
}

/// A prefix of one test's own, on the single node or on the cluster, and
/// the removal of every key under it when the test ends, passed or failed:
/// the prefix is held with a [`KeySweep`], which removes the keys as it is
/// dropped.
pub(super) struct Sweep {
    prefix: Swept<String>,
    cluster: bool,
}

impl Sweep {
    /// A prefix no other run has used, on the single node.
    pub(super) fn node(tag: &str) -> Self {
        Self::under(valkey_sweep::on_node(tag), false, |p| p.to_owned())
    }

    /// A prefix no other run has used, on the cluster, with no hash tag.
    pub(super) fn cluster(tag: &str) -> Self {
        Self::under(valkey_sweep::on_cluster(tag), true, |p| p.to_owned())
    }

    /// A prefix no other run has used, on the cluster, closing a hash tag
    /// of its own, so every key under it lies in the tag's slot.
    pub(super) fn cluster_tagged(tag: &str) -> Self {
        Self::under(valkey_sweep::on_cluster(tag).hash_tagged(), true, |p| {
            p.to_owned()
        })
    }

    /// A prefix no other run has used, on the single node, that opens a
    /// brace it does not close: the form that splits a user's keys over two
    /// slots.
    pub(super) fn node_unclosed(tag: &str) -> Self {
        Self::under(valkey_sweep::on_node(tag), false, |p| format!("{p}{{b"))
    }

    fn under(keys: KeySweep, cluster: bool, shape: impl FnOnce(&str) -> String) -> Self {
        let prefix = shape(keys.prefix());
        Self {
            prefix: keys.hold(prefix),
            cluster,
        }
    }

    /// The prefix the test writes under.
    pub(super) fn prefix(&self) -> &str {
        self.prefix.as_str()
    }

    /// A registry built by its constructor under the prefix, on a
    /// connection of its own.
    pub(super) async fn registry(&self) -> ValkeySessionRegistry {
        let client = if self.cluster {
            cluster_client().await
        } else {
            connect().await
        };
        ValkeySessionRegistry::with_options(client, self.prefix.as_str(), TTL)
            .await
            .expect("a registry")
    }
}

fn new_key() -> SessionKey {
    SessionKey::of(&SessionId::new(&SystemRng))
}

/// The move records of `user`, read from the server: former key to target.
async fn records(client: &Client, prefix: &str, user: &UserId) -> Vec<(String, String)> {
    let keys = user_keys(prefix, user).expect("one slot");
    let mut held: Vec<(String, String)> = client
        .hgetall::<std::collections::HashMap<String, String>, _>(&keys.forward)
        .await
        .expect("HGETALL")
        .into_iter()
        .collect();
    held.sort();
    held
}

/// The former keys of `user` in their order, read from the server.
async fn record_order(client: &Client, prefix: &str, user: &UserId) -> Vec<String> {
    let keys = user_keys(prefix, user).expect("one slot");
    client
        .zrange(&keys.forward_order, 0_i64, -1_i64, None, false, None, false)
        .await
        .expect("ZRANGE")
}

async fn moved(
    registry: &ValkeySessionRegistry,
    user: &UserId,
    old: &SessionKey,
    new: &SessionKey,
) -> MoveOutcome {
    registry
        .move_session(user, old, new)
        .await
        .expect("move_session")
}

async fn current(
    registry: &ValkeySessionRegistry,
    user: &UserId,
    session: &SessionKey,
) -> Option<SessionKey> {
    registry
        .current_key(user, session)
        .await
        .expect("current_key")
}

/// The registry keeps the whole registry contract on a single node.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_the_registry_keeps_the_registry_contract() {
    let sweep = Sweep::node("mvkit");
    let registry = sweep.registry().await;
    crate::testing::registry_contract::assert_registry_contract(&registry).await;
}

/// A moved session keeps its place among sessions registered at other
/// times, onto a new key and onto a key registered already: the clock moves
/// a second between registrations, so the order read is the registration
/// time's and not a tie broken by key.
pub(super) async fn a_moved_session_keeps_its_place(
    registry: &ValkeySessionRegistry,
    clock: &MockClock,
) {
    let alice = UserId::new(&SystemRng);
    let (first, old, last, new) = (new_key(), new_key(), new_key(), new_key());
    for key in [&first, &old, &last] {
        registry.register(&alice, key).await.unwrap();
        clock.advance_secs(1);
    }
    assert_eq!(
        moved(registry, &alice, &old, &new).await,
        MoveOutcome::Moved
    );
    assert_eq!(
        registry.active_sessions(&alice).await.unwrap(),
        vec![first, new, last],
        "a moved session keeps the place its registration gave it"
    );

    let carol = UserId::new(&SystemRng);
    let (moving, between, taken) = (new_key(), new_key(), new_key());
    for key in [&moving, &between, &taken] {
        registry.register(&carol, key).await.unwrap();
        clock.advance_secs(1);
    }
    assert_eq!(
        moved(registry, &carol, &moving, &taken).await,
        MoveOutcome::Moved
    );
    assert_eq!(
        registry.active_sessions(&carol).await.unwrap(),
        vec![taken, between],
        "the session is held once, in the place of the key it left"
    );
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_moved_session_keeps_its_place() {
    let sweep = Sweep::node("mvplace");
    let clock = MockClock::at_reference();
    let registry = sweep.registry().await.with_clock(Arc::new(clock.clone()));
    a_moved_session_keeps_its_place(&registry, &clock).await;
}

/// A session whose member has lapsed does not move, and nothing is written
/// under the new key.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_lapsed_session_does_not_move() {
    let sweep = Sweep::node("mvlapsed");
    let clock = MockClock::at_reference();
    let registry = sweep.registry().await.with_clock(Arc::new(clock.clone()));
    let user = UserId::new(&SystemRng);
    let (old, new) = (new_key(), new_key());
    registry.register(&user, &old).await.unwrap();
    clock.advance_secs(91);
    assert_eq!(
        moved(&registry, &user, &old, &new).await,
        MoveOutcome::OldGone
    );
    assert!(!registry.is_valid(&user, &new).await.unwrap());
    assert_eq!(records(&registry.client, sweep.prefix(), &user).await, []);
}

/// A move to the same key writes no record.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_move_to_the_same_key_writes_no_record() {
    let sweep = Sweep::node("mvsame");
    let registry = sweep.registry().await;
    let user = UserId::new(&SystemRng);
    let session = new_key();
    registry.register(&user, &session).await.unwrap();
    assert_eq!(
        moved(&registry, &user, &session, &session).await,
        MoveOutcome::Moved
    );
    assert_eq!(records(&registry.client, sweep.prefix(), &user).await, []);
}

/// A record lives as long as the entry it leads to: the slide of a used
/// session renews the records' keys with the registry's, and once the
/// entry has lapsed the record is not followed and the user's next move
/// removes it.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_record_lives_with_its_target() {
    let sweep = Sweep::node("mvlives");
    let clock = MockClock::at_reference();
    let registry = sweep.registry().await.with_clock(Arc::new(clock.clone()));
    let admin = connect().await;
    let user = UserId::new(&SystemRng);
    let keys = user_keys(sweep.prefix(), &user).expect("one slot");
    let (a, b) = (new_key(), new_key());
    registry.register(&user, &a).await.unwrap();
    assert_eq!(moved(&registry, &user, &a, &b).await, MoveOutcome::Moved);
    // The clock of the scores is the test's, the keys' expiry the server's:
    // an expiry set by hand stands for the time a real session would have
    // been in use, so only a slide can bring the records' keys back in line.
    for records in [&keys.forward, &keys.forward_order] {
        let _: i64 = admin.expire(records, 100_000, None).await.expect("EXPIRE");
    }
    for _ in 0..6 {
        clock.advance_secs(45);
        assert!(registry.is_valid(&user, &b).await.unwrap());
    }
    assert_eq!(current(&registry, &user, &a).await, Some(b));
    let pttl = |key: String| {
        let admin = admin.clone();
        async move { admin.pttl::<i64, _>(key).await.expect("PTTL") }
    };
    let held = pttl(keys.registry.clone()).await;
    for records in [&keys.forward, &keys.forward_order] {
        let left = pttl(records.clone()).await;
        assert!(
            held > 0 && (held - left).abs() < 1_000,
            "{records} expires with the registry set: {left} ms against {held} ms"
        );
    }

    clock.advance_secs(91);
    assert_eq!(current(&registry, &user, &a).await, None);
    let (c, d) = (new_key(), new_key());
    registry.register(&user, &c).await.unwrap();
    assert_eq!(moved(&registry, &user, &c, &d).await, MoveOutcome::Moved);
    assert_eq!(
        records(&admin, sweep.prefix(), &user).await,
        [(c.to_string(), d.to_string())],
        "the next move removed the record whose target lapsed"
    );
    assert_eq!(
        record_order(&admin, sweep.prefix(), &user).await,
        [c.to_string()]
    );
}

/// A cut-off does not follow a record to a session that lapsed: the key to
/// keep names no live session, so nothing is ended.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_cut_off_does_not_follow_a_record_to_a_lapsed_session() {
    let sweep = Sweep::node("mvcutlapsed");
    let clock = MockClock::at_reference();
    let registry = sweep.registry().await.with_clock(Arc::new(clock.clone()));
    let user = UserId::new(&SystemRng);
    let (a, b, other) = (new_key(), new_key(), new_key());
    registry.register(&user, &a).await.unwrap();
    assert_eq!(moved(&registry, &user, &a, &b).await, MoveOutcome::Moved);
    clock.advance_secs(45);
    registry.register(&user, &other).await.unwrap();
    clock.advance_secs(46);
    assert_eq!(
        registry
            .invalidate_other_sessions(&user, &a)
            .await
            .expect("the cut-off"),
        CutOff::NotHeld
    );
    assert!(
        registry.is_valid(&user, &other).await.unwrap(),
        "nothing ended"
    );
}

/// A key registered again is a session of its own, not a former key of the
/// session it once moved to.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_registered_key_is_not_a_former_key() {
    let sweep = Sweep::node("mvreg");
    let clock = MockClock::at_reference();
    let registry = sweep.registry().await.with_clock(Arc::new(clock.clone()));
    let user = UserId::new(&SystemRng);
    let (a, b) = (new_key(), new_key());
    registry.register(&user, &a).await.unwrap();
    assert_eq!(moved(&registry, &user, &a, &b).await, MoveOutcome::Moved);
    registry.register(&user, &a).await.unwrap();
    clock.advance_secs(45);
    assert!(registry.is_valid(&user, &b).await.unwrap());
    clock.advance_secs(46);
    assert!(!registry.is_valid(&user, &a).await.unwrap(), "a lapsed");
    assert_eq!(current(&registry, &user, &a).await, None);
}

/// A session that rotates twice past the bound stays signed in: every move
/// answers `Moved`, the user holds exactly the bound of records, the
/// session's first key and its latest former key still find it, and its
/// second key does not.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_session_that_rotates_past_the_bound_stays_signed_in() {
    let sweep = Sweep::node("mvbound");
    let registry = sweep.registry().await;
    let user = UserId::new(&SystemRng);
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
    let held = records(&registry.client, sweep.prefix(), &user).await;
    assert_eq!(held.len(), MAX_MOVE_RECORDS_PER_USER);
    assert_eq!(
        record_order(&registry.client, sweep.prefix(), &user)
            .await
            .len(),
        MAX_MOVE_RECORDS_PER_USER
    );
    assert_eq!(current(&registry, &user, &keys[0]).await, Some(last));
    assert_eq!(
        current(&registry, &user, &keys[keys.len() - 2]).await,
        Some(last)
    );
    assert_eq!(current(&registry, &user, &keys[1]).await, None);
}

/// A move at the bound gives up another session's record before it would
/// refuse.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_another_sessions_record_is_given_up_before_a_move_is_refused() {
    let sweep = Sweep::node("mvother");
    let registry = sweep.registry().await;
    let user = UserId::new(&SystemRng);
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
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_the_earliest_record_goes_whichever_sessions_it_is() {
    let sweep = Sweep::node("mvearliest");
    let registry = sweep.registry().await;
    let user = UserId::new(&SystemRng);
    let a: Vec<SessionKey> = (0..3).map(|_| new_key()).collect();
    let b: Vec<SessionKey> = (0..MAX_MOVE_RECORDS_PER_USER - 1)
        .map(|_| new_key())
        .collect();
    registry.register(&user, &a[0]).await.unwrap();
    registry.register(&user, &b[0]).await.unwrap();
    for pair in a.windows(2).chain(b.windows(2)) {
        assert_eq!(
            moved(&registry, &user, &pair[0], &pair[1]).await,
            MoveOutcome::Moved
        );
    }
    assert_eq!(
        records(&registry.client, sweep.prefix(), &user).await.len(),
        MAX_MOVE_RECORDS_PER_USER
    );
    let b_last = new_key();
    let b_now = b[MAX_MOVE_RECORDS_PER_USER - 2];
    assert_eq!(
        moved(&registry, &user, &b_now, &b_last).await,
        MoveOutcome::Moved
    );
    assert_eq!(current(&registry, &user, &a[1]).await, None);
    assert_eq!(current(&registry, &user, &a[0]).await, Some(a[2]));
    assert_eq!(current(&registry, &user, &b[1]).await, Some(b_last));
}

/// A move is refused only when every record of the user is the first
/// former key of a live session, and then nothing changes.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_move_is_refused_only_when_every_record_is_a_first_former_key() {
    let sweep = Sweep::node("mvfull");
    let registry = sweep.registry().await;
    let user = UserId::new(&SystemRng);
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

/// Two moves of one key to two different keys, from two connections:
/// exactly one moves the session, and it is under that one's key alone.
/// Built to catch a move split into a registration script and a removal
/// script, where both can register before either removes.
pub(super) async fn of_two_moves_of_one_key_exactly_one_moves_it(
    one: &ValkeySessionRegistry,
    two: &ValkeySessionRegistry,
) {
    for run in 0..RACE_RUNS {
        let user = UserId::new(&SystemRng);
        let (old, to_one, to_two) = (new_key(), new_key(), new_key());
        one.register(&user, &old).await.unwrap();
        let (wait_one, wait_two) = stagger(run);
        let (first, second) = tokio::join!(
            async {
                tokio::time::sleep(wait_one).await;
                one.move_session(&user, &old, &to_one).await
            },
            async {
                tokio::time::sleep(wait_two).await;
                two.move_session(&user, &old, &to_two).await
            }
        );
        let answers = [first.unwrap(), second.unwrap()];
        let moves = answers.iter().filter(|a| **a == MoveOutcome::Moved).count();
        assert_eq!(moves, 1, "run {run}: {answers:?}");
        assert_eq!(
            one.active_sessions(&user).await.unwrap().len(),
            1,
            "run {run}: one session, under one key"
        );
    }
}

/// A move racing the removal of all of a user's sessions, from two
/// connections, leaves nothing of the user valid. Built to catch a move
/// split in two scripts, where the new key registers after the removal.
pub(super) async fn a_move_racing_the_end_of_every_session_leaves_none(
    mover: &ValkeySessionRegistry,
    ender: &ValkeySessionRegistry,
) {
    for run in 0..RACE_RUNS {
        let user = UserId::new(&SystemRng);
        let (old, new) = (new_key(), new_key());
        mover.register(&user, &old).await.unwrap();
        let (wait_move, wait_end) = stagger(run);
        let (move_done, end_done) = tokio::join!(
            async {
                tokio::time::sleep(wait_move).await;
                mover.move_session(&user, &old, &new).await
            },
            async {
                tokio::time::sleep(wait_end).await;
                ender.invalidate_user(&user).await
            }
        );
        let outcome = move_done.unwrap();
        end_done.unwrap();
        assert!(
            matches!(outcome, MoveOutcome::Moved | MoveOutcome::OldGone),
            "run {run}: {outcome:?}"
        );
        assert!(
            !mover.is_valid(&user, &new).await.unwrap(),
            "run {run}: the new key outlived the end of every session"
        );
        assert!(!mover.is_valid(&user, &old).await.unwrap(), "run {run}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_of_two_moves_of_one_key_exactly_one_moves_it() {
    let sweep = Sweep::node("mvrace2");
    let (one, two) = (sweep.registry().await, sweep.registry().await);
    of_two_moves_of_one_key_exactly_one_moves_it(&one, &two).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_move_racing_the_end_of_every_session_leaves_none() {
    let sweep = Sweep::node("mvraceuser");
    let (mover, ender) = (sweep.registry().await, sweep.registry().await);
    a_move_racing_the_end_of_every_session_leaves_none(&mover, &ender).await;
}

/// `keys` in a fixed order, so two lists compare as sets.
pub(super) fn sorted(keys: &[SessionKey]) -> Vec<SessionKey> {
    let mut keys = keys.to_vec();
    keys.sort_by_key(ToString::to_string);
    keys
}

/// A move racing a cut-off that keeps the key moved from, with two other
/// sessions of the user, from two connections. Every run ends in one of two
/// states: the cut-off kept the session and the move then moved it; or the
/// move ran first, and the cut-off, finding the session to keep moved, ended
/// all three. Built to catch a move split into a registration script and a
/// removal script: a cut-off between them answers that it kept the session
/// and ends its new key, so nothing is valid.
pub(super) async fn a_move_racing_a_cut_off_ends_in_one_of_two_states(
    mover: &ValkeySessionRegistry,
    cutter: &ValkeySessionRegistry,
) {
    for run in 0..RACE_RUNS {
        let user = UserId::new(&SystemRng);
        let (old, x, y, new) = (new_key(), new_key(), new_key(), new_key());
        for session in [&old, &x, &y] {
            mover.register(&user, session).await.unwrap();
        }
        let (wait_move, wait_cut) = stagger(run);
        let (move_done, cut_done) = tokio::join!(
            async {
                tokio::time::sleep(wait_move).await;
                mover.move_session(&user, &old, &new).await
            },
            async {
                tokio::time::sleep(wait_cut).await;
                cutter.invalidate_other_sessions(&user, &old).await
            }
        );
        let outcome = move_done.unwrap();
        assert_eq!(outcome, MoveOutcome::Moved, "run {run}");
        let valid =
            |session: SessionKey| async move { mover.is_valid(&user, &session).await.unwrap() };
        match cut_done.unwrap() {
            CutOff::KeptOne(ended) if sorted(&ended) == sorted(&[x, y]) => {
                assert!(valid(new).await, "run {run}: the kept session moved");
            }
            CutOff::KeptNone(ended) if sorted(&ended) == sorted(&[new, x, y]) => {
                assert!(!valid(new).await, "run {run}: the moved session was ended");
            }
            other => panic!("run {run}: a third state: {other:?}"),
        }
        for session in [old, x, y] {
            assert!(!valid(session).await, "run {run}");
        }
    }
}

/// A move racing an ending by the key moved from, from two connections:
/// nothing of the session is valid afterwards, whichever ran first (the
/// ending first: the move finds the key gone; the move first: the ending
/// follows its record). Built to catch a move split in two scripts, where
/// the ending lands between them and the new key survives.
pub(super) async fn a_move_racing_an_ending_by_the_old_key_leaves_none(
    mover: &ValkeySessionRegistry,
    ender: &ValkeySessionRegistry,
) {
    for run in 0..RACE_RUNS {
        let user = UserId::new(&SystemRng);
        let (old, new) = (new_key(), new_key());
        mover.register(&user, &old).await.unwrap();
        let (wait_move, wait_end) = stagger(run);
        let (move_done, end_done) = tokio::join!(
            async {
                tokio::time::sleep(wait_move).await;
                mover.move_session(&user, &old, &new).await
            },
            async {
                tokio::time::sleep(wait_end).await;
                ender.invalidate_session(&user, &old).await
            }
        );
        let outcome = move_done.unwrap();
        end_done.unwrap();
        assert!(
            matches!(outcome, MoveOutcome::Moved | MoveOutcome::OldGone),
            "run {run}: {outcome:?}"
        );
        assert!(
            !mover.is_valid(&user, &new).await.unwrap(),
            "run {run}: the new key outlived the ending"
        );
        assert!(!mover.is_valid(&user, &old).await.unwrap(), "run {run}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_move_racing_a_cut_off_ends_in_one_of_two_states() {
    let sweep = Sweep::node("mvracecut");
    let (mover, cutter) = (sweep.registry().await, sweep.registry().await);
    a_move_racing_a_cut_off_ends_in_one_of_two_states(&mover, &cutter).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_move_racing_an_ending_by_the_old_key_leaves_none() {
    let sweep = Sweep::node("mvraceend");
    let (mover, ender) = (sweep.registry().await, sweep.registry().await);
    a_move_racing_an_ending_by_the_old_key_leaves_none(&mover, &ender).await;
}

/// A move publishes nothing: a pattern subscriber on every channel the
/// registry publishes on receives, as its first message, one published by
/// hand after the move, and a watcher of the key moved from is still
/// waiting once the watcher told by that message has ended.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_move_publishes_nothing() {
    let serial = SUBSCRIBER_TESTS.lock().await;
    let sweep = Sweep::node("mvquiet");
    let registry = sweep.registry().await;
    let admin = connect().await;
    let user = UserId::new(&SystemRng);
    let (old, new, other) = (new_key(), new_key(), new_key());
    registry.register(&user, &old).await.unwrap();
    registry.register(&user, &other).await.unwrap();

    let listener = connect().await;
    let mut published = listener.message_rx();
    listener
        .psubscribe(format!("{}:revoked-*", sweep.prefix()))
        .await
        .expect("PSUBSCRIBE");
    let watch = |session: SessionKey| {
        let registry = registry.clone();
        tokio::spawn(async move { registry.watch_revocation(&user, &session).await })
    };
    let (watching_old, watching_other) = (watch(old), watch(other));
    eventually("the two watchers joined", || async {
        registry.subscriber.watcher_count() == 2
    })
    .await;
    let connection = connection_name(sweep.prefix());
    eventually("the watchers' connection is subscribed", || async {
        subscriber_connections(&admin, &connection).await == 1
    })
    .await;

    assert_eq!(
        moved(&registry, &user, &old, &new).await,
        MoveOutcome::Moved
    );
    let marker = revocation_session_channel(sweep.prefix(), &other.to_string());
    let _: i64 = admin.publish(marker.as_str(), "1").await.expect("PUBLISH");
    tokio::time::timeout(Duration::from_secs(5), watching_other)
        .await
        .expect("the watcher of the session published for is told")
        .unwrap();
    assert!(
        !watching_old.is_finished(),
        "a watcher of the key moved from was woken by the move"
    );
    let first = tokio::time::timeout(Duration::from_secs(5), published.recv())
        .await
        .expect("the hand-published message arrives")
        .expect("a message");
    assert_eq!(
        first.channel.to_string(),
        marker,
        "the move published before the marker"
    );
    watching_old.abort();
    let _ = listener.quit().await;
    drop(serial);
}

/// On a server that stopped running scripts after the registry was built
/// (an ACL changed under it), the move and the cut-off answer `Unsupported`
/// and change nothing, the current key still answers, and an ending by a
/// former key still ends the session it leads to, by separate commands,
/// with one warning.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_server_that_stops_running_scripts_still_ends_a_session_by_a_former_key() {
    let capture = TracingCapture::install();
    let sweep = Sweep::node("mvnoscript");
    let prefix = sweep.prefix().to_owned();
    with_scripting_refused(move |admin, restricted| async move {
        let registry = ValkeySessionRegistry::assembled(restricted, prefix.as_str().into(), TTL);
        let user = UserId::new(&SystemRng);
        let (old, new, other, former) = (new_key(), new_key(), new_key(), new_key());
        registry.register(&user, &old).await.expect("register");
        registry.register(&user, &other).await.expect("register");

        let refused = registry.move_session(&user, &old, &new).await;
        assert!(
            matches!(refused, Err(ValkeyStoreError::Unsupported(_))),
            "{refused:?}"
        );
        assert!(registry.is_valid(&user, &old).await.unwrap());
        assert!(!registry.is_valid(&user, &new).await.unwrap());
        assert_eq!(records(&admin, &prefix, &user).await, []);
        let cut = registry.invalidate_other_sessions(&user, &old).await;
        assert!(
            matches!(cut, Err(ValkeyStoreError::Unsupported(_))),
            "{cut:?}"
        );
        assert!(registry.is_valid(&user, &other).await.unwrap());

        // A record planted by hand, as a move on a server that ran scripts
        // would have left it.
        let keys = user_keys(&prefix, &user).expect("one slot");
        let _: i64 = admin
            .hset(&keys.forward, (former.to_string(), old.to_string()))
            .await
            .expect("HSET");
        let _: i64 = admin
            .zadd(
                &keys.forward_order,
                None,
                None,
                false,
                false,
                (1.0, former.to_string()),
            )
            .await
            .expect("ZADD");
        assert_eq!(current(&registry, &user, &former).await, Some(old));

        registry
            .invalidate_session(&user, &former)
            .await
            .expect("an ending by a former key");
        assert!(
            !registry.is_valid(&user, &old).await.unwrap(),
            "the session the former key leads to is ended"
        );
        assert!(registry.is_valid(&user, &other).await.unwrap());
        assert_eq!(records(&admin, &prefix, &user).await, []);
    })
    .await;
    let warned = capture
        .events()
        .iter()
        .filter(|e| {
            e.level == tracing::Level::WARN && e.message.contains("ended by separate commands")
        })
        .count();
    assert_eq!(warned, 1, "{:#?}", capture.events());
    drop(sweep);
}
