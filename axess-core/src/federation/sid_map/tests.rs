use super::*;
use crate::testing::mock_random::MockRng;

const ISS: &str = "https://idp.example.com";
const OTHER: &str = "https://other.example.com";

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
}

fn user(label: &str) -> UserId {
    axess_identity::testing::user(label)
}

fn key(issuer: &str, sid: &str) -> SidKey {
    (issuer.to_string(), sid.to_string())
}

/// Insert as a user whose IdP subject is their local id (the unlinked case).
fn put(
    map: &SidMap,
    key: SidKey,
    user: UserId,
    session: SessionId,
    at: DateTime<Utc>,
) -> Option<SidEntry> {
    map.insert(key, &user.to_string(), user, session, at)
}

/// Register a session of a user whose IdP subject is their local id.
fn reg(map: &SidMap, issuer: &str, user: UserId, session: SessionId) {
    map.register_subject_session(issuer, &user.to_string(), user, session);
}

/// A deterministic stream of session ids.
struct Sessions(MockRng);

impl Sessions {
    fn new() -> Self {
        Self(MockRng::new(11))
    }
    fn next(&self) -> SessionId {
        SessionId::new(&self.0)
    }
}

/// Recompute the user index and check the queue against the entries; the
/// map's three structures must agree after every operation.
fn assert_consistent(map: &SidMap) {
    let state = map.lock();
    let mut expected: HashMap<(String, String), HashSet<String>> = HashMap::new();
    for ((issuer, sid), stored) in &state.entries {
        expected
            .entry((issuer.clone(), stored.subject.clone()))
            .or_default()
            .insert(sid.clone());
    }
    assert_eq!(
        state.by_subject, expected,
        "subject index must mirror the entries"
    );
    let mut sessions: HashMap<SessionId, HashSet<SidKey>> = HashMap::new();
    for (key, stored) in &state.entries {
        sessions
            .entry(stored.session)
            .or_default()
            .insert(key.clone());
    }
    assert_eq!(
        state.keys_of_session, sessions,
        "session index must mirror the entries"
    );
    for (key, stored) in &state.entries {
        assert!(
            state
                .order
                .iter()
                .any(|(at, k)| k == key && *at == stored.at),
            "entry {key:?} must have a queue item"
        );
    }
}

#[test]
fn user_index_agrees_with_entries_across_inserts_displacements_and_removals() {
    let map = SidMap::new();
    let s = Sessions::new();
    let (alice, bob) = (user("alice"), user("bob"));

    put(&map, key(ISS, "a"), alice, s.next(), at(0));
    put(&map, key(ISS, "b"), alice, s.next(), at(1));
    put(&map, key(OTHER, "a"), alice, s.next(), at(2));
    put(&map, key(ISS, "c"), bob, s.next(), at(3));
    assert_consistent(&map);

    // The same (issuer, sid) now belongs to bob: alice's index entry moves.
    let displaced = put(&map, key(ISS, "a"), bob, s.next(), at(4));
    assert_eq!(displaced.map(|e| e.0), Some(alice));
    assert_consistent(&map);

    map.remove(&key(ISS, "b"));
    assert_consistent(&map);
    assert_eq!(map.len(), 3);
}

#[test]
fn take_subject_sessions_takes_only_that_subject_under_that_issuer() {
    let map = SidMap::new();
    let s = Sessions::new();
    let (alice, bob) = (user("alice"), user("bob"));
    let (a1, a2, a_other, b1) = (s.next(), s.next(), s.next(), s.next());
    put(&map, key(ISS, "1"), alice, a1, at(0));
    put(&map, key(ISS, "2"), alice, a2, at(1));
    put(&map, key(OTHER, "1"), alice, a_other, at(2));
    put(&map, key(ISS, "3"), bob, b1, at(3));

    let mut taken: Vec<SessionId> = map
        .take_subject_sessions(ISS, &alice.to_string())
        .into_iter()
        .map(|(_, session)| session)
        .collect();
    taken.sort();
    let mut expected = vec![a1, a2];
    expected.sort();
    assert_eq!(taken, expected);

    assert_eq!(map.len(), 2);
    assert!(map.contains_key(&key(OTHER, "1")), "other issuer untouched");
    assert!(map.contains_key(&key(ISS, "3")), "other subject untouched");
    assert!(
        map.take_subject_sessions(ISS, &alice.to_string())
            .is_empty()
    );
    assert_consistent(&map);
}

/// A linked account: the IdP's subject is not the local user id, and a
/// subject-only logout still reaches the session, reporting the local user
/// the session is registered under.
#[test]
fn a_linked_subject_finds_its_sessions_under_the_local_user() {
    let map = SidMap::new();
    let s = Sessions::new();
    let local = user("local-user");
    let (with_sid, without_sid) = (s.next(), s.next());
    map.insert(key(ISS, "s1"), "google-oauth2|1234", local, with_sid, at(0));
    map.register_subject_session(ISS, "google-oauth2|1234", local, with_sid);
    map.register_subject_session(ISS, "google-oauth2|1234", local, without_sid);

    // The local id names nobody to the IdP.
    assert!(
        map.take_subject_sessions(ISS, &local.to_string())
            .is_empty()
    );
    assert_eq!(map.len(), 1);

    let mut taken = map.take_subject_sessions(ISS, "google-oauth2|1234");
    taken.sort_by_key(|(_, session)| session.to_string());
    let mut expected = vec![(local, with_sid), (local, without_sid)];
    expected.sort_by_key(|(_, session)| session.to_string());
    assert_eq!(taken, expected);
    assert!(map.is_empty());
    assert_eq!(map.subject_len(), 0);
    assert_consistent(&map);
}

/// Inserting one key again at one instant, as a frozen clock does, keeps one
/// queue item, so the queue cannot outgrow the map.
#[test]
fn reinserting_a_key_at_the_same_instant_does_not_grow_the_queue() {
    let map = SidMap::new();
    let s = Sessions::new();
    let u = user("u");
    for _ in 0..1_000 {
        put(&map, key(ISS, "x"), u, s.next(), at(0));
    }
    assert_eq!(map.len(), 1);
    assert!(
        map.lock().order.len() <= 2 + QUEUE_SLACK,
        "queue held {}",
        map.lock().order.len()
    );
    assert_eq!(map.evict_oldest(10).len(), 1, "eviction still removes it");
    assert!(map.is_empty());
}

/// A replaced or removed entry leaves nothing in the time order, so a pass of
/// `max` removes `max` live entries.
#[test]
fn replaced_and_removed_entries_do_not_count_toward_the_eviction_budget() {
    let map = SidMap::new();
    let s = Sessions::new();
    let u = user("u");
    // Key "a" is replaced, leaving its first queue item stale; "gone" is
    // removed, leaving another.
    put(&map, key(ISS, "a"), u, s.next(), at(0));
    put(&map, key(ISS, "a"), u, s.next(), at(1));
    put(&map, key(ISS, "gone"), u, s.next(), at(2));
    map.remove(&key(ISS, "gone"));
    put(&map, key(ISS, "b"), u, s.next(), at(3));

    let evicted = map.evict_oldest(2);

    assert_eq!(evicted.len(), 2, "both live entries went in one pass");
    assert!(map.is_empty());
    assert_consistent(&map);
}

#[test]
fn ageing_out_costs_the_batch_and_leaves_the_rest() {
    let map = SidMap::new();
    let s = Sessions::new();
    let u = user("u");
    for n in 0..1_000 {
        put(&map, key(ISS, &n.to_string()), u, s.next(), at(n));
    }
    // Everything before t=500 is due; only 128 are taken per call.
    let first = map.evict_inserted_before(at(500), 128);
    assert_eq!(first.len(), 128);
    assert_eq!(map.len(), 872);
    assert_eq!(first[0].0, key(ISS, "0"), "oldest first");
    assert_eq!(first[127].0, key(ISS, "127"));

    // Draining the backlog takes the other 372 due entries, no more.
    let rest = map.evict_inserted_before(at(500), 10_000);
    assert_eq!(rest.len(), 372);
    assert_eq!(map.len(), 500);
    assert!(map.evict_inserted_before(at(500), 10_000).is_empty());
    assert_consistent(&map);
}

#[test]
fn a_replaced_mapping_is_not_aged_out_under_its_old_time() {
    let map = SidMap::new();
    let s = Sessions::new();
    let u = user("u");
    put(&map, key(ISS, "x"), u, s.next(), at(0));
    // Re-login with the same sid refreshes the mapping.
    put(&map, key(ISS, "x"), u, s.next(), at(1_000));

    assert!(map.evict_inserted_before(at(500), 10).is_empty());
    assert_eq!(
        map.len(),
        1,
        "the refreshed mapping outlives the stale queue item"
    );
    assert_eq!(map.evict_inserted_before(at(2_000), 10).len(), 1);
}

#[test]
fn evict_oldest_takes_in_insertion_order() {
    let map = SidMap::new();
    let s = Sessions::new();
    let u = user("u");
    for n in 0..10 {
        put(&map, key(ISS, &n.to_string()), u, s.next(), at(n));
    }
    let evicted = map.evict_oldest(3);
    let sids: Vec<_> = evicted.iter().map(|(k, _)| k.1.clone()).collect();
    assert_eq!(sids, ["0", "1", "2"]);
    assert_eq!(map.len(), 7);
}

#[test]
fn the_queue_stays_a_small_multiple_of_the_map_under_churn() {
    let map = SidMap::new();
    let s = Sessions::new();
    let u = user("u");
    // Every login is followed by its logout: the map stays at one entry
    // while 5,000 queue items would pile up if stale ones were never shed.
    for n in 0..5_000 {
        put(&map, key(ISS, &n.to_string()), u, s.next(), at(n));
        if n > 0 {
            map.remove(&key(ISS, &(n - 1).to_string()));
        }
    }
    assert_eq!(map.len(), 1);
    let queued = map.lock().order.len();
    assert!(queued <= 2 + QUEUE_SLACK + 2, "queue grew to {queued}");
    assert_consistent(&map);
}

#[test]
fn remove_session_unwinds_one_login() {
    let map = SidMap::new();
    let s = Sessions::new();
    let (keep, drop) = (s.next(), s.next());
    put(&map, key(ISS, "keep"), user("a"), keep, at(0));
    put(&map, key(ISS, "drop"), user("b"), drop, at(1));
    assert_eq!(map.remove_session(&drop), 1);
    assert_eq!(map.remove_session(&drop), 0);
    assert!(map.contains_key(&key(ISS, "keep")));
    assert_consistent(&map);
}

// ── subject registry ─────────────────────────────────────────────────────────

#[test]
fn subject_sessions_are_taken_per_issuer_and_user() {
    let map = SidMap::new();
    let s = Sessions::new();
    let (alice, bob) = (user("alice"), user("bob"));
    let (a1, a2, other, b1) = (s.next(), s.next(), s.next(), s.next());
    reg(&map, ISS, alice, a1);
    reg(&map, ISS, alice, a2);
    reg(&map, ISS, alice, a2);
    reg(&map, OTHER, alice, other);
    reg(&map, ISS, bob, b1);
    assert_eq!(map.subject_len(), 4, "a repeated registration counts once");

    let sub = |u: &UserId| u.to_string();
    let mut taken: Vec<SessionId> = map
        .take_subject_sessions(ISS, &sub(&alice))
        .into_iter()
        .map(|(_, session)| session)
        .collect();
    taken.sort_by_key(|id| id.to_string());
    let mut expected = vec![a1, a2];
    expected.sort_by_key(|id| id.to_string());
    assert_eq!(taken, expected);
    assert_eq!(map.subject_len(), 2);
    assert!(map.take_subject_sessions(ISS, &sub(&alice)).is_empty());
    assert_eq!(
        map.take_subject_sessions(OTHER, &sub(&alice)),
        vec![(alice, other)]
    );
    assert_eq!(map.take_subject_sessions(ISS, &sub(&bob)), vec![(bob, b1)]);
}

#[test]
fn taking_subject_sessions_also_takes_the_sid_entries() {
    let map = SidMap::new();
    let s = Sessions::new();
    let alice = user("alice");
    let (with_sid, without) = (s.next(), s.next());
    put(&map, key(ISS, "a"), alice, with_sid, at(0));
    reg(&map, ISS, alice, with_sid);
    reg(&map, ISS, alice, without);

    let taken = map.take_subject_sessions(ISS, &alice.to_string());

    assert_eq!(taken.len(), 2, "the shared session is reported once");
    assert!(map.is_empty());
    assert_consistent(&map);
}

#[test]
fn ending_a_session_through_the_sid_paths_forgets_its_subject_entry() {
    let map = SidMap::new();
    let s = Sessions::new();
    let alice = user("alice");
    let (by_remove, by_user, by_session) = (s.next(), s.next(), s.next());
    for (sid, session) in [("r", by_remove), ("u", by_user), ("s", by_session)] {
        put(&map, key(ISS, sid), alice, session, at(0));
        reg(&map, ISS, alice, session);
    }
    assert_eq!(map.subject_len(), 3);

    map.remove(&key(ISS, "r")).expect("mapped");
    assert_eq!(map.subject_len(), 2);
    assert_eq!(map.remove_session(&by_session), 1);
    assert_eq!(map.subject_len(), 1);
    assert_eq!(
        map.take_subject_sessions(ISS, &alice.to_string()),
        vec![(alice, by_user)]
    );
    assert_eq!(map.subject_len(), 0);
}

/// Dropping sid entries by age or capacity leaves the subject registry alone.
#[test]
fn eviction_of_sid_entries_keeps_the_subject_entries() {
    let map = SidMap::new();
    let s = Sessions::new();
    let alice = user("alice");
    for n in 0..3 {
        let session = s.next();
        put(&map, key(ISS, &format!("sid-{n}")), alice, session, at(n));
        reg(&map, ISS, alice, session);
    }
    assert_eq!(map.evict_oldest(2).len(), 2);
    assert_eq!(map.evict_inserted_before(at(100), 10).len(), 1);
    assert!(map.is_empty());
    assert_eq!(map.subject_len(), 3);
}

#[test]
fn the_sweep_rotates_through_live_triples_and_skips_forgotten_ones() {
    let map = SidMap::new();
    let s = Sessions::new();
    let alice = user("alice");
    let ids: Vec<SessionId> = (0..4).map(|_| s.next()).collect();
    for id in &ids {
        reg(&map, ISS, alice, *id);
    }
    map.forget_subject_session(ISS, &alice, &ids[1]);

    let first = map.sweep_subject_candidates(2);
    let second = map.sweep_subject_candidates(2);
    let mut seen: Vec<SessionId> = first.iter().chain(&second).map(|t| t.2).collect();
    seen.sort_by_key(|id| id.to_string());
    seen.dedup();
    assert_eq!(
        seen.len(),
        3,
        "every live triple is visited, the forgotten one never"
    );
    assert!(!seen.contains(&ids[1]));
}

#[test]
fn the_sweep_queue_stays_bounded_when_sessions_are_forgotten() {
    let map = SidMap::new();
    let s = Sessions::new();
    let alice = user("alice");
    for _ in 0..1_000 {
        let session = s.next();
        reg(&map, ISS, alice, session);
        map.forget_subject_session(ISS, &alice, &session);
    }
    let queued = map.lock().subject_order.len();
    assert!(
        queued <= 2 * map.subject_len() + QUEUE_SLACK + 1,
        "queue held {queued}"
    );
}

/// An entry stamped before its predecessors, as happens after the clock
/// steps back, still ages out on schedule. The order is by the time an entry
/// carries, not by when it arrived, so the older stamp is not stuck behind a
/// newer one at the front.
#[test]
fn an_entry_stamped_before_its_predecessors_ages_out_on_schedule() {
    let map = SidMap::new();
    let s = Sessions::new();
    let u = user("u");
    // Arrives first and is recent; the clock then steps back an hour and the
    // next login is stamped long before it.
    put(&map, key(ISS, "recent"), u, s.next(), at(10_000));
    put(&map, key(ISS, "stepped-back"), u, s.next(), at(0));

    let aged = map.evict_inserted_before(at(5_000), 10);

    let sids: Vec<_> = aged.iter().map(|(k, _)| k.1.clone()).collect();
    assert_eq!(
        sids,
        ["stepped-back"],
        "the old stamp is due, the recent one is not"
    );
    assert!(map.contains_key(&key(ISS, "recent")));
    assert_consistent(&map);
}

/// The fan-out order of a subject logout is the same on every run: the
/// registry is a hash set, and its iteration order is not.
#[test]
fn a_subject_logout_returns_its_sessions_in_a_fixed_order() {
    let u = user("u");
    let s = Sessions::new();
    let sessions: Vec<_> = (0..16).map(|_| s.next()).collect();
    let mut expected: Vec<(UserId, SessionId)> = sessions.iter().map(|x| (u, *x)).collect();
    expected.sort_unstable();
    // Fresh maps get fresh hasher keys; the output must not depend on them.
    for _ in 0..8 {
        let map = SidMap::new();
        for session in &sessions {
            reg(&map, ISS, u, *session);
        }
        let taken = map.take_subject_sessions(ISS, &u.to_string());
        assert_eq!(taken, expected);
    }
}

/// A mapping the displacing login took out can be put back, with its
/// original insertion time, while the key is still vacant and its session
/// still lives; not over a newer mapping, and not for a session that ended.
#[test]
fn a_displaced_mapping_is_restored_only_into_a_vacant_key_for_a_live_session() {
    let map = SidMap::new();
    let s = Sessions::new();
    let (a, b) = (user("a"), user("b"));
    let (sa, sb) = (s.next(), s.next());
    reg(&map, ISS, a, sa);
    map.insert(key(ISS, "x"), &a.to_string(), a, sa, at(5));

    let displaced = map
        .insert_displacing(key(ISS, "x"), &b.to_string(), b, sb, at(9))
        .expect("a's mapping is displaced");
    assert_eq!((displaced.user, displaced.session), (a, sa));
    assert_eq!(displaced.inserted_at, at(5));

    // The key is taken, so nothing is restored over it.
    assert!(!map.restore_if_vacant(key(ISS, "x"), displaced.clone()));
    assert_eq!(map.get(&key(ISS, "x")).map(|e| e.0), Some(b));

    map.remove_session(&sb);
    assert!(map.restore_if_vacant(key(ISS, "x"), displaced.clone()));
    assert_eq!(map.get(&key(ISS, "x")), Some((a, sa, at(5))));
    assert_consistent(&map);

    // An ended session is not resurrected.
    map.remove(&key(ISS, "x"));
    assert!(!map.restore_if_vacant(key(ISS, "x"), displaced));
}
