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
    let mut expected: HashMap<(String, UserId), HashSet<String>> = HashMap::new();
    for ((issuer, sid), (user, _, _)) in &state.entries {
        expected
            .entry((issuer.clone(), *user))
            .or_default()
            .insert(sid.clone());
    }
    assert_eq!(
        state.by_user, expected,
        "user index must mirror the entries"
    );
    for (key, (_, _, inserted)) in &state.entries {
        assert!(
            state.order.iter().any(|(at, k)| k == key && at == inserted),
            "entry {key:?} must have a queue item"
        );
    }
}

#[test]
fn user_index_agrees_with_entries_across_inserts_displacements_and_removals() {
    let map = SidMap::new();
    let s = Sessions::new();
    let (alice, bob) = (user("alice"), user("bob"));

    map.insert(key(ISS, "a"), alice, s.next(), at(0));
    map.insert(key(ISS, "b"), alice, s.next(), at(1));
    map.insert(key(OTHER, "a"), alice, s.next(), at(2));
    map.insert(key(ISS, "c"), bob, s.next(), at(3));
    assert_consistent(&map);

    // The same (issuer, sid) now belongs to bob: alice's index entry moves.
    let displaced = map.insert(key(ISS, "a"), bob, s.next(), at(4));
    assert_eq!(displaced.map(|e| e.0), Some(alice));
    assert_consistent(&map);

    map.remove(&key(ISS, "b"));
    assert_consistent(&map);
    assert_eq!(map.len(), 3);
}

#[test]
fn take_user_sessions_takes_only_that_user_under_that_issuer() {
    let map = SidMap::new();
    let s = Sessions::new();
    let (alice, bob) = (user("alice"), user("bob"));
    let (a1, a2, a_other, b1) = (s.next(), s.next(), s.next(), s.next());
    map.insert(key(ISS, "1"), alice, a1, at(0));
    map.insert(key(ISS, "2"), alice, a2, at(1));
    map.insert(key(OTHER, "1"), alice, a_other, at(2));
    map.insert(key(ISS, "3"), bob, b1, at(3));

    let mut taken = map.take_user_sessions(ISS, &alice);
    taken.sort();
    let mut expected = vec![a1, a2];
    expected.sort();
    assert_eq!(taken, expected);

    assert_eq!(map.len(), 2);
    assert!(map.contains_key(&key(OTHER, "1")), "other issuer untouched");
    assert!(map.contains_key(&key(ISS, "3")), "other user untouched");
    assert!(map.take_user_sessions(ISS, &alice).is_empty());
    assert_consistent(&map);
}

#[test]
fn ageing_out_costs_the_batch_and_leaves_the_rest() {
    let map = SidMap::new();
    let s = Sessions::new();
    let u = user("u");
    for n in 0..1_000 {
        map.insert(key(ISS, &n.to_string()), u, s.next(), at(n));
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
    map.insert(key(ISS, "x"), u, s.next(), at(0));
    // Re-login with the same sid refreshes the mapping.
    map.insert(key(ISS, "x"), u, s.next(), at(1_000));

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
        map.insert(key(ISS, &n.to_string()), u, s.next(), at(n));
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
        map.insert(key(ISS, &n.to_string()), u, s.next(), at(n));
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
    map.insert(key(ISS, "keep"), user("a"), keep, at(0));
    map.insert(key(ISS, "drop"), user("b"), drop, at(1));
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
    map.register_subject_session(ISS, alice, a1);
    map.register_subject_session(ISS, alice, a2);
    map.register_subject_session(ISS, alice, a2);
    map.register_subject_session(OTHER, alice, other);
    map.register_subject_session(ISS, bob, b1);
    assert_eq!(map.subject_len(), 4, "a repeated registration counts once");

    let mut taken = map.take_subject_sessions(ISS, &alice);
    taken.sort_by_key(|id| id.to_string());
    let mut expected = vec![a1, a2];
    expected.sort_by_key(|id| id.to_string());
    assert_eq!(taken, expected);
    assert_eq!(map.subject_len(), 2);
    assert!(map.take_subject_sessions(ISS, &alice).is_empty());
    assert_eq!(map.take_subject_sessions(OTHER, &alice), vec![other]);
    assert_eq!(map.take_subject_sessions(ISS, &bob), vec![b1]);
}

#[test]
fn taking_subject_sessions_also_takes_the_sid_entries() {
    let map = SidMap::new();
    let s = Sessions::new();
    let alice = user("alice");
    let (with_sid, without) = (s.next(), s.next());
    map.insert(key(ISS, "a"), alice, with_sid, at(0));
    map.register_subject_session(ISS, alice, with_sid);
    map.register_subject_session(ISS, alice, without);

    let taken = map.take_subject_sessions(ISS, &alice);

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
        map.insert(key(ISS, sid), alice, session, at(0));
        map.register_subject_session(ISS, alice, session);
    }
    assert_eq!(map.subject_len(), 3);

    map.remove(&key(ISS, "r")).expect("mapped");
    assert_eq!(map.subject_len(), 2);
    assert_eq!(map.remove_session(&by_session), 1);
    assert_eq!(map.subject_len(), 1);
    assert_eq!(map.take_user_sessions(ISS, &alice), vec![by_user]);
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
        map.insert(key(ISS, &format!("sid-{n}")), alice, session, at(n));
        map.register_subject_session(ISS, alice, session);
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
        map.register_subject_session(ISS, alice, *id);
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
        map.register_subject_session(ISS, alice, session);
        map.forget_subject_session(ISS, &alice, &session);
    }
    let queued = map.lock().subject_order.len();
    assert!(
        queued <= 2 * map.subject_len() + QUEUE_SLACK + 1,
        "queue held {queued}"
    );
}
