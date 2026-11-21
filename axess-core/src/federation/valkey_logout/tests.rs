//! The Valkey `sid` store and replay log against a live server, ignored by
//! default: `VALKEY_URL=redis://127.0.0.1:6390 cargo test -p axess-core
//! --features testing,oauth,jwt-aws-lc,valkey -- --ignored valkey_logout`.
//! Each test removes what it wrote, also when it fails.

use super::*;
use crate::session::id::{SessionId, SessionKey};
use crate::testing::mock_random::MockRng;
use crate::testing::valkey_sweep::{KeySweep, Swept};
use axess_clock::testing::Shift;

/// A `sid` record stamps its insertion in whole microseconds since the
/// epoch, rounded down, and reads them back; a value it cannot hold reads as
/// the epoch.
#[test]
fn a_sid_record_stamps_microseconds() {
    let stamp = |text: &str| {
        let row = format!(r#"{{"admin":"01010101-0101-0101-0101-010101010101","since":"{text}"}}"#);
        serde_json::from_str::<crate::session::data::Impersonation>(&row)
            .expect("reads")
            .since
    };
    assert_eq!(
        micros(stamp("2026-01-01T00:00:00.123456789Z")),
        1_767_225_600_123_456
    );
    assert_eq!(micros(stamp("1969-12-31T23:59:59.9999995Z")), -1);
    assert_eq!(
        from_micros(1_767_225_600_123_456),
        stamp("2026-01-01T00:00:00.123456Z")
    );
    assert_eq!(from_micros(-1), stamp("1969-12-31T23:59:59.999999Z"));
    assert_eq!(from_micros(i64::MAX), stamp("1970-01-01T00:00:00Z"));
}

/// A fresh prefix named by `tag`, whose keys are removed when the sweep is
/// dropped: at the end of the test that holds it, also when it fails.
fn sweep(tag: &str) -> KeySweep {
    crate::testing::valkey_sweep::on_node(&format!("logout_{tag}"))
}

async fn client() -> Client {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = Client::new(Config::from_url(&url).expect("url"), None, None, None);
    client.init().await.expect("connect");
    client
}

/// A store under a fresh prefix, held with the sweep of its keys.
async fn store(tag: &str) -> Swept<ValkeySidStore> {
    let sweep = sweep(tag);
    let store = ValkeySidStore::new(client().await).with_prefix(sweep.prefix());
    sweep.hold(store)
}

const ISS: &str = "https://idp.example.com";

fn key(sid: &str) -> SidKey {
    (ISS.to_string(), sid.to_string())
}

fn ids() -> (UserId, UserId, SessionKey, SessionKey, TenantId, TenantId) {
    let rng = MockRng::new(41);
    (
        axess_identity::testing::user("alice"),
        axess_identity::testing::user("bob"),
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
        axess_identity::testing::tenant("acme"),
        axess_identity::testing::tenant("beta"),
    )
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_a_mapping_is_found_only_in_its_tenants_scope() {
    let s = store("scope").await;
    let (alice, _, sa, _, acme, beta) = ids();
    let at = axess_clock::testing::MockClock::reference_time();
    s.register_subject_session(ISS, "sub", Some(acme), alice, sa)
        .await
        .unwrap();
    assert!(
        s.insert_displacing(key("sid-a"), "sub", Some(acme), alice, sa, at)
            .await
            .unwrap()
            .is_none()
    );

    let found = s.get(&key("sid-a"), Some(&acme)).await.unwrap();
    assert_eq!(found.map(|e| (e.0, e.1)), Some((alice, sa)));
    assert!(s.get(&key("sid-a"), Some(&beta)).await.unwrap().is_none());
    assert!(s.get(&key("sid-a"), None).await.unwrap().is_some());
    assert_eq!(
        s.subject_sessions(ISS, "sub", Some(&acme)).await.unwrap(),
        vec![(alice, sa)]
    );
    assert!(
        s.subject_sessions(ISS, "sub", Some(&beta))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_remove_if_session_removes_only_the_named_session() {
    let s = store("removeif").await;
    let (alice, bob, sa, sb, acme, _) = ids();
    let at = axess_clock::testing::MockClock::reference_time();
    s.register_subject_session(ISS, "sub-a", Some(acme), alice, sa)
        .await
        .unwrap();
    s.insert_displacing(key("x"), "sub-a", Some(acme), alice, sa, at)
        .await
        .unwrap();

    // Another session took the key meanwhile: the old one's removal is a no-op.
    let displaced = s
        .insert_displacing(key("x"), "sub-b", Some(acme), bob, sb, at)
        .await
        .unwrap()
        .expect("alice's mapping is displaced");
    assert_eq!((displaced.user, displaced.session), (alice, sa));
    assert!(s.remove_if_session(&key("x"), &sa).await.unwrap().is_none());
    assert!(s.get(&key("x"), None).await.unwrap().is_some());

    let removed = s.remove_if_session(&key("x"), &sb).await.unwrap();
    assert_eq!(removed.map(|e| e.1), Some(sb));
    assert!(s.get(&key("x"), None).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_remove_session_clears_mappings_and_the_subject_record() {
    let s = store("removesession").await;
    let (alice, _, sa, _, acme, _) = ids();
    let at = axess_clock::testing::MockClock::reference_time();
    s.register_subject_session(ISS, "sub", Some(acme), alice, sa)
        .await
        .unwrap();
    for sid in ["one", "two"] {
        s.insert_displacing(key(sid), "sub", Some(acme), alice, sa, at)
            .await
            .unwrap();
    }
    assert_eq!(s.remove_session(&sa).await.unwrap(), 2);
    assert!(s.get(&key("one"), None).await.unwrap().is_none());
    assert!(
        s.subject_sessions(ISS, "sub", None)
            .await
            .unwrap()
            .is_empty(),
        "the subject record went with the session"
    );
    assert!(!s.forget_subject_session(ISS, &alice, &sa).await.unwrap());
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_a_displaced_mapping_comes_back_only_while_its_key_is_vacant() {
    let s = store("restore").await;
    let (alice, bob, sa, sb, acme, _) = ids();
    let at = axess_clock::testing::MockClock::reference_time();
    s.register_subject_session(ISS, "sub-a", Some(acme), alice, sa)
        .await
        .unwrap();
    s.insert_displacing(key("x"), "sub-a", Some(acme), alice, sa, at)
        .await
        .unwrap();
    let displaced = s
        .insert_displacing(key("x"), "sub-b", Some(acme), bob, sb, at)
        .await
        .unwrap()
        .expect("displaced");

    assert!(
        !s.restore_if_vacant(key("x"), displaced.clone())
            .await
            .unwrap(),
        "the key is taken"
    );
    s.remove_session(&sb).await.unwrap();
    assert!(
        s.restore_if_vacant(key("x"), displaced.clone())
            .await
            .unwrap()
    );
    assert_eq!(
        s.get(&key("x"), Some(&acme)).await.unwrap().map(|e| e.1),
        Some(sa)
    );

    s.remove_session(&sa).await.unwrap();
    assert!(
        !s.restore_if_vacant(key("x"), displaced).await.unwrap(),
        "an ended session is not resurrected"
    );
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_a_pair_is_new_then_in_flight_then_a_replay_until_forgotten() {
    let sweep = sweep("jti");
    let log = ValkeyReplayLog::new(client().await).with_prefix(sweep.prefix());
    let now = axess_clock::testing::MockClock::reference_time();
    assert_eq!(log.record(ISS, "j1", now).await.unwrap(), Recorded::New);
    assert_eq!(
        log.record(ISS, "j1", now).await.unwrap(),
        Recorded::InFlight
    );
    log.settle(ISS, "j1").await.unwrap();
    assert_eq!(log.record(ISS, "j1", now).await.unwrap(), Recorded::Replay);
    assert_eq!(
        log.record("https://other", "j1", now).await.unwrap(),
        Recorded::New,
        "another issuer's pair is another pair"
    );

    assert_eq!(log.record(ISS, "j2", now).await.unwrap(), Recorded::New);
    log.forget(ISS, "j2").await.unwrap();
    assert_eq!(log.record(ISS, "j2", now).await.unwrap(), Recorded::New);
}

/// The default lifetimes are the ones the constants' text states: a `sid`
/// mapping lives a day and an hour, past the in-process map's 24 hour
/// prune, and a subject record thirty days.
#[test]
fn the_default_lifetimes_are_a_day_and_an_hour_and_thirty_days() {
    assert_eq!(DEFAULT_SID_TTL, Duration::from_secs(90_000));
    assert_eq!(DEFAULT_SUBJECT_TTL, Duration::from_secs(2_592_000));
}

/// A mapping keeps the instant it was inserted at, to the microsecond:
/// through a read, through a displacement, and through its restoration.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_a_mapping_keeps_the_instant_it_was_inserted_at() {
    let s = store("instant").await;
    let (alice, bob, sa, sb, acme, _) = ids();
    let at = axess_clock::testing::MockClock::reference_time()
        .plus(axess_clock::SignedDuration::microseconds(1_234_567));
    let later = at.plus(axess_clock::SignedDuration::seconds(9));
    s.register_subject_session(ISS, "sub-a", Some(acme), alice, sa)
        .await
        .unwrap();
    s.insert_displacing(key("x"), "sub-a", Some(acme), alice, sa, at)
        .await
        .unwrap();
    assert_eq!(s.get(&key("x"), None).await.unwrap().map(|e| e.2), Some(at));

    let displaced = s
        .insert_displacing(key("x"), "sub-b", Some(acme), bob, sb, later)
        .await
        .unwrap()
        .expect("displaced");
    assert_eq!(displaced.inserted_at, at);
    assert_eq!(
        s.get(&key("x"), None).await.unwrap().map(|e| e.2),
        Some(later)
    );

    s.remove_session(&sb).await.unwrap();
    assert!(s.restore_if_vacant(key("x"), displaced).await.unwrap());
    assert_eq!(s.get(&key("x"), None).await.unwrap().map(|e| e.2), Some(at));
}

/// Subject records are kept per issuer and subject: a `sub` logout lists
/// that subject's sessions under that issuer, not another issuer's subject
/// of the same name and not another subject.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_subject_sessions_are_per_issuer_and_subject() {
    const OTHER: &str = "https://other.example.com";
    let s = store("subjects").await;
    let (alice, bob, sa, sb, acme, _) = ids();
    s.register_subject_session(ISS, "sub", Some(acme), alice, sa)
        .await
        .unwrap();
    s.register_subject_session(OTHER, "sub", Some(acme), bob, sb)
        .await
        .unwrap();

    assert_eq!(
        s.subject_sessions(ISS, "sub", None).await.unwrap(),
        vec![(alice, sa)]
    );
    assert_eq!(
        s.subject_sessions(OTHER, "sub", None).await.unwrap(),
        vec![(bob, sb)]
    );
    assert!(
        s.subject_sessions(ISS, "another-sub", None)
            .await
            .unwrap()
            .is_empty()
    );
}

/// The mapping keys in a session's index, sorted.
async fn indexed(s: &ValkeySidStore, session: &SessionKey) -> Vec<String> {
    let mut members: Vec<String> = s
        .client
        .smembers(s.sids_key(session).unwrap())
        .await
        .unwrap();
    members.sort();
    members
}

/// A mapping that is displaced, or removed for its session, leaves that
/// session's index of mappings: the index holds only keys that still map to
/// the session.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_a_mapping_that_leaves_a_session_leaves_its_index() {
    let s = store("index").await;
    let (alice, bob, sa, sb, acme, _) = ids();
    let at = axess_clock::testing::MockClock::reference_time();
    let (x, y) = (s.sid_key(&key("x")).unwrap(), s.sid_key(&key("y")).unwrap());
    for sid in ["x", "y"] {
        s.insert_displacing(key(sid), "sub-a", Some(acme), alice, sa, at)
            .await
            .unwrap();
    }
    assert_eq!(indexed(&s, &sa).await, vec![x.clone(), y.clone()]);

    s.insert_displacing(key("x"), "sub-b", Some(acme), bob, sb, at)
        .await
        .unwrap();
    assert_eq!(indexed(&s, &sa).await, vec![y], "the displaced key left");
    assert_eq!(indexed(&s, &sb).await, vec![x]);

    s.remove_if_session(&key("y"), &sa).await.unwrap();
    assert!(indexed(&s, &sa).await.is_empty(), "the removed key left");
}
