//! The Valkey `sid` store and replay log against a live server, ignored by
//! default: `VALKEY_URL=redis://127.0.0.1:6390 cargo test -p axess-core
//! --features testing,oauth,jwt-aws-lc,valkey -- --ignored valkey_logout`.

use super::*;
use crate::testing::mock_random::MockRng;

fn unique(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("axo_logout_{tag}_{nanos}")
}

async fn client() -> Client {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = Client::new(Config::from_url(&url).expect("url"), None, None, None);
    client.init().await.expect("connect");
    client
}

async fn store(tag: &str) -> ValkeySidStore {
    ValkeySidStore::new(client().await).with_prefix(unique(tag))
}

const ISS: &str = "https://idp.example.com";

fn key(sid: &str) -> SidKey {
    (ISS.to_string(), sid.to_string())
}

fn ids() -> (UserId, UserId, SessionId, SessionId, TenantId, TenantId) {
    let rng = MockRng::new(41);
    (
        axess_identity::testing::user("alice"),
        axess_identity::testing::user("bob"),
        SessionId::new(&rng),
        SessionId::new(&rng),
        axess_identity::testing::tenant("acme"),
        axess_identity::testing::tenant("beta"),
    )
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_a_mapping_is_found_only_in_its_tenants_scope() {
    let s = store("scope").await;
    let (alice, _, sa, _, acme, beta) = ids();
    let at = chrono::Utc::now();
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
    let at = chrono::Utc::now();
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
    let at = chrono::Utc::now();
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
    let at = chrono::Utc::now();
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
    let log = ValkeyReplayLog::new(client().await).with_prefix(unique("jti"));
    let now = chrono::Utc::now();
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
