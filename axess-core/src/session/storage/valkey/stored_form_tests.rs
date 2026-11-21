//! What the Valkey store holds for a session, against a live server
//! (ignored by default, `VALKEY_URL`): the session's key in the key name,
//! and the session id in no key name and no value. Every test works under a
//! prefix of its own and removes what it wrote, also when it fails.

use super::store::ValkeySessionStore;
use super::watch_tests::connect;
use crate::session::data::SessionData;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{ConditionalUpdate, CycleOutcome, SessionStore};
use crate::testing::valkey_sweep::KeySweep;
use axess_rng::SystemRng;
use fred::prelude::*;
use fred::types::{ClusterHash, CustomCommand};
use std::time::Duration;

const TTL: Duration = Duration::from_secs(60);

/// The sweep that removes a test's keys when it ends, also when it fails.
fn sweep() -> KeySweep {
    crate::testing::valkey_sweep::on_node("form")
}

/// A plaintext store and a sealed one, each under a prefix of its own
/// inside `sweep`'s.
fn stores(client: &Client, sweep: &KeySweep) -> [(ValkeySessionStore, String); 2] {
    let (plain, sealed) = (
        format!("{}_plain", sweep.prefix()),
        format!("{}_sealed", sweep.prefix()),
    );
    [
        (
            ValkeySessionStore::plaintext_insecure(client.clone()).with_prefix(plain.clone()),
            plain,
        ),
        (
            ValkeySessionStore::encrypted(client.clone(), crate::testing::test_key(6))
                .with_prefix(sealed.clone()),
            sealed,
        ),
    ]
}

fn session(revision: u64) -> SessionData {
    SessionData {
        revision,
        custom: serde_json::json!({"role": "admin"}),
        ..SessionData::default()
    }
}

/// Every key name under `prefix`, by `SCAN`, in byte order.
async fn key_names(client: &Client, prefix: &str) -> Vec<String> {
    let pattern = format!("{prefix}:*");
    let mut cursor = "0".to_string();
    let mut found = Vec::new();
    loop {
        let (next, mut page): (String, Vec<String>) = client
            .custom(
                CustomCommand::new_static("SCAN", ClusterHash::FirstKey, false),
                vec![cursor.as_str(), "MATCH", pattern.as_str(), "COUNT", "1000"],
            )
            .await
            .expect("SCAN");
        found.append(&mut page);
        if next == "0" {
            break;
        }
        cursor = next;
    }
    found.sort();
    found
}

/// Neither a key name under `prefix` nor the value under it holds `id`: not
/// its hyphenated text, not its 32 hexadecimal digits, not its 16 bytes.
async fn assert_holds_no_id(client: &Client, prefix: &str, id: &SessionId) {
    let forms = [
        id.to_string().into_bytes(),
        id.as_uuid().simple().to_string().into_bytes(),
        id.as_bytes().to_vec(),
    ];
    for name in key_names(client, prefix).await {
        let value: Vec<u8> = client.get(&name).await.expect("GET");
        for held in [name.as_bytes(), value.as_slice()] {
            for form in &forms {
                assert!(
                    !held.windows(form.len()).any(|window| window == form),
                    "a key name or a value holds the session id"
                );
            }
        }
    }
}

async fn remove_all(client: &Client, prefix: &str) {
    for name in key_names(client, prefix).await {
        client.del::<(), _>(name).await.expect("DEL");
    }
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn the_key_name_holds_the_sessions_key() {
    let client = connect().await;
    let sweep = sweep();
    for (store, prefix) in stores(&client, &sweep) {
        let id = SessionId::new(&SystemRng);
        let key = SessionKey::of(&id);
        store.save(&key, &session(1), TTL).await.unwrap();

        let expected = [format!("{prefix}:sess:{key}")];
        assert_eq!(key_names(&client, &prefix).await, expected);
        assert_eq!(expected[0].len(), prefix.len() + ":sess:".len() + 64);
        assert_holds_no_id(&client, &prefix, &id).await;

        // Every later write of the session leaves it under the same name.
        assert!(store.update(&key, &session(1), TTL).await.unwrap());
        assert_eq!(
            store
                .update_if_revision(&key, 1, &session(2), TTL)
                .await
                .unwrap(),
            ConditionalUpdate::Written
        );
        assert_eq!(key_names(&client, &prefix).await, expected);
        assert_holds_no_id(&client, &prefix, &id).await;
        assert_eq!(store.load(&key).await.unwrap().unwrap().revision, 2);
        remove_all(&client, &prefix).await;
    }
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_rotation_names_both_keys_by_the_sessions_keys() {
    let client = connect().await;
    let sweep = sweep();
    for (store, prefix) in stores(&client, &sweep) {
        let ids = [
            SessionId::new(&SystemRng),
            SessionId::new(&SystemRng),
            SessionId::new(&SystemRng),
        ];
        let [first, second, third] = ids.map(|id| SessionKey::of(&id));
        let name = |key: &SessionKey| format!("{prefix}:sess:{key}");
        store.save(&first, &session(1), TTL).await.unwrap();

        assert_eq!(
            store
                .cycle(&first, &second, &session(1), TTL, true)
                .await
                .unwrap(),
            CycleOutcome::Rotated
        );
        assert_eq!(key_names(&client, &prefix).await, [name(&second)]);

        assert_eq!(
            store
                .cycle_if_revision(&second, &third, &session(1), TTL, true, 1)
                .await
                .unwrap(),
            CycleOutcome::Rotated
        );
        assert_eq!(key_names(&client, &prefix).await, [name(&third)]);
        for id in &ids {
            assert_holds_no_id(&client, &prefix, id).await;
        }

        // The zero-ttl form removes both keys, and no other.
        store.save(&first, &session(1), TTL).await.unwrap();
        store.save(&second, &session(1), TTL).await.unwrap();
        assert_eq!(
            store
                .cycle(&third, &first, &session(1), Duration::ZERO, true)
                .await
                .unwrap(),
            CycleOutcome::SessionGone
        );
        assert_eq!(key_names(&client, &prefix).await, [name(&second)]);
        remove_all(&client, &prefix).await;
    }
}

/// A value copied under another session's key is not that session: the
/// sealed value is bound to the key it was written under.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_value_copied_under_another_key_does_not_load() {
    let client = connect().await;
    let sweep = sweep();
    let [_, (store, prefix)] = stores(&client, &sweep);
    let (admin, attacker) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    store.save(&admin, &session(1), TTL).await.unwrap();
    store
        .save(&attacker, &SessionData::default(), TTL)
        .await
        .unwrap();

    let stolen: Vec<u8> = client
        .get(format!("{prefix}:sess:{admin}"))
        .await
        .expect("GET");
    client
        .set::<(), _, _>(
            format!("{prefix}:sess:{attacker}"),
            stolen,
            Some(Expiration::EX(60)),
            None,
            false,
        )
        .await
        .expect("SET");

    assert!(store.load(&attacker).await.is_err());
    assert!(store.load(&admin).await.unwrap().is_some());
    remove_all(&client, &prefix).await;
}

/// A key an earlier release wrote under the session id itself is not the
/// session's: it does not load under the id's key. Such keys are the ones
/// whose last part is not 64 characters long.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_key_under_a_session_id_is_not_read() {
    let client = connect().await;
    let sweep = sweep();
    let [(store, prefix), _] = stores(&client, &sweep);
    let id = SessionId::new(&SystemRng);
    let key = SessionKey::of(&id);
    // What such a key holds does not matter to the lookup; a plaintext
    // store would read this value if it found it.
    let blob = rmp_serde::to_vec_named(&session(1)).unwrap();
    client
        .set::<(), _, _>(
            format!("{prefix}:sess:{id}"),
            blob,
            Some(Expiration::EX(60)),
            None,
            false,
        )
        .await
        .expect("SET");
    assert!(store.load(&key).await.unwrap().is_none());
    assert!(!store.update(&key, &session(1), TTL).await.unwrap());

    store.save(&key, &session(1), TTL).await.unwrap();
    let left_by_an_earlier_release: Vec<String> = key_names(&client, &prefix)
        .await
        .into_iter()
        .filter(|name| name.rsplit(':').next().is_some_and(|last| last.len() != 64))
        .collect();
    assert_eq!(left_by_an_earlier_release, [format!("{prefix}:sess:{id}")]);
    remove_all(&client, &prefix).await;
}
