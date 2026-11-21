//! What the SQLite store holds for a session: its key in the `id` column,
//! and the session id in no column at all.

use super::*;
use crate::session::crypto::SessionCrypto;
use crate::session::data::SessionData;
use crate::session::id::{SessionId, SessionKey};
use axess_rng::SystemRng;
use sqlx::sqlite::SqlitePoolOptions;

const TTL: Duration = Duration::from_secs(60);

async fn pool() -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

/// A plaintext store and a sealed one, each on a database of its own.
async fn stores() -> [SqliteSessionStore; 2] {
    let plain = SqliteSessionStore::plaintext_insecure(pool().await);
    let sealed = SqliteSessionStore::new(
        pool().await,
        SessionCrypto::new(crate::testing::test_key(4)),
    );
    for store in [&plain, &sealed] {
        store.init_schema().await.unwrap();
    }
    [plain, sealed]
}

fn session() -> SessionData {
    SessionData {
        revision: 1,
        custom: serde_json::json!({"role": "admin"}),
        ..SessionData::default()
    }
}

/// Every row, every column: the name, the text column and the binary one.
async fn rows(store: &SqliteSessionStore) -> Vec<(String, String, Option<Vec<u8>>)> {
    sqlx::query_as("SELECT id, data, data_bin FROM sessions ORDER BY id")
        .fetch_all(&store.pool)
        .await
        .unwrap()
}

async fn row_names(store: &SqliteSessionStore) -> Vec<String> {
    rows(store).await.into_iter().map(|row| row.0).collect()
}

/// No column of any row holds `id`: not its hyphenated text, not its 32
/// hexadecimal digits, not its 16 bytes.
async fn assert_holds_no_id(store: &SqliteSessionStore, id: &SessionId) {
    let forms = [
        id.to_string().into_bytes(),
        id.as_uuid().simple().to_string().into_bytes(),
        id.as_bytes().to_vec(),
    ];
    for (name, text, binary) in rows(store).await {
        for column in [
            name.as_bytes(),
            text.as_bytes(),
            binary.as_deref().unwrap_or_default(),
        ] {
            for form in &forms {
                assert!(
                    !column.windows(form.len()).any(|window| window == form),
                    "a column holds the session id"
                );
            }
        }
    }
}

#[tokio::test]
async fn the_row_is_named_by_the_key() {
    for store in stores().await {
        let id = SessionId::new(&SystemRng);
        let key = SessionKey::of(&id);
        store.save(&key, &session(), TTL).await.unwrap();

        let stored = row_names(&store).await;
        assert_eq!(stored, [key.to_string()]);
        assert_eq!(stored[0].len(), 64);
        assert!(
            stored[0]
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        );
        assert_holds_no_id(&store, &id).await;

        // Every later write of the session leaves it under the same name.
        assert!(store.update(&key, &session(), TTL).await.unwrap());
        let next = SessionData {
            revision: 2,
            ..session()
        };
        assert_eq!(
            store.update_if_revision(&key, 1, &next, TTL).await.unwrap(),
            ConditionalUpdate::Written
        );
        assert_eq!(row_names(&store).await, [key.to_string()]);
        assert_holds_no_id(&store, &id).await;
        assert_eq!(store.load(&key).await.unwrap().unwrap().revision, 2);
    }
}

#[tokio::test]
async fn a_rotation_names_both_rows_by_their_keys() {
    for store in stores().await {
        let ids = [
            SessionId::new(&SystemRng),
            SessionId::new(&SystemRng),
            SessionId::new(&SystemRng),
        ];
        let [first, second, third] = ids.map(|id| SessionKey::of(&id));
        store.save(&first, &session(), TTL).await.unwrap();

        assert_eq!(
            store
                .cycle(&first, &second, &session(), TTL, true)
                .await
                .unwrap(),
            CycleOutcome::Rotated
        );
        assert_eq!(row_names(&store).await, [second.to_string()]);

        assert_eq!(
            store
                .cycle_if_revision(&second, &third, &session(), TTL, true, 1)
                .await
                .unwrap(),
            CycleOutcome::Rotated
        );
        assert_eq!(row_names(&store).await, [third.to_string()]);
        for id in &ids {
            assert_holds_no_id(&store, id).await;
        }

        // The zero-ttl form removes the rows under both keys, and no other.
        store.save(&first, &session(), TTL).await.unwrap();
        store.save(&second, &session(), TTL).await.unwrap();
        assert_eq!(
            store
                .cycle(&third, &first, &session(), Duration::ZERO, true)
                .await
                .unwrap(),
            CycleOutcome::SessionGone
        );
        assert_eq!(row_names(&store).await, [second.to_string()]);
    }
}

/// A row an earlier release stored under the session id itself is not the
/// session's row: it does not load under the id's key, and the documented
/// statement removes it and leaves the rows of this release.
#[tokio::test]
async fn a_row_under_a_session_id_is_not_read_and_one_statement_removes_it() {
    let [store, _] = stores().await;
    let id = SessionId::new(&SystemRng);
    let key = SessionKey::of(&id);
    // What such a row holds does not matter to the lookup; a plaintext
    // store would read this one if it found it.
    let blob = rmp_serde::to_vec_named(&session()).unwrap();
    for name in [id.to_string(), id.as_uuid().simple().to_string()] {
        sqlx::query(
            "INSERT INTO sessions (id, data, data_bin, expires_at) VALUES (?1, '', ?2, ?3)",
        )
        .bind(name)
        .bind(&blob)
        .bind(i64::MAX)
        .execute(&store.pool)
        .await
        .unwrap();
    }
    assert!(store.load(&key).await.unwrap().is_none());
    assert!(!store.update(&key, &session(), TTL).await.unwrap());

    store.save(&key, &session(), TTL).await.unwrap();
    assert_eq!(row_names(&store).await.len(), 3);
    let removed = sqlx::query("DELETE FROM sessions WHERE length(id) <> 64")
        .execute(&store.pool)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(removed, 2);
    assert_eq!(row_names(&store).await, [key.to_string()]);
    assert!(store.load(&key).await.unwrap().is_some());
}

/// The sealed store writes the second session format: its blob starts with
/// the marker `41 58 53 82`. A plaintext store writes the session as
/// MessagePack, with no marker.
#[tokio::test]
async fn a_sealed_row_starts_with_the_second_format_marker() {
    let [plain, sealed] = stores().await;
    let key = SessionKey::of(&SessionId::new(&SystemRng));
    for store in [&plain, &sealed] {
        store.save(&key, &session(), TTL).await.unwrap();
    }
    let blob = rows(&sealed).await.remove(0).2.expect("the binary column");
    assert_eq!(blob[..4], [0x41, 0x58, 0x53, 0x82]);
    let unsealed = rows(&plain).await.remove(0).2.expect("the binary column");
    assert_eq!(unsealed, rmp_serde::to_vec_named(&session()).unwrap());
}
