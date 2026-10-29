//! Real-SQLite tests for the binary `data_bin` column and the legacy text
//! column it replaced.

use super::*;
use crate::session::crypto::SessionCrypto;
use crate::session::data::SessionData;
use axess_rng::SystemRng;
use sqlx::sqlite::SqlitePoolOptions;

const KEY: [u8; 32] = [5u8; 32];

fn admin() -> SessionData {
    SessionData {
        custom: serde_json::json!({"role": "admin"}),
        ..SessionData::default()
    }
}

async fn pool() -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

/// The table as an earlier release created it: no `data_bin`.
async fn legacy_store() -> SqliteSessionStore {
    let pool = pool().await;
    sqlx::query(
        "CREATE TABLE sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, \
         expires_at INTEGER NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    // The documented upgrade step.
    sqlx::query("ALTER TABLE sessions ADD COLUMN data_bin BLOB")
        .execute(&pool)
        .await
        .unwrap();
    SqliteSessionStore::new(
        pool,
        SessionCrypto::new(KEY).with_legacy_blobs(crate::session::crypto::LegacyBlobs::Accept),
    )
}

async fn columns(store: &SqliteSessionStore, id: &SessionId) -> (Option<Vec<u8>>, String) {
    sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

async fn plant_legacy(store: &SqliteSessionStore, id: &SessionId) {
    let text = SessionCodec::encrypted(SessionCrypto::new(KEY))
        .encode_text(id, &admin())
        .unwrap();
    sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?1, ?2, ?3)")
        .bind(id.to_string())
        .bind(text)
        .bind(i64::MAX)
        .execute(&store.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_save_writes_bytes_and_leaves_the_text_column_empty() {
    let store = legacy_store().await;
    let id = SessionId::new(&SystemRng);
    store
        .save(&id, &admin(), Duration::from_secs(60))
        .await
        .unwrap();

    let (bin, text) = columns(&store, &id).await;
    assert_eq!(text, "", "no base64 in the TEXT column");
    let bin = bin.expect("binary column written");
    let back = SessionCodec::encrypted(SessionCrypto::new(KEY))
        .decode_bytes(&id, &bin)
        .unwrap();
    assert_eq!(back.custom, admin().custom);
    assert_eq!(
        store.load(&id).await.unwrap().unwrap().custom,
        admin().custom
    );
}

#[tokio::test]
async fn a_legacy_text_row_loads_and_the_next_save_moves_it_to_bytes() {
    let store = legacy_store().await;
    let id = SessionId::new(&SystemRng);
    plant_legacy(&store, &id).await;
    let (bin, text) = columns(&store, &id).await;
    assert!(bin.is_none() && !text.is_empty());

    let loaded = store.load(&id).await.unwrap().expect("legacy row loads");
    assert_eq!(loaded.custom, admin().custom);

    store
        .save(&id, &loaded, Duration::from_secs(60))
        .await
        .unwrap();
    let (bin, text) = columns(&store, &id).await;
    assert!(bin.is_some(), "rewritten into the binary column");
    assert_eq!(text, "", "legacy text emptied");
    assert!(store.load(&id).await.unwrap().is_some());
}

#[tokio::test]
async fn a_cycle_writes_the_new_row_as_bytes() {
    let store = legacy_store().await;
    let (old, new) = (SessionId::new(&SystemRng), SessionId::new(&SystemRng));
    plant_legacy(&store, &old).await;
    let loaded = store.load(&old).await.unwrap().unwrap();

    assert_eq!(
        store
            .cycle(&old, &new, &loaded, Duration::from_secs(60), true)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );

    let (bin, text) = columns(&store, &new).await;
    assert!(bin.is_some() && text.is_empty());
    assert!(store.load(&old).await.unwrap().is_none());
}

#[tokio::test]
async fn a_legacy_plaintext_json_row_still_loads() {
    let pool = pool().await;
    let store = SqliteSessionStore::plaintext(pool);
    store.init_schema().await.unwrap();
    let id = SessionId::new(&SystemRng);
    sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?1, ?2, ?3)")
        .bind(id.to_string())
        .bind(serde_json::to_string(&admin()).unwrap())
        .bind(i64::MAX)
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        store.load(&id).await.unwrap().unwrap().custom,
        admin().custom
    );
}
