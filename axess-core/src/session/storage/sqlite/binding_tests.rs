//! Real-SQLite tests for id binding and `cycle` ordering.

use super::*;
use crate::session::crypto::{BoundFormat, SessionCrypto};
use crate::session::data::SessionData;
use axess_rng::SystemRng;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sqlx::sqlite::SqlitePoolOptions;

const KEY: [u8; 32] = [3u8; 32];

async fn store() -> SqliteSessionStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteSessionStore::new(pool, SessionCrypto::new(KEY));
    store.init_schema().await.unwrap();
    store
}

fn admin() -> SessionData {
    SessionData {
        custom: serde_json::json!({"role": "admin"}),
        ..SessionData::default()
    }
}

async fn raw(store: &SqliteSessionStore, id: &SessionId) -> Vec<u8> {
    sqlx::query_scalar("SELECT data_bin FROM sessions WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn data_copied_into_another_sessions_row_does_not_load() {
    let store = store().await;
    let (admin_id, attacker_id) = (SessionId::new(&SystemRng), SessionId::new(&SystemRng));
    let ttl = Duration::from_secs(60);
    store.save(&admin_id, &admin(), ttl).await.unwrap();
    store
        .save(&attacker_id, &SessionData::default(), ttl)
        .await
        .unwrap();

    let stolen = raw(&store, &admin_id).await;
    sqlx::query("UPDATE sessions SET data_bin = ?1 WHERE id = ?2")
        .bind(stolen)
        .bind(attacker_id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();

    assert!(store.load(&attacker_id).await.is_err());
    assert!(store.load(&admin_id).await.unwrap().is_some());
}

#[tokio::test]
async fn legacy_row_loads_and_is_resealed_on_save() {
    let store = store().await;
    let id = SessionId::new(&SystemRng);
    let legacy = BASE64.encode(
        SessionCrypto::new(KEY)
            .encrypt_unbound(&rmp_serde::to_vec_named(&admin()).unwrap())
            .unwrap(),
    );
    sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?1, ?2, ?3)")
        .bind(id.to_string())
        .bind(&legacy)
        .bind(i64::MAX)
        .execute(&store.pool)
        .await
        .unwrap();

    let loaded = store.load(&id).await.unwrap().expect("legacy row loads");
    assert_eq!(loaded.custom, admin().custom);

    store
        .save(&id, &loaded, Duration::from_secs(60))
        .await
        .unwrap();
    let after = raw(&store, &id).await;
    assert!(BoundFormat::SESSION.marks(&after), "save re-encrypts");
    assert!(store.load(&id).await.unwrap().is_some());
}

#[tokio::test]
async fn cycle_is_idempotent_when_the_new_row_already_exists() {
    let store = store().await;
    let (old, new) = (SessionId::new(&SystemRng), SessionId::new(&SystemRng));
    let ttl = Duration::from_secs(60);
    store.save(&old, &admin(), ttl).await.unwrap();
    // A retried rotation: the new row is already there.
    store
        .save(&new, &SessionData::default(), ttl)
        .await
        .unwrap();

    store.cycle(&old, &new, &admin(), ttl).await.unwrap();

    assert!(store.load(&old).await.unwrap().is_none());
    let rotated = store.load(&new).await.unwrap().expect("new row present");
    assert_eq!(rotated.custom, admin().custom);
}

#[tokio::test]
async fn cycle_to_the_same_id_keeps_the_session() {
    let store = store().await;
    let id = SessionId::new(&SystemRng);
    let ttl = Duration::from_secs(60);
    store.save(&id, &admin(), ttl).await.unwrap();
    store.cycle(&id, &id, &admin(), ttl).await.unwrap();
    assert!(store.load(&id).await.unwrap().is_some());
}

#[tokio::test]
async fn failed_insert_leaves_the_old_session_in_place() {
    let store = store().await;
    let (old, new) = (SessionId::new(&SystemRng), SessionId::new(&SystemRng));
    let ttl = Duration::from_secs(60);
    store.save(&old, &admin(), ttl).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER refuse BEFORE INSERT ON sessions WHEN NEW.id = '{new}' \
         BEGIN SELECT RAISE(ABORT, 'refused'); END"
    )))
    .execute(&store.pool)
    .await
    .unwrap();

    assert!(store.cycle(&old, &new, &admin(), ttl).await.is_err());
    assert!(store.load(&old).await.unwrap().is_some());
    assert!(store.load(&new).await.unwrap().is_none());
}
