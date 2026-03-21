//! SqliteSessionStore tests using in-memory SQLite.
//!
//! Run with: `cargo test -p axess-core --features sqlite --test sqlite_store`

#![cfg(feature = "sqlite")]

use axess_core::{
    session::{data::SessionData, id::SessionId, store::SessionStore},
    storage::sqlite::SqliteSessionStore,
    utils::random::SystemRng,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::time::Duration;

async fn make_store() -> SqliteSessionStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteSessionStore::new(pool);
    store.init_schema().await.unwrap();
    store
}

#[tokio::test]
async fn save_and_load_roundtrip() {
    let store = make_store().await;
    let mut rng = SystemRng;
    let id = SessionId::new(&mut rng);
    let data = SessionData::default();

    store
        .save(&id, &data, Duration::from_secs(60))
        .await
        .unwrap();
    let loaded = store.load(&id).await.unwrap();
    assert!(loaded.is_some());
    assert!(loaded.unwrap().auth_state.is_guest());
}

#[tokio::test]
async fn load_nonexistent_returns_none() {
    let store = make_store().await;
    let mut rng = SystemRng;
    let id = SessionId::new(&mut rng);
    let loaded = store.load(&id).await.unwrap();
    assert!(loaded.is_none());
}

#[tokio::test]
async fn delete_removes_session() {
    let store = make_store().await;
    let mut rng = SystemRng;
    let id = SessionId::new(&mut rng);
    let data = SessionData::default();

    store
        .save(&id, &data, Duration::from_secs(60))
        .await
        .unwrap();
    store.delete(&id).await.unwrap();
    assert!(store.load(&id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_nonexistent_is_idempotent() {
    let store = make_store().await;
    let mut rng = SystemRng;
    let id = SessionId::new(&mut rng);
    // Should not error.
    store.delete(&id).await.unwrap();
}

#[tokio::test]
async fn cycle_replaces_old_with_new() {
    let store = make_store().await;
    let mut rng = SystemRng;
    let old_id = SessionId::new(&mut rng);
    let data = SessionData::default();
    let ttl = Duration::from_secs(60);

    store.save(&old_id, &data, ttl).await.unwrap();

    let new_id = store.cycle(&old_id, &data, ttl, &mut rng).await.unwrap();
    assert_ne!(old_id, new_id);
    assert!(store.load(&old_id).await.unwrap().is_none());
    assert!(store.load(&new_id).await.unwrap().is_some());
}

#[tokio::test]
async fn expired_session_not_returned() {
    let store = make_store().await;
    let mut rng = SystemRng;
    let id = SessionId::new(&mut rng);
    let data = SessionData::default();

    // Save with 0-second TTL — already expired.
    store
        .save(&id, &data, Duration::from_secs(0))
        .await
        .unwrap();

    // Should not be returned.
    // Note: SQLite stores expires_at as unix timestamp. With TTL=0, it's
    // already in the past by the time load runs.
    tokio::time::sleep(Duration::from_millis(10)).await;
    let loaded = store.load(&id).await.unwrap();
    assert!(loaded.is_none(), "expired session should not be returned");
}

#[tokio::test]
async fn cleanup_expired_removes_old_sessions() {
    let store = make_store().await;
    let mut rng = SystemRng;

    let id_expired = SessionId::new(&mut rng);
    let id_valid = SessionId::new(&mut rng);
    let data = SessionData::default();

    store
        .save(&id_expired, &data, Duration::from_secs(0))
        .await
        .unwrap();
    store
        .save(&id_valid, &data, Duration::from_secs(3600))
        .await
        .unwrap();

    // SQLite uses second-precision timestamps. Sleep past the 1-second boundary
    // so the expired session's expires_at is definitively in the past.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let deleted = store.cleanup_expired().await.unwrap();
    assert_eq!(deleted, 1);

    assert!(store.load(&id_valid).await.unwrap().is_some());
}

#[tokio::test]
async fn save_overwrites_existing() {
    let store = make_store().await;
    let mut rng = SystemRng;
    let id = SessionId::new(&mut rng);

    let data1 = SessionData {
        fingerprint: Some("first".to_string()),
        ..SessionData::default()
    };
    let data2 = SessionData {
        fingerprint: Some("second".to_string()),
        ..SessionData::default()
    };

    store
        .save(&id, &data1, Duration::from_secs(60))
        .await
        .unwrap();
    store
        .save(&id, &data2, Duration::from_secs(60))
        .await
        .unwrap();

    let loaded = store.load(&id).await.unwrap().unwrap();
    assert_eq!(loaded.fingerprint.as_deref(), Some("second"));
}
