//! PostgresSessionStore integration tests.
//!
//! These tests require a running PostgreSQL instance. Set `POSTGRES_URL` to
//! the connection string (e.g. `postgres://postgres:postgres@localhost:5432/postgres`).
//!
//! Run with: `cargo test -p axess-core --features postgres --test postgres_store -- --ignored`

#![cfg(feature = "postgres")]

use axess_clock::testing::MockClock;
use axess_core::{
    PostgresSessionStore,
    session::{data::SessionData, id::SessionId, store::SessionStore},
};
use axess_rng::SystemRng;
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;

async fn make_store() -> Option<(PostgresSessionStore, sqlx::PgPool)> {
    let url = std::env::var("POSTGRES_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .ok()?;
    let store = PostgresSessionStore::plaintext(pool.clone());

    // init_schema is idempotent (IF NOT EXISTS). Run it every time
    // so tests work regardless of execution order.
    store.init_schema().await.unwrap();

    // Clean up any leftover sessions from previous tests.
    sqlx::query("DELETE FROM sessions")
        .execute(&pool)
        .await
        .unwrap();

    Some((store, pool))
}

/// `make_store` variant that injects a [`MockClock`] so TTL-boundary
/// tests advance time deterministically instead of `tokio::time::sleep`.
/// Returns `None` when `POSTGRES_URL` is unset (same gate as
/// `make_store`).
async fn make_store_with_mock_clock() -> Option<(PostgresSessionStore, sqlx::PgPool, Arc<MockClock>)>
{
    let (store, pool) = make_store().await?;
    let clock = Arc::new(MockClock::at(chrono::Utc::now()));
    let store = store.with_clock(clock.clone());
    Some((store, pool, clock))
}

#[tokio::test]
#[ignore] // Requires POSTGRES_URL
#[serial]
async fn save_and_load_roundtrip() {
    let Some((store, _pool)) = make_store().await else {
        eprintln!("POSTGRES_URL not set, skipping");
        return;
    };
    let rng = SystemRng;
    let id = SessionId::new(&rng);
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
#[ignore]
#[serial]
async fn load_nonexistent_returns_none() {
    let Some((store, _pool)) = make_store().await else {
        return;
    };
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let loaded = store.load(&id).await.unwrap();
    assert!(loaded.is_none());
}

#[tokio::test]
#[ignore]
#[serial]
async fn delete_removes_session() {
    let Some((store, _pool)) = make_store().await else {
        return;
    };
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let data = SessionData::default();

    store
        .save(&id, &data, Duration::from_secs(60))
        .await
        .unwrap();
    store.delete(&id).await.unwrap();
    assert!(store.load(&id).await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
#[serial]
async fn delete_nonexistent_is_idempotent() {
    let Some((store, _pool)) = make_store().await else {
        return;
    };
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    store.delete(&id).await.unwrap();
}

#[tokio::test]
#[ignore]
#[serial]
async fn cycle_replaces_old_with_new() {
    let Some((store, _pool)) = make_store().await else {
        return;
    };
    let rng = SystemRng;
    let old_id = SessionId::new(&rng);
    let data = SessionData::default();
    let ttl = Duration::from_secs(60);

    store.save(&old_id, &data, ttl).await.unwrap();

    let new_id = SessionId::new(&rng);
    store.cycle(&old_id, &new_id, &data, ttl).await.unwrap();
    assert_ne!(old_id, new_id);
    assert!(store.load(&old_id).await.unwrap().is_none());
    assert!(store.load(&new_id).await.unwrap().is_some());
}

#[tokio::test]
#[ignore]
#[serial]
async fn expired_session_not_returned() {
    let Some((store, _pool, clock)) = make_store_with_mock_clock().await else {
        return;
    };
    let rng = SystemRng;
    let id = SessionId::new(&rng);

    store
        .save(&id, &SessionData::default(), Duration::from_secs(10))
        .await
        .unwrap();
    clock.advance_secs(11);

    let loaded = store.load(&id).await.unwrap();
    assert!(loaded.is_none(), "session past TTL must not be returned");
}

#[tokio::test]
#[ignore]
#[serial]
async fn cleanup_expired_removes_old_sessions() {
    let Some((store, _pool, clock)) = make_store_with_mock_clock().await else {
        return;
    };
    let rng = SystemRng;

    let id_expired = SessionId::new(&rng);
    let id_valid = SessionId::new(&rng);
    let data = SessionData::default();

    store
        .save(&id_expired, &data, Duration::from_secs(10))
        .await
        .unwrap();
    store
        .save(&id_valid, &data, Duration::from_secs(3600))
        .await
        .unwrap();

    clock.advance_secs(11);
    let deleted = store.cleanup_expired().await.unwrap();
    assert_eq!(deleted, 1);

    assert!(store.load(&id_valid).await.unwrap().is_some());
}

#[tokio::test]
#[ignore]
#[serial]
async fn save_overwrites_existing() {
    let Some((store, _pool)) = make_store().await else {
        return;
    };
    let rng = SystemRng;
    let id = SessionId::new(&rng);

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

/// Parity with `tests/sqlite_store.rs::prune_expired_trait_method_reclaims_orphans`.
/// The trait-surface `prune_expired` must reclaim the same rows as the
/// inherent `cleanup_expired` it delegates to. Application code holding
/// a `&dyn SessionStore` (e.g. an ops-endpoint dispatcher) must be able
/// to drop expired rows without downcasting to the concrete backend.
#[tokio::test]
#[ignore]
#[serial]
async fn prune_expired_trait_method_reclaims_orphans() {
    let Some((store, _pool, clock)) = make_store_with_mock_clock().await else {
        return;
    };
    let rng = SystemRng;

    let id_expired = SessionId::new(&rng);
    let id_valid = SessionId::new(&rng);
    let data = SessionData::default();

    store
        .save(&id_expired, &data, Duration::from_secs(10))
        .await
        .unwrap();
    store
        .save(&id_valid, &data, Duration::from_secs(3600))
        .await
        .unwrap();

    clock.advance_secs(11);
    let pruned = SessionStore::prune_expired(&store).await.unwrap();
    assert_eq!(
        pruned, 1,
        "trait-surface prune_expired should reclaim the expired row"
    );
    assert!(store.load(&id_valid).await.unwrap().is_some());
}

/// Parity with `tests/sqlite_store.rs::msgpack_roundtrip_preserves_custom_bag`.
/// `SessionData` with a populated `custom` bag must round-trip
/// byte-perfect through the MessagePack codec on the Postgres backend
///; same wire format as SQLite, same regression value: catches a
/// silent fall-back to the legacy JSON encoder that the new decoder
/// would still parse without complaint.
#[tokio::test]
#[ignore]
#[serial]
async fn msgpack_roundtrip_preserves_custom_bag() {
    let Some((store, _pool)) = make_store().await else {
        return;
    };
    let rng = SystemRng;
    let id = SessionId::new(&rng);

    let data = SessionData {
        custom: serde_json::json!({
            "axess.oauth.csrf_state": "xyz123",
            "axess.oauth.nonce": "n0nc3",
            "axess.oauth.pkce_verifier": "abc-def_~ghi",
            "app.user_pref": { "theme": "dark", "items": [1, 2, 3] },
        }),
        ..SessionData::default()
    };

    store
        .save(&id, &data, Duration::from_secs(60))
        .await
        .unwrap();
    let loaded = store.load(&id).await.unwrap().expect("loaded");
    assert_eq!(loaded.custom, data.custom);
}
