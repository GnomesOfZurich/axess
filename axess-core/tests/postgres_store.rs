//! PostgresSessionStore integration tests.
//!
//! These tests require a running PostgreSQL instance. Set `POSTGRES_URL` to
//! the connection string (e.g. `postgres://postgres:postgres@localhost:5432/postgres`).
//!
//! Run with: `cargo test -p axess-core --features postgres,testing --test postgres_store -- --ignored`

#![cfg(all(feature = "postgres", feature = "testing"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::{
    PostgresSessionStore,
    session::{
        data::SessionData,
        id::{SessionId, SessionKey},
        store::{CycleOutcome, SessionStore},
    },
};
use axess_rng::SystemRng;
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;

/// A store on the server `POSTGRES_URL` names, with an empty `sessions`
/// table. These tests run only with `--ignored`, on purpose: a missing URL
/// or an unreachable server fails the test, it never skips it.
async fn make_store(clock: &MockClock) -> PostgresSessionStore {
    let url = std::env::var("POSTGRES_URL").unwrap_or_else(|_| {
        panic!(
            "POSTGRES_URL is not set: these tests need a live server and run only with --ignored"
        )
    });
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .unwrap_or_else(|e| panic!("POSTGRES_URL is set but the server is unreachable: {e}"));
    let store =
        PostgresSessionStore::plaintext_insecure(pool.clone()).with_clock(Arc::new(clock.clone()));

    // init_schema is idempotent (IF NOT EXISTS). Run it every time
    // so tests work regardless of execution order.
    store.init_schema().await.unwrap();

    // Clean up any leftover sessions from previous tests.
    sqlx::query("DELETE FROM sessions")
        .execute(&pool)
        .await
        .unwrap();

    store
}

/// `make_store` with the clock handed back, so a TTL-boundary test
/// advances time itself.
async fn make_store_with_mock_clock() -> (PostgresSessionStore, Arc<MockClock>) {
    let clock = common::test_clock();
    let store = make_store(&clock).await;
    (store, Arc::new(clock))
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn save_and_load_roundtrip() {
    let clock = common::test_clock();
    let store = make_store(&clock).await;
    let rng = SystemRng;
    let id = SessionKey::of(&SessionId::new(&rng));
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
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn load_nonexistent_returns_none() {
    let clock = common::test_clock();
    let store = make_store(&clock).await;
    let rng = SystemRng;
    let id = SessionKey::of(&SessionId::new(&rng));
    let loaded = store.load(&id).await.unwrap();
    assert!(loaded.is_none());
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn delete_removes_session() {
    let clock = common::test_clock();
    let store = make_store(&clock).await;
    let rng = SystemRng;
    let id = SessionKey::of(&SessionId::new(&rng));
    let data = SessionData::default();

    store
        .save(&id, &data, Duration::from_secs(60))
        .await
        .unwrap();
    store.delete(&id).await.unwrap();
    assert!(store.load(&id).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn delete_nonexistent_is_idempotent() {
    let clock = common::test_clock();
    let store = make_store(&clock).await;
    let rng = SystemRng;
    let id = SessionKey::of(&SessionId::new(&rng));
    store.delete(&id).await.unwrap();
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn cycle_replaces_old_with_new() {
    let clock = common::test_clock();
    let store = make_store(&clock).await;
    let rng = SystemRng;
    let old_id = SessionKey::of(&SessionId::new(&rng));
    let data = SessionData::default();
    let ttl = Duration::from_secs(60);

    store.save(&old_id, &data, ttl).await.unwrap();

    let new_id = SessionKey::of(&SessionId::new(&rng));
    assert_eq!(
        store
            .cycle(&old_id, &new_id, &data, ttl, true)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    assert_ne!(old_id, new_id);
    assert!(store.load(&old_id).await.unwrap().is_none());
    assert!(store.load(&new_id).await.unwrap().is_some());
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn expired_session_not_returned() {
    let (store, clock) = make_store_with_mock_clock().await;
    let rng = SystemRng;
    let id = SessionKey::of(&SessionId::new(&rng));

    store
        .save(&id, &SessionData::default(), Duration::from_secs(10))
        .await
        .unwrap();
    clock.advance_secs(11);

    let loaded = store.load(&id).await.unwrap();
    assert!(loaded.is_none(), "session past TTL must not be returned");
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn cleanup_expired_removes_old_sessions() {
    let (store, clock) = make_store_with_mock_clock().await;
    let rng = SystemRng;

    let id_expired = SessionKey::of(&SessionId::new(&rng));
    let id_valid = SessionKey::of(&SessionId::new(&rng));
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
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn save_overwrites_existing() {
    let clock = common::test_clock();
    let store = make_store(&clock).await;
    let rng = SystemRng;
    let id = SessionKey::of(&SessionId::new(&rng));

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
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn prune_expired_trait_method_reclaims_orphans() {
    let (store, clock) = make_store_with_mock_clock().await;
    let rng = SystemRng;

    let id_expired = SessionKey::of(&SessionId::new(&rng));
    let id_valid = SessionKey::of(&SessionId::new(&rng));
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
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn msgpack_roundtrip_preserves_custom_bag() {
    let clock = common::test_clock();
    let store = make_store(&clock).await;
    let rng = SystemRng;
    let id = SessionKey::of(&SessionId::new(&rng));

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

/// A session that was deleted is not brought back by `update` or by a
/// `cycle` that requires its old row; a never-stored old id still rotates
/// when the row is not required.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn an_ended_session_is_not_revived_by_update_or_cycle() {
    let clock = common::test_clock();
    let store = make_store(&clock).await;
    let rng = SystemRng;
    let data = SessionData::default();
    let ttl = Duration::from_secs(60);

    let id = SessionKey::of(&SessionId::new(&rng));
    store.save(&id, &data, ttl).await.unwrap();
    assert!(store.update(&id, &data, ttl).await.unwrap());
    store.delete(&id).await.unwrap();
    assert!(!store.update(&id, &data, ttl).await.unwrap());
    assert!(store.load(&id).await.unwrap().is_none());

    let (old, new) = (
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
    );
    store.save(&old, &data, ttl).await.unwrap();
    store.delete(&old).await.unwrap();
    assert_eq!(
        store.cycle(&old, &new, &data, ttl, true).await.unwrap(),
        CycleOutcome::SessionGone
    );
    assert!(store.load(&new).await.unwrap().is_none());

    let (fresh_old, fresh_new) = (
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
    );
    assert_eq!(
        store
            .cycle(&fresh_old, &fresh_new, &data, ttl, false)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    assert!(store.load(&fresh_new).await.unwrap().is_some());
}

#[cfg(feature = "testing")]
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[serial]
async fn update_if_revision_keeps_the_contract() {
    let clock = common::test_clock();
    let store = make_store(&clock).await;
    axess_core::testing::store_contract::assert_update_if_revision_contract(&store).await;
}
