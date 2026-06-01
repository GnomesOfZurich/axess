//! SqliteSessionStore tests using in-memory SQLite.
//!
//! Run with: `cargo test -p axess-core --features sqlite --test sqlite_store`

#![cfg(feature = "sqlite")]

use axess_clock::testing::MockClock;
use axess_core::{
    SqliteSessionStore,
    session::{crypto::SessionCrypto, data::SessionData, id::SessionId, store::SessionStore},
};
use axess_identity::{TenantId, UserId};
use axess_rng::SystemRng;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use std::time::Duration;

async fn make_store() -> SqliteSessionStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteSessionStore::plaintext(pool);
    store.init_schema().await.unwrap();
    store
}

/// Build a store with an injected [`MockClock`] so TTL-boundary tests
/// advance time deterministically instead of `tokio::time::sleep`-ing.
/// Returns the store + the shared clock handle (caller advances via
/// `clock.advance_secs(...)` or `clock.set(...)`).
async fn make_store_with_mock_clock() -> (SqliteSessionStore, Arc<MockClock>) {
    let clock = Arc::new(MockClock::at(chrono::Utc::now()));
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteSessionStore::plaintext(pool).with_clock(clock.clone());
    store.init_schema().await.unwrap();
    (store, clock)
}

/// Encrypted store with the supplied current + optional previous key.
/// Mirrors the production shape from `examples/sqlite/src/web/app.rs`
/// (current encryption key + a rotation-window previous key).
async fn make_encrypted_store(key: [u8; 32], previous: Option<[u8; 32]>) -> SqliteSessionStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut crypto = SessionCrypto::new(key);
    if let Some(prev) = previous {
        crypto = crypto.with_previous_key(prev);
    }
    let store = SqliteSessionStore::new(pool, crypto);
    store.init_schema().await.unwrap();
    store
}

/// Build an encrypted store on an EXISTING pool; needed for the
/// key-rotation + wrong-key tests, where one store writes a row and
/// a second store with different crypto reads (or fails to read) the
/// same row.
async fn make_encrypted_store_on_pool(
    pool: sqlx::SqlitePool,
    key: [u8; 32],
    previous: Option<[u8; 32]>,
) -> SqliteSessionStore {
    let mut crypto = SessionCrypto::new(key);
    if let Some(prev) = previous {
        crypto = crypto.with_previous_key(prev);
    }
    let store = SqliteSessionStore::new(pool, crypto);
    store.init_schema().await.unwrap();
    store
}

async fn fresh_pool() -> sqlx::SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

#[tokio::test]
async fn save_and_load_roundtrip() {
    let store = make_store().await;
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
async fn load_nonexistent_returns_none() {
    let store = make_store().await;
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let loaded = store.load(&id).await.unwrap();
    assert!(loaded.is_none());
}

#[tokio::test]
async fn delete_removes_session() {
    let store = make_store().await;
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
async fn delete_nonexistent_is_idempotent() {
    let store = make_store().await;
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    // Should not error.
    store.delete(&id).await.unwrap();
}

#[tokio::test]
async fn cycle_replaces_old_with_new() {
    let store = make_store().await;
    let rng = SystemRng;
    let id_old = SessionId::new(&rng);
    let data = SessionData::default();
    let ttl = Duration::from_secs(60);

    store.save(&id_old, &data, ttl).await.unwrap();

    let id_new = SessionId::new(&rng);
    store.cycle(&id_old, &id_new, &data, ttl).await.unwrap();
    assert_ne!(id_old, id_new);
    assert!(store.load(&id_old).await.unwrap().is_none());
    assert!(store.load(&id_new).await.unwrap().is_some());
}

#[tokio::test]
async fn expired_session_not_returned() {
    // DST shape: save with a finite TTL, then advance the injected
    // clock past `expires_at`. The store's `load` query is
    // `WHERE expires_at > ?1` where `?1 = self.clock.now().timestamp()`,
    // so once `now > expires_at` the row stops being returned.
    let (store, clock) = make_store_with_mock_clock().await;
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
async fn cleanup_expired_removes_old_sessions() {
    // Save one short-TTL + one long-TTL row, advance the injected
    // clock past the short TTL, sweep. Only the short-TTL row should
    // be reaped.
    let (store, clock) = make_store_with_mock_clock().await;
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

/// The trait-surface `prune_expired` must reclaim the same
/// rows as the inherent `cleanup_expired` (it delegates).
#[tokio::test]
async fn prune_expired_trait_method_reclaims_orphans() {
    let (store, clock) = make_store_with_mock_clock().await;
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
    // Drive via the trait-surface so an application holding the
    // store generically (e.g. through an ops-endpoint dispatcher)
    // can reclaim cycle-orphans without downcasting.
    let pruned = SessionStore::prune_expired(&store).await.unwrap();
    assert_eq!(
        pruned, 1,
        "trait-surface prune_expired should reclaim the expired row"
    );
    assert!(store.load(&id_valid).await.unwrap().is_some());
}

/// `cleanup_expired` must return the actual rows-deleted
/// count, not a hard-coded `1`. With zero expired rows present, the
/// call must return `0`. Pins both `cleanup_expired -> Ok(1)` and
/// the `prune_expired` delegate against `Ok(1)`-replacement
/// mutations.
#[tokio::test]
async fn cleanup_expired_returns_zero_when_no_rows_expired() {
    let store = make_store().await;
    let rng = SystemRng;

    let id_valid = SessionId::new(&rng);
    let data = SessionData::default();
    store
        .save(&id_valid, &data, Duration::from_secs(3600))
        .await
        .unwrap();

    let removed = store.cleanup_expired().await.unwrap();
    assert_eq!(
        removed, 0,
        "no expired rows must yield zero removed (got {removed})"
    );

    let pruned = SessionStore::prune_expired(&store).await.unwrap();
    assert_eq!(
        pruned, 0,
        "prune_expired delegate must propagate the zero count"
    );
}

/// when MORE than one row is expired, the count must be
/// the actual number of deletions; not a hard-coded `1`.
#[tokio::test]
async fn cleanup_expired_returns_actual_count_when_many() {
    let (store, clock) = make_store_with_mock_clock().await;
    let rng = SystemRng;

    let data = SessionData::default();
    for _ in 0..3 {
        let id = SessionId::new(&rng);
        store
            .save(&id, &data, Duration::from_secs(10))
            .await
            .unwrap();
    }

    clock.advance_secs(11);
    let removed = store.cleanup_expired().await.unwrap();
    assert_eq!(
        removed, 3,
        "cleanup_expired must return actual deleted row count, not Ok(1)"
    );
}

/// SQL writes round-trip through the new MessagePack codec.
/// Regression: a `SessionData` with a populated `custom` bag must
/// survive `save → load` byte-perfect. Catches any backend that fell
/// back to the legacy JSON serialisation but kept the new decoder
/// (which would still parse the wire form successfully).
#[tokio::test]
async fn msgpack_roundtrip_preserves_custom_bag() {
    let store = make_store().await;
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

#[tokio::test]
async fn save_overwrites_existing() {
    let store = make_store().await;
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

// ── SessionCrypto path ──────────────────────────────────────────────
//
// Production wires `SqliteSessionStore::new(pool, SessionCrypto::new(key))`.
// The plaintext tests above don't exercise the AES-256-GCM envelope,
// nonce, or key-rotation logic. The four tests below pin the
// crypto-path invariants a regression would silently break.

/// Encrypted round-trip: `save` writes ciphertext, `load` decrypts
/// back to identical plaintext. Catches a backend that bypassed the
/// codec or stripped the encryption call entirely.
#[tokio::test]
async fn encrypted_roundtrip_preserves_custom_bag() {
    let key = [7u8; 32];
    let store = make_encrypted_store(key, None).await;
    let rng = SystemRng;
    let id = SessionId::new(&rng);

    let data = SessionData {
        custom: serde_json::json!({
            "axess.oauth.csrf_state": "xyz123",
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

/// Key rotation: write with key A as the current key, then mount the
/// same pool with key B current + key A previous. Old rows must
/// decrypt via the previous-key path; new writes use the current key
/// (verified by a follow-up read after re-saving).
#[tokio::test]
async fn key_rotation_reads_old_writes_new() {
    let key_a = [1u8; 32];
    let key_b = [2u8; 32];
    let pool = fresh_pool().await;

    // Phase 1: current = A, no previous.
    let store_a = make_encrypted_store_on_pool(pool.clone(), key_a, None).await;
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let data = SessionData {
        fingerprint: Some("rotation-test".to_string()),
        ..SessionData::default()
    };
    store_a
        .save(&id, &data, Duration::from_secs(60))
        .await
        .unwrap();

    // Phase 2: rotate. Current = B, previous = A.
    let store_b = make_encrypted_store_on_pool(pool.clone(), key_b, Some(key_a)).await;
    let loaded = store_b
        .load(&id)
        .await
        .unwrap()
        .expect("previous-key path must decrypt the A-encrypted row");
    assert_eq!(loaded.fingerprint.as_deref(), Some("rotation-test"));

    // Re-save under B; old previous-key path no longer needed for
    // this row.
    let data2 = SessionData {
        fingerprint: Some("post-rotation".to_string()),
        ..SessionData::default()
    };
    store_b
        .save(&id, &data2, Duration::from_secs(60))
        .await
        .unwrap();

    // Phase 3: drop the previous key. Row must now decrypt under B alone.
    let store_b_only = make_encrypted_store_on_pool(pool.clone(), key_b, None).await;
    let loaded = store_b_only
        .load(&id)
        .await
        .unwrap()
        .expect("re-saved row must decrypt under current key alone");
    assert_eq!(loaded.fingerprint.as_deref(), Some("post-rotation"));
}

/// Wrong key cannot decrypt. Save under key A; load via a store
/// built with key B (no previous-key fallback). Must surface as an
/// error, not silently return `None` (which would mask a key
/// misconfiguration on a fleet rotation).
#[tokio::test]
async fn wrong_key_fails_to_decrypt() {
    let key_a = [10u8; 32];
    let key_b = [11u8; 32];
    let pool = fresh_pool().await;

    let store_a = make_encrypted_store_on_pool(pool.clone(), key_a, None).await;
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    store_a
        .save(&id, &SessionData::default(), Duration::from_secs(60))
        .await
        .unwrap();

    let store_b = make_encrypted_store_on_pool(pool.clone(), key_b, None).await;
    let outcome = store_b.load(&id).await;
    assert!(
        outcome.is_err(),
        "load with wrong key must error, not silently return None (got {outcome:?})"
    );
}

/// A non-default `SessionData` (with a populated `Authenticated`
/// auth_state, fingerprint, custom bag) must survive `save → load`
/// byte-perfect. Every prior round-trip test uses
/// `SessionData::default()` (= `Guest`); any serialization bug
/// specific to populated authenticated-state fields would slip
/// through unless this shape is exercised.
#[tokio::test]
async fn authenticated_state_roundtrip_byte_perfect() {
    let store = make_store().await;
    let rng = SystemRng;
    let id = SessionId::new(&rng);

    let user_id = UserId::from_bytes([2u8; 16]);
    let tenant_id = TenantId::from_bytes([1u8; 16]);
    let authn_time = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let data = SessionData {
        auth_state: axess_core::session::data::AuthState::Authenticated {
            user_id,
            tenant_id,
            authn_time,
            factors_completed: Vec::new(),
        },
        fingerprint: Some("test-fingerprint".to_string()),
        custom: serde_json::json!({ "session.scope": "read+write" }),
        ..SessionData::default()
    };

    store
        .save(&id, &data, Duration::from_secs(60))
        .await
        .unwrap();
    let loaded = store.load(&id).await.unwrap().expect("loaded");

    // SessionData doesn't derive PartialEq; compare via the
    // structural pieces that matter for the round-trip pin.
    assert_eq!(
        loaded.auth_state, data.auth_state,
        "auth_state must round-trip"
    );
    assert_eq!(
        loaded.fingerprint, data.fingerprint,
        "fingerprint must round-trip"
    );
    assert_eq!(loaded.custom, data.custom, "custom bag must round-trip");
    assert_eq!(loaded.version, data.version, "version must round-trip");
}
