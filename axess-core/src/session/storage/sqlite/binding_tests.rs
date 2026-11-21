//! Real-SQLite tests for id binding and `cycle` ordering.

use super::*;
use crate::session::crypto::{BoundFormat, SessionCrypto};
use crate::session::data::SessionData;
use crate::session::id::{SessionId, SessionKey};
use axess_rng::SystemRng;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sqlx::sqlite::SqlitePoolOptions;

const KEY: [u8; 32] = crate::testing::test_key(3);

async fn store() -> SqliteSessionStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteSessionStore::new(
        pool,
        SessionCrypto::new(KEY).with_legacy_blobs(crate::session::crypto::LegacyBlobs::Accept),
    );
    store.init_schema().await.unwrap();
    store
}

fn admin() -> SessionData {
    SessionData {
        custom: serde_json::json!({"role": "admin"}),
        ..SessionData::default()
    }
}

async fn raw(store: &SqliteSessionStore, id: &SessionKey) -> Vec<u8> {
    sqlx::query_scalar("SELECT data_bin FROM sessions WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn data_copied_into_another_sessions_row_does_not_load() {
    let store = store().await;
    let (admin_id, attacker_id) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
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

/// A legacy blob in the text column of a row is not the row's session: the
/// load does not read the text column, though this store's crypto reads
/// legacy blobs with no end date, and the session's next save writes the
/// current form over it.
#[tokio::test]
async fn a_legacy_text_row_is_refused_and_the_next_save_seals_the_current_form() {
    let store = store().await;
    let id = SessionKey::of(&SessionId::new(&SystemRng));
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

    assert!(matches!(
        store.load(&id).await,
        Err(SqlStoreError::Decode(_))
    ));

    store
        .save(&id, &admin(), Duration::from_secs(60))
        .await
        .unwrap();
    let after = raw(&store, &id).await;
    assert!(
        BoundFormat::SESSION.marks(&after),
        "the save seals the current form"
    );
    assert!(store.load(&id).await.unwrap().is_some());
}

#[tokio::test]
async fn cycle_is_idempotent_when_the_new_row_already_exists() {
    let store = store().await;
    let (old, new) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    let ttl = Duration::from_secs(60);
    store.save(&old, &admin(), ttl).await.unwrap();
    // A retried rotation: the new row is already there.
    store
        .save(&new, &SessionData::default(), ttl)
        .await
        .unwrap();

    assert_eq!(
        store.cycle(&old, &new, &admin(), ttl, true).await.unwrap(),
        CycleOutcome::Rotated
    );

    assert!(store.load(&old).await.unwrap().is_none());
    let rotated = store.load(&new).await.unwrap().expect("new row present");
    assert_eq!(rotated.custom, admin().custom);
}

#[tokio::test]
async fn cycle_to_the_same_id_keeps_the_session() {
    let store = store().await;
    let id = SessionKey::of(&SessionId::new(&SystemRng));
    let ttl = Duration::from_secs(60);
    store.save(&id, &admin(), ttl).await.unwrap();
    assert_eq!(
        store.cycle(&id, &id, &admin(), ttl, true).await.unwrap(),
        CycleOutcome::Rotated
    );
    assert!(store.load(&id).await.unwrap().is_some());
}

#[tokio::test]
async fn failed_insert_leaves_the_old_session_in_place() {
    let store = store().await;
    let (old, new) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    let ttl = Duration::from_secs(60);
    store.save(&old, &admin(), ttl).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER refuse BEFORE INSERT ON sessions WHEN NEW.id = '{new}' \
         BEGIN SELECT RAISE(ABORT, 'refused'); END"
    )))
    .execute(&store.pool)
    .await
    .unwrap();

    assert!(store.cycle(&old, &new, &admin(), ttl, true).await.is_err());
    assert!(store.load(&old).await.unwrap().is_some());
    assert!(store.load(&new).await.unwrap().is_none());
}

#[tokio::test]
async fn sqlite_store_never_revives_an_ended_session() {
    crate::session::store::revival_tests::run_all(&store().await).await;
}

/// Plant a row sealed without row binding in the binary column.
async fn plant_unbound(store: &SqliteSessionStore, id: &SessionKey, expires_at: i64) -> Vec<u8> {
    let blob = SessionCrypto::new(KEY)
        .encrypt_unbound(&rmp_serde::to_vec_named(&admin()).unwrap())
        .unwrap();
    sqlx::query("INSERT INTO sessions (id, data, data_bin, expires_at) VALUES (?1, '', ?2, ?3)")
        .bind(id.to_string())
        .bind(&blob)
        .bind(expires_at)
        .execute(&store.pool)
        .await
        .unwrap();
    blob
}

async fn expiry(store: &SqliteSessionStore, id: &SessionKey) -> i64 {
    sqlx::query_scalar("SELECT expires_at FROM sessions WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

/// A row that carries no row binding is refused, though this store's crypto
/// reads legacy blobs with no end date: such a blob opens under any row, so
/// reading it as a session would let a row be moved. The refused row is left
/// as it is, and the session's next save writes the current form.
#[tokio::test]
async fn an_unbound_row_is_refused_under_a_policy_that_reads_legacy_blobs() {
    let store = store().await;
    let id = SessionKey::of(&SessionId::new(&SystemRng));
    let expires = store.clock.now().unix_seconds() + 600;
    let unbound = plant_unbound(&store, &id, expires).await;
    assert!(!BoundFormat::SESSION.marks(&unbound));

    assert!(matches!(
        store.load(&id).await,
        Err(SqlStoreError::Crypto(_))
    ));
    assert_eq!(
        raw(&store, &id).await,
        unbound,
        "the refused blob is left as it was found"
    );
    assert_eq!(expiry(&store, &id).await, expires);

    store
        .save(&id, &admin(), Duration::from_secs(60))
        .await
        .unwrap();
    assert!(BoundFormat::SESSION.marks(&raw(&store, &id).await));
    assert!(store.load(&id).await.unwrap().is_some());
}

/// A bound row that only the previous key opens is re-sealed under the
/// current key by the load that found it, and keeps its expiry.
#[tokio::test]
async fn load_reseals_a_row_sealed_under_the_previous_key_and_keeps_its_expiry() {
    let store = store().await;
    let id = SessionKey::of(&SessionId::new(&SystemRng));
    store
        .save(&id, &admin(), Duration::from_secs(600))
        .await
        .unwrap();
    let before = raw(&store, &id).await;
    let expires = expiry(&store, &id).await;

    let rotated = SqliteSessionStore::new(
        store.pool.clone(),
        SessionCrypto::new(crate::testing::test_key(4)).with_previous_key(KEY),
    );
    let loaded = rotated
        .load(&id)
        .await
        .unwrap()
        .expect("the previous key opens the row");
    assert_eq!(loaded.custom, admin().custom);
    let after = raw(&store, &id).await;
    assert_ne!(after, before, "re-sealed by the load");
    assert!(BoundFormat::SESSION.marks(&after));
    assert_eq!(expiry(&store, &id).await, expires, "the expiry is kept");
    assert!(
        SqliteSessionStore::new(
            store.pool.clone(),
            SessionCrypto::new(crate::testing::test_key(4))
        )
        .load(&id)
        .await
        .unwrap()
        .is_some(),
        "the current key alone opens the re-sealed row"
    );
}

/// A row whose binary column is NULL is not read, whatever its text column
/// holds: base64 of a blob in the current sealed form, bound to the row, is
/// refused as undecodable and left as it lies, and a conditional write that
/// meets it is refused the same way.
#[tokio::test]
async fn a_text_column_row_is_not_read() {
    let store = store().await;
    let id = SessionKey::of(&SessionId::new(&SystemRng));
    let text = BASE64.encode(store.codec.encode_bytes(&id, &admin()).unwrap());
    sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?1, ?2, ?3)")
        .bind(id.to_string())
        .bind(&text)
        .bind(i64::MAX)
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(matches!(
        store.load(&id).await,
        Err(SqlStoreError::Decode(_))
    ));
    assert!(matches!(
        store
            .update_if_revision(&id, 0, &admin(), Duration::from_secs(60))
            .await,
        Err(SqlStoreError::Decode(_))
    ));
    let columns: (Option<Vec<u8>>, String) =
        sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = ?1")
            .bind(id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(columns, (None, text), "left as it lies");
}

/// The re-seal is conditional on the bytes that were read: a save that
/// landed in between is kept.
#[tokio::test]
async fn a_reseal_never_overwrites_a_save_that_landed_meanwhile() {
    let store = store().await;
    let id = SessionKey::of(&SessionId::new(&SystemRng));
    let stale = plant_unbound(&store, &id, i64::MAX).await;
    let newer = SessionData {
        custom: serde_json::json!({"role": "newer"}),
        ..SessionData::default()
    };
    store
        .save(&id, &newer, Duration::from_secs(60))
        .await
        .unwrap();

    store
        .reseal(&id, &admin(), &stale, store.clock.now().unix_seconds())
        .await;

    let loaded = store.load(&id).await.unwrap().unwrap();
    assert_eq!(loaded.custom, newer.custom);
}

/// With legacy blobs rejected, an unbound row is refused and left as it is;
/// a bound row loads.
#[tokio::test]
async fn rejecting_legacy_blobs_refuses_an_unbound_row() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let strict = SqliteSessionStore::new(
        pool,
        SessionCrypto::new(KEY).with_legacy_blobs(crate::session::crypto::LegacyBlobs::Reject),
    );
    strict.init_schema().await.unwrap();
    let (legacy_id, bound_id) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    plant_unbound(&strict, &legacy_id, i64::MAX).await;
    strict
        .save(&bound_id, &admin(), Duration::from_secs(60))
        .await
        .unwrap();

    assert!(strict.load(&legacy_id).await.is_err());
    assert!(strict.load(&bound_id).await.unwrap().is_some());
}
