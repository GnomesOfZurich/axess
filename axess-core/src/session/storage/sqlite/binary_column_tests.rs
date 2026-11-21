//! Real-SQLite tests for the binary `data_bin` column, the only column a
//! load reads, and the text column it replaced, which no load reads.

use super::*;
use crate::session::crypto::SessionCrypto;
use crate::session::data::SessionData;
use crate::session::id::{SessionId, SessionKey};
use axess_rng::{SecureRng, SystemRng};
use sqlx::sqlite::SqlitePoolOptions;

const KEY: [u8; 32] = crate::testing::test_key(5);

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

async fn columns(store: &SqliteSessionStore, id: &SessionKey) -> (Option<Vec<u8>>, String) {
    sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

/// A row as an earlier release wrote it: base64 of a blob in the current
/// sealed form, bound to the row, in the text column only.
async fn plant_legacy(store: &SqliteSessionStore, id: &SessionKey) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    let text = BASE64.encode(
        SessionCodec::encrypted(SessionCrypto::new(KEY))
            .encode_bytes(id, &admin())
            .unwrap(),
    );
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
    let id = SessionKey::of(&SessionId::new(&SystemRng));
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

/// A row whose binary column is NULL is not read, whatever its text column
/// holds: base64 of a blob in the current sealed form, bound to the row, is
/// refused as undecodable and left as it lies, and the session's next save
/// writes the binary column and empties the text.
#[tokio::test]
async fn a_text_column_row_is_not_read_and_the_next_save_writes_bytes() {
    let store = legacy_store().await;
    let id = SessionKey::of(&SessionId::new(&SystemRng));
    plant_legacy(&store, &id).await;
    let before = columns(&store, &id).await;
    assert!(before.0.is_none() && !before.1.is_empty());

    assert!(matches!(
        store.load(&id).await,
        Err(SqlStoreError::Decode(_))
    ));
    assert_eq!(columns(&store, &id).await, before, "left as it lies");

    store
        .save(&id, &admin(), Duration::from_secs(60))
        .await
        .unwrap();
    let (bin, text) = columns(&store, &id).await;
    assert!(bin.is_some(), "written into the binary column");
    assert_eq!(text, "", "the text emptied");
    assert!(store.load(&id).await.unwrap().is_some());
}

/// The crypto of a store whose key was rotated: `KEY` is its previous key.
fn rotated() -> SessionCrypto {
    SessionCrypto::new(crate::testing::test_key(6)).with_previous_key(KEY)
}

/// A random source that runs a closure once, on its first draw. The codec
/// draws a nonce when it seals the bytes a conditional write is about to
/// store, after the row was read and before it is written, so the closure
/// is a concurrent request landing exactly there.
struct InterleavingRng {
    once: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl SecureRng for InterleavingRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        let action = self.once.lock().unwrap().take();
        if let Some(action) = action {
            action();
        }
        SystemRng.fill_bytes(dest);
    }
}

/// A second connection to the same database file, as another process or
/// pool of the deployment, that loads the row and so re-seals it.
fn reseal_from_another_connection(url: String, id: SessionKey) {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let pool = SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect(&url)
                    .await
                    .unwrap();
                let other = SqliteSessionStore::new(pool, rotated());
                other.load(&id).await.unwrap().expect("the row loads");
            });
    })
    .join()
    .unwrap();
}

/// A load that re-seals the row between a conditional write's read and its
/// write changes the stored bytes, not the revision: the write is judged on
/// the revision and is written, instead of being refused as a conflict with a
/// concurrent request that changed nothing.
#[tokio::test]
async fn a_reseal_during_a_conditional_write_is_not_a_conflict() {
    let dir = std::env::temp_dir().join(format!("axess-reseal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let id = SessionKey::of(&SessionId::new(&SystemRng));
    let path = dir.join(format!("{id}.db"));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, \
         expires_at INTEGER NOT NULL, data_bin BLOB)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let reseal = {
        let (url, id) = (url.clone(), id);
        Box::new(move || reseal_from_another_connection(url, id))
    };
    let store = SqliteSessionStore::new(
        pool,
        rotated().with_rng(Arc::new(InterleavingRng {
            once: std::sync::Mutex::new(Some(reseal)),
        })),
    );
    let stale = SessionCodec::encrypted(SessionCrypto::new(KEY))
        .encode_bytes(&id, &admin())
        .unwrap();
    sqlx::query("INSERT INTO sessions (id, data, data_bin, expires_at) VALUES (?1, '', ?2, ?3)")
        .bind(id.to_string())
        .bind(&stale)
        .bind(i64::MAX)
        .execute(&store.pool)
        .await
        .unwrap();

    let next = SessionData {
        revision: 1,
        custom: serde_json::json!({"role": "owner"}),
        ..SessionData::default()
    };
    let outcome = store
        .update_if_revision(&id, 0, &next, Duration::from_secs(60))
        .await
        .unwrap();
    let (bin, _) = columns(&store, &id).await;
    assert!(
        bin.is_some_and(|bin| bin != stale),
        "the concurrent load re-sealed the row"
    );
    assert_eq!(
        outcome,
        ConditionalUpdate::Written,
        "a re-seal changes the bytes, not the revision"
    );
    let stored = store.load(&id).await.unwrap().expect("row");
    assert_eq!(stored.revision, 1);
    assert_eq!(stored.custom, next.custom);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_cycle_writes_the_new_row_as_bytes() {
    let store = legacy_store().await;
    let (old, new) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    store
        .save(&old, &admin(), Duration::from_secs(60))
        .await
        .unwrap();
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

/// A session stored as JSON, the encoding of the 0.1.x line, is refused
/// wherever the row holds it: in the text column of a plaintext store, which
/// no load reads, as the bytes of a plaintext store, and sealed under the key
/// of an encrypted store. Each load fails with the decode error, so no
/// session is served.
#[tokio::test]
async fn a_json_row_is_refused_in_either_column_and_under_either_codec() {
    let json = serde_json::to_vec(&admin()).unwrap();
    let plain = SqliteSessionStore::plaintext_insecure(pool().await);
    plain.init_schema().await.unwrap();
    let sealed = SqliteSessionStore::new(pool().await, SessionCrypto::new(KEY));
    sealed.init_schema().await.unwrap();

    let text_row = SessionKey::of(&SessionId::new(&SystemRng));
    sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?1, ?2, ?3)")
        .bind(text_row.to_string())
        .bind(String::from_utf8(json.clone()).unwrap())
        .bind(i64::MAX)
        .execute(&plain.pool)
        .await
        .unwrap();

    let byte_row = SessionKey::of(&SessionId::new(&SystemRng));
    plant_bytes(&plain, &byte_row, json.clone()).await;

    let sealed_row = SessionKey::of(&SessionId::new(&SystemRng));
    let blob = SessionCrypto::new(KEY)
        .seal_bound(
            crate::session::crypto::BoundFormat::SESSION,
            sealed_row.as_bytes(),
            &json,
        )
        .unwrap();
    plant_bytes(&sealed, &sealed_row, blob).await;

    for (store, id) in [
        (&plain, &text_row),
        (&plain, &byte_row),
        (&sealed, &sealed_row),
    ] {
        let refused = store.load(id).await;
        assert!(
            matches!(refused, Err(SqlStoreError::Decode(_))),
            "a JSON session is not served: {refused:?}"
        );
    }
}

async fn plant_bytes(store: &SqliteSessionStore, id: &SessionKey, bytes: Vec<u8>) {
    sqlx::query("INSERT INTO sessions (id, data, data_bin, expires_at) VALUES (?1, '', ?2, ?3)")
        .bind(id.to_string())
        .bind(bytes)
        .bind(i64::MAX)
        .execute(&store.pool)
        .await
        .unwrap();
}
