//! The Postgres session store against a real server, ignored by default
//! (`POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres`). Every test works on a schema of its own, so the
//! tests can run in parallel and be repeated against the same server.

use super::*;
use crate::session::crypto::{BoundFormat, LegacyBlobs, SessionCrypto};
use crate::testing::sql_live;
use axess_clock::testing::MockClock;
use axess_rng::SystemRng;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const KEY: [u8; 32] = [3u8; 32];
const TTL: Duration = Duration::from_secs(60);

async fn store() -> PostgresSessionStore {
    let store = PostgresSessionStore::new(
        sql_live::postgres_pool(4).await,
        SessionCrypto::new(KEY).with_legacy_blobs(crate::session::crypto::LegacyBlobs::Accept),
    );
    store.init_schema().await.expect("init_schema");
    store
}

async fn store_with_clock() -> (PostgresSessionStore, Arc<MockClock>) {
    let clock = Arc::new(MockClock::at(chrono::Utc::now()));
    (store().await.with_clock(clock.clone()), clock)
}

fn admin() -> SessionData {
    SessionData {
        custom: serde_json::json!({"role": "admin"}),
        ..SessionData::default()
    }
}

fn new_id() -> SessionId {
    SessionId::new(&SystemRng)
}

async fn raw(store: &PostgresSessionStore, id: &SessionId) -> Vec<u8> {
    sqlx::query_scalar("SELECT data_bin FROM sessions WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

async fn expiry(store: &PostgresSessionStore, id: &SessionId) -> i64 {
    sqlx::query_scalar("SELECT expires_at FROM sessions WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

/// A blob sealed without the row binding, in the binary column.
async fn plant_unbound(store: &PostgresSessionStore, id: &SessionId, expires_at: i64) -> Vec<u8> {
    let blob = SessionCrypto::new(KEY)
        .encrypt_unbound(&rmp_serde::to_vec_named(&admin()).unwrap())
        .unwrap();
    sqlx::query("INSERT INTO sessions (id, data, data_bin, expires_at) VALUES ($1, '', $2, $3)")
        .bind(id.to_string())
        .bind(&blob)
        .bind(expires_at)
        .execute(&store.pool)
        .await
        .unwrap();
    blob
}

/// A row as an earlier release wrote it: base64 in the text column only.
async fn plant_text(store: &PostgresSessionStore, id: &SessionId) {
    let text = BASE64.encode(
        SessionCrypto::new(KEY)
            .encrypt_unbound(&rmp_serde::to_vec_named(&admin()).unwrap())
            .unwrap(),
    );
    sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES ($1, $2, $3)")
        .bind(id.to_string())
        .bind(text)
        .bind(i64::MAX)
        .execute(&store.pool)
        .await
        .unwrap();
}

/// `update` and `cycle` never write back a session that was ended.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn an_ended_session_is_never_revived() {
    crate::session::store::revival_tests::run_all(&store().await).await;
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_plaintext_store_round_trips_and_deletes() {
    let pool = sql_live::postgres_pool(2).await;
    let store = PostgresSessionStore::plaintext(pool);
    store.init_schema().await.unwrap();
    let id = new_id();
    store.save(&id, &admin(), TTL).await.unwrap();
    assert_eq!(
        store.load(&id).await.unwrap().unwrap().custom,
        admin().custom
    );
    store.delete(&id).await.unwrap();
    assert!(store.load(&id).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn data_copied_into_another_sessions_row_does_not_load() {
    let store = store().await;
    let (admin_id, attacker_id) = (new_id(), new_id());
    store.save(&admin_id, &admin(), TTL).await.unwrap();
    store
        .save(&attacker_id, &SessionData::default(), TTL)
        .await
        .unwrap();
    let stolen = raw(&store, &admin_id).await;
    sqlx::query("UPDATE sessions SET data_bin = $1 WHERE id = $2")
        .bind(stolen)
        .bind(attacker_id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();

    assert!(store.load(&attacker_id).await.is_err());
    assert!(store.load(&admin_id).await.unwrap().is_some());
}

/// A load re-seals a row that carries no row binding, keeps its expiry, and
/// the next load reads the bound form.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn load_reseals_an_unbound_row_and_keeps_its_expiry() {
    let store = store().await;
    let id = new_id();
    let expires = store.clock.now().timestamp() + 600;
    let unbound = plant_unbound(&store, &id, expires).await;
    assert!(!BoundFormat::SESSION.marks(&unbound));

    let loaded = store.load(&id).await.unwrap().expect("unbound row loads");
    assert_eq!(loaded.custom, admin().custom);
    assert!(BoundFormat::SESSION.marks(&raw(&store, &id).await));
    assert_eq!(expiry(&store, &id).await, expires, "the expiry is kept");
    assert!(store.load(&id).await.unwrap().is_some());
}

/// A legacy text-column row is moved to the binary column by its load.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn load_moves_a_text_column_row_to_the_binary_column() {
    let store = store().await;
    let id = new_id();
    plant_text(&store, &id).await;

    assert_eq!(
        store.load(&id).await.unwrap().unwrap().custom,
        admin().custom
    );
    let (bin, text): (Option<Vec<u8>>, String) =
        sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = $1")
            .bind(id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(bin.is_some_and(|b| BoundFormat::SESSION.marks(&b)));
    assert!(text.is_empty());
}

/// The re-seal is conditional on the bytes that were read: a save that
/// landed in between is kept, for a binary row and for a text row.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_reseal_never_overwrites_a_save_that_landed_meanwhile() {
    let store = store().await;
    let now = store.clock.now().timestamp();
    let newer = SessionData {
        custom: serde_json::json!({"role": "newer"}),
        ..SessionData::default()
    };

    let id = new_id();
    let stale = plant_unbound(&store, &id, i64::MAX).await;
    store.save(&id, &newer, TTL).await.unwrap();
    store.reseal(&id, &admin(), Some(&stale), "", now).await;
    assert_eq!(store.load(&id).await.unwrap().unwrap().custom, newer.custom);

    let text_id = new_id();
    plant_text(&store, &text_id).await;
    let (_, text): (Option<Vec<u8>>, String) =
        sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = $1")
            .bind(text_id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
    store.save(&text_id, &newer, TTL).await.unwrap();
    store.reseal(&text_id, &admin(), None, &text, now).await;
    assert_eq!(
        store.load(&text_id).await.unwrap().unwrap().custom,
        newer.custom
    );
}

/// With legacy blobs rejected, an unbound row is refused and left as it is;
/// a bound row loads.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn rejecting_legacy_blobs_refuses_an_unbound_row() {
    let strict = PostgresSessionStore::new(
        sql_live::postgres_pool(2).await,
        SessionCrypto::new(KEY).with_legacy_blobs(LegacyBlobs::Reject),
    );
    strict.init_schema().await.unwrap();
    let (legacy_id, bound_id) = (new_id(), new_id());
    let unbound = plant_unbound(&strict, &legacy_id, i64::MAX).await;
    strict.save(&bound_id, &admin(), TTL).await.unwrap();

    assert!(strict.load(&legacy_id).await.is_err());
    assert_eq!(raw(&strict, &legacy_id).await, unbound, "left as it was");
    assert!(strict.load(&bound_id).await.unwrap().is_some());
}

/// `update` and `cycle` treat a session whose time has passed as gone.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn an_expired_session_is_gone_to_load_update_and_cycle() {
    let (store, clock) = store_with_clock().await;
    let (id, other, new) = (new_id(), new_id(), new_id());
    store.save(&id, &admin(), TTL).await.unwrap();
    store.save(&other, &admin(), TTL).await.unwrap();
    clock.advance_secs(61);

    assert!(store.load(&id).await.unwrap().is_none());
    assert!(!store.update(&id, &admin(), TTL).await.unwrap());
    assert!(store.load(&id).await.unwrap().is_none(), "not revived");
    assert_eq!(
        store
            .cycle(&other, &new, &admin(), TTL, true)
            .await
            .unwrap(),
        CycleOutcome::SessionGone
    );
    assert!(store.load(&new).await.unwrap().is_none());

    // Without `require_old` the expired remnant is removed and the new row
    // is written.
    let remnant = id;
    assert_eq!(
        store
            .cycle(&remnant, &new, &admin(), TTL, false)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    assert!(store.load(&new).await.unwrap().is_some());
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE id = $1")
        .bind(remnant.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

/// Cleanup removes exactly the expired rows, and the count says so.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn cleanup_removes_only_expired_rows() {
    let (store, clock) = store_with_clock().await;
    let (short, long) = (new_id(), new_id());
    store
        .save(&short, &admin(), Duration::from_secs(10))
        .await
        .unwrap();
    store
        .save(&long, &admin(), Duration::from_secs(1_000))
        .await
        .unwrap();
    clock.advance_secs(11);

    assert_eq!(store.cleanup_expired().await.unwrap(), 1);
    assert_eq!(store.prune_expired().await.unwrap(), 0);
    assert!(store.load(&long).await.unwrap().is_some());
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn cycle_is_idempotent_when_the_new_row_already_exists() {
    let store = store().await;
    let (old, new) = (new_id(), new_id());
    store.save(&old, &admin(), TTL).await.unwrap();
    store
        .save(&new, &SessionData::default(), TTL)
        .await
        .unwrap();

    assert_eq!(
        store.cycle(&old, &new, &admin(), TTL, true).await.unwrap(),
        CycleOutcome::Rotated
    );
    assert!(store.load(&old).await.unwrap().is_none());
    assert_eq!(
        store.load(&new).await.unwrap().unwrap().custom,
        admin().custom
    );

    assert_eq!(
        store.cycle(&new, &new, &admin(), TTL, true).await.unwrap(),
        CycleOutcome::Rotated
    );
    assert!(store.load(&new).await.unwrap().is_some());
}

/// A rotation whose insert is refused leaves the old session in place.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_failed_insert_leaves_the_old_session_in_place() {
    let store = store().await;
    let (old, new) = (new_id(), new_id());
    store.save(&old, &admin(), TTL).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE sessions ADD CONSTRAINT refuse CHECK (id <> '{new}')"
    )))
    .execute(&store.pool)
    .await
    .unwrap();

    assert!(store.cycle(&old, &new, &admin(), TTL, true).await.is_err());
    assert!(store.load(&old).await.unwrap().is_some());
    assert!(store.load(&new).await.unwrap().is_none());
}

/// Two rotations of one session: one wins and the other finds it gone, so
/// the authenticated data ends up under exactly one new id.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn racing_rotations_leave_the_data_under_one_id() {
    let store = store().await;
    let (old, a, b) = (new_id(), new_id(), new_id());
    store.save(&old, &admin(), TTL).await.unwrap();
    let data = admin();
    let (ra, rb) = tokio::join!(
        store.cycle(&old, &a, &data, TTL, true),
        store.cycle(&old, &b, &data, TTL, true),
    );
    let mut outcomes = vec![ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(
        outcomes,
        vec![CycleOutcome::Rotated, CycleOutcome::SessionGone]
    );
    let live = store.load(&a).await.unwrap().is_some() as u8
        + store.load(&b).await.unwrap().is_some() as u8;
    assert_eq!(live, 1);
    assert!(store.load(&old).await.unwrap().is_none());
}

/// The documented upgrade of a table created before the binary column.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn the_documented_upgrade_step_makes_an_old_table_work() {
    let pool = sql_live::postgres_pool(2).await;
    sqlx::query("CREATE TABLE sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at BIGINT NOT NULL)").execute(&pool).await.unwrap();
    let store = PostgresSessionStore::new(
        pool.clone(),
        SessionCrypto::new(KEY).with_legacy_blobs(crate::session::crypto::LegacyBlobs::Accept),
    );
    let id = new_id();
    sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES ($1, $2, $3)")
        .bind(id.to_string())
        .bind(
            BASE64.encode(
                SessionCrypto::new(KEY)
                    .encrypt_unbound(&rmp_serde::to_vec_named(&admin()).unwrap())
                    .unwrap(),
            ),
        )
        .bind(i64::MAX)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS data_bin BYTEA")
        .execute(&pool)
        .await
        .unwrap();
    store
        .init_schema()
        .await
        .expect("init_schema on an upgraded table");
    assert_eq!(
        store.load(&id).await.unwrap().unwrap().custom,
        admin().custom
    );
    assert!(BoundFormat::SESSION.marks(&raw(&store, &id).await));
    let fresh = new_id();
    store.save(&fresh, &admin(), TTL).await.unwrap();
    assert!(store.load(&fresh).await.unwrap().is_some());
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn update_if_revision_keeps_the_contract() {
    crate::testing::store_contract::assert_update_if_revision_contract(&store().await).await;
}
