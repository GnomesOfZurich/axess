//! The Postgres session store against a real server, ignored by default
//! (`POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres`). Every test works on a schema of its own, so the
//! tests can run in parallel and be repeated against the same server.

use super::*;
use crate::session::crypto::{BoundFormat, LegacyBlobs, SessionCrypto};
use crate::session::id::{SessionId, SessionKey};
use crate::testing::sql_live;
use axess_clock::testing::MockClock;
use axess_rng::SystemRng;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const KEY: [u8; 32] = crate::testing::test_key(3);
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
    let clock = Arc::new(MockClock::at(
        axess_clock::testing::MockClock::reference_time(),
    ));
    (store().await.with_clock(clock.clone()), clock)
}

fn admin() -> SessionData {
    SessionData {
        custom: serde_json::json!({"role": "admin"}),
        ..SessionData::default()
    }
}

fn new_id() -> SessionKey {
    SessionKey::of(&SessionId::new(&SystemRng))
}

async fn raw(store: &PostgresSessionStore, id: &SessionKey) -> Vec<u8> {
    sqlx::query_scalar("SELECT data_bin FROM sessions WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

/// Both data columns of a row: the binary one may be NULL.
async fn columns(store: &PostgresSessionStore, id: &SessionKey) -> (Option<Vec<u8>>, String) {
    sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

async fn expiry(store: &PostgresSessionStore, id: &SessionKey) -> i64 {
    sqlx::query_scalar("SELECT expires_at FROM sessions WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

/// A blob sealed without the row binding, in the binary column.
async fn plant_unbound(store: &PostgresSessionStore, id: &SessionKey, expires_at: i64) -> Vec<u8> {
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

/// A bound row as an earlier release wrote it: base64 of a blob in the
/// current sealed form, in the text column only.
async fn plant_text(store: &PostgresSessionStore, id: &SessionKey) {
    let text = BASE64.encode(store.codec.encode_bytes(id, &admin()).unwrap());
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
    let store = PostgresSessionStore::plaintext_insecure(pool);
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

/// A row that carries no row binding is refused, though this store's crypto
/// reads legacy blobs with no end date: such a blob opens under any row, so
/// reading it as a session would let a row be moved. The refused row is left
/// as it is, and the session's next save writes the current form.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn an_unbound_row_is_refused_under_a_policy_that_reads_legacy_blobs() {
    let store = store().await;
    let id = new_id();
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

    store.save(&id, &admin(), TTL).await.unwrap();
    assert!(BoundFormat::SESSION.marks(&raw(&store, &id).await));
    assert!(store.load(&id).await.unwrap().is_some());
}

/// A row whose binary column is NULL is not read, whatever its text column
/// holds: base64 of a blob in the current sealed form, bound to the row, is
/// refused as undecodable and left as it lies.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_text_column_row_is_not_read() {
    let store = store().await;
    let id = new_id();
    plant_text(&store, &id).await;
    let before = columns(&store, &id).await;

    assert!(matches!(
        store.load(&id).await,
        Err(SqlStoreError::Decode(_))
    ));
    assert_eq!(columns(&store, &id).await, before, "left as it lies");
}

/// The re-seal is conditional on the bytes that were read: a save that
/// landed in between is kept.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_reseal_never_overwrites_a_save_that_landed_meanwhile() {
    let store = store().await;
    let now = store.clock.now().unix_seconds();
    let newer = SessionData {
        custom: serde_json::json!({"role": "newer"}),
        ..SessionData::default()
    };

    let id = new_id();
    let stale = plant_unbound(&store, &id, i64::MAX).await;
    store.save(&id, &newer, TTL).await.unwrap();
    store.reseal(&id, &admin(), &stale, now).await;
    assert_eq!(store.load(&id).await.unwrap().unwrap().custom, newer.custom);
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

/// The documented upgrade of a table created before the binary column: its
/// rows hold their blob in the text column, and `data_bin` is NULL once the
/// upgrade step has run. No such row is read, whatever its blob: one in the
/// current sealed form and one from before row binding are both refused as
/// undecodable and left as they lie, and a conditional write that meets one
/// is refused the same way. A session saved after the step loads.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn the_documented_upgrade_step_makes_an_old_table_work() {
    let pool = sql_live::postgres_pool(2).await;
    sqlx::query("CREATE TABLE sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at BIGINT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    let store = PostgresSessionStore::new(
        pool.clone(),
        SessionCrypto::new(KEY).with_legacy_blobs(LegacyBlobs::Accept),
    );
    let (kept, ended, unbound) = (new_id(), new_id(), new_id());
    let current = |id: &SessionKey| store.codec.encode_bytes(id, &admin()).unwrap();
    let before_binding = SessionCrypto::new(KEY)
        .encrypt_unbound(&rmp_serde::to_vec_named(&admin()).unwrap())
        .unwrap();
    for (id, old) in [
        (&kept, current(&kept)),
        (&ended, current(&ended)),
        (&unbound, before_binding),
    ] {
        sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES ($1, $2, $3)")
            .bind(id.to_string())
            .bind(BASE64.encode(old))
            .bind(i64::MAX)
            .execute(&pool)
            .await
            .unwrap();
    }

    sqlx::query("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS data_bin BYTEA")
        .execute(&pool)
        .await
        .unwrap();
    store
        .init_schema()
        .await
        .expect("init_schema on an upgraded table");

    assert!(
        matches!(store.load(&unbound).await, Err(SqlStoreError::Decode(_))),
        "a blob from before row binding is not a session"
    );
    let (binary, text) = columns(&store, &unbound).await;
    assert!(binary.is_none() && !text.is_empty(), "left as it was");

    for (what, row) in [("in the current form", &kept), ("never loaded", &ended)] {
        let before = columns(&store, row).await;
        assert!(
            matches!(store.load(row).await, Err(SqlStoreError::Decode(_))),
            "a text row {what} is not read"
        );
        assert!(
            matches!(
                store
                    .update_if_revision(row, admin().revision, &admin(), Duration::ZERO)
                    .await,
                Err(SqlStoreError::Decode(_))
            ),
            "a conditional write that meets a text row {what} is refused"
        );
        assert_eq!(columns(&store, row).await, before, "left as it lies");
    }

    let fresh = new_id();
    store.save(&fresh, &admin(), TTL).await.unwrap();
    assert!(store.load(&fresh).await.unwrap().is_some());
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn update_if_revision_keeps_the_contract() {
    crate::testing::store_contract::assert_update_if_revision_contract(&store().await).await;
}

/// The store refuses a payload over its cap and keeps the row it had.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn an_oversized_payload_is_refused_and_the_old_row_kept() {
    let store = store().await;
    let id = new_id();
    store.save(&id, &admin(), TTL).await.unwrap();
    let big = SessionData {
        custom: serde_json::json!({"blob": "x".repeat(100 * 1024)}),
        ..SessionData::default()
    };
    assert!(matches!(
        store.save(&id, &big, TTL).await,
        Err(SqlStoreError::PayloadTooLarge { .. })
    ));
    assert!(matches!(
        store.cycle(&id, &new_id(), &big, TTL, true).await,
        Err(SqlStoreError::PayloadTooLarge { .. })
    ));
    assert_eq!(
        store.load(&id).await.unwrap().unwrap().custom["role"],
        "admin"
    );
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_session_carrying_assurance_round_trips() {
    let store = store().await;
    let id = new_id();
    let data = crate::session::data::assured_fixture::assured_session();
    store.save(&id, &data, TTL).await.unwrap();
    let back = store.load(&id).await.unwrap().expect("stored");
    assert_eq!(back.auth_state, data.auth_state);
    assert_eq!(back.auth_state.assurance(), data.auth_state.assurance());
}

/// A zero cleanup interval is refused by name where the task is spawned.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
#[should_panic(expected = "the cleanup interval must be greater than zero")]
async fn spawn_cleanup_task_refuses_a_zero_interval_by_name() {
    let s = store().await;
    drop(s.spawn_cleanup_task(Duration::ZERO));
}

// ── What the store holds for a session ───────────────────────────────────────

/// A plaintext store and a sealed one, each on a schema of its own.
async fn stored_form_stores() -> [PostgresSessionStore; 2] {
    let plain = PostgresSessionStore::plaintext_insecure(sql_live::postgres_pool(2).await);
    let sealed =
        PostgresSessionStore::new(sql_live::postgres_pool(2).await, SessionCrypto::new(KEY));
    for store in [&plain, &sealed] {
        store.init_schema().await.expect("init_schema");
    }
    [plain, sealed]
}

fn revised(revision: u64) -> SessionData {
    SessionData {
        revision,
        ..admin()
    }
}

/// Every row, every column: the name, the text column and the binary one.
async fn all_rows(store: &PostgresSessionStore) -> Vec<(String, String, Option<Vec<u8>>)> {
    sqlx::query_as("SELECT id, data, data_bin FROM sessions ORDER BY id")
        .fetch_all(&store.pool)
        .await
        .unwrap()
}

async fn row_names(store: &PostgresSessionStore) -> Vec<String> {
    let mut names: Vec<String> = all_rows(store).await.into_iter().map(|row| row.0).collect();
    // In byte order, whatever collation the server sorts the column by.
    names.sort();
    names
}

/// No column of any row holds `id`: not its hyphenated text, not its 32
/// hexadecimal digits, not its 16 bytes.
async fn assert_holds_no_id(store: &PostgresSessionStore, id: &SessionId) {
    let forms = [
        id.to_string().into_bytes(),
        id.as_uuid().simple().to_string().into_bytes(),
        id.as_bytes().to_vec(),
    ];
    for (name, text, binary) in all_rows(store).await {
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
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn the_row_is_named_by_the_key() {
    for store in stored_form_stores().await {
        let id = SessionId::new(&SystemRng);
        let key = SessionKey::of(&id);
        store.save(&key, &revised(1), TTL).await.unwrap();

        let names = row_names(&store).await;
        assert_eq!(names, [key.to_string()]);
        assert_eq!(names[0].len(), 64);
        assert_holds_no_id(&store, &id).await;

        // Every later write of the session leaves it under the same name.
        assert!(store.update(&key, &revised(1), TTL).await.unwrap());
        assert_eq!(
            store
                .update_if_revision(&key, 1, &revised(2), TTL)
                .await
                .unwrap(),
            ConditionalUpdate::Written
        );
        assert_eq!(row_names(&store).await, [key.to_string()]);
        assert_holds_no_id(&store, &id).await;
        assert_eq!(store.load(&key).await.unwrap().unwrap().revision, 2);
    }
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_rotation_names_both_rows_by_their_keys() {
    for store in stored_form_stores().await {
        let ids = [
            SessionId::new(&SystemRng),
            SessionId::new(&SystemRng),
            SessionId::new(&SystemRng),
        ];
        let [first, second, third] = ids.map(|id| SessionKey::of(&id));
        store.save(&first, &revised(1), TTL).await.unwrap();

        assert_eq!(
            store
                .cycle(&first, &second, &revised(1), TTL, true)
                .await
                .unwrap(),
            CycleOutcome::Rotated
        );
        assert_eq!(row_names(&store).await, [second.to_string()]);

        assert_eq!(
            store
                .cycle_if_revision(&second, &third, &revised(1), TTL, true, 1)
                .await
                .unwrap(),
            CycleOutcome::Rotated
        );
        assert_eq!(row_names(&store).await, [third.to_string()]);
        for id in &ids {
            assert_holds_no_id(&store, id).await;
        }

        // The zero-ttl form removes the rows under both keys, and no other.
        store.save(&first, &revised(1), TTL).await.unwrap();
        store.save(&second, &revised(1), TTL).await.unwrap();
        assert_eq!(
            store
                .cycle(&third, &first, &revised(1), Duration::ZERO, true)
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
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_row_under_a_session_id_is_not_read_and_one_statement_removes_it() {
    let [store, _] = stored_form_stores().await;
    let id = SessionId::new(&SystemRng);
    let key = SessionKey::of(&id);
    // What such a row holds does not matter to the lookup; a plaintext
    // store would read this one if it found it.
    let blob = rmp_serde::to_vec_named(&revised(1)).unwrap();
    for name in [id.to_string(), id.as_uuid().simple().to_string()] {
        sqlx::query(
            "INSERT INTO sessions (id, data, data_bin, expires_at) VALUES ($1, '', $2, $3)",
        )
        .bind(name)
        .bind(&blob)
        .bind(i64::MAX)
        .execute(&store.pool)
        .await
        .unwrap();
    }
    assert!(store.load(&key).await.unwrap().is_none());
    assert!(!store.update(&key, &revised(1), TTL).await.unwrap());

    store.save(&key, &revised(1), TTL).await.unwrap();
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
