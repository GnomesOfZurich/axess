//! Pin every inherent and `SessionStore` body for
//! `SqliteSessionStore`. Uses a real in-memory SQLite pool so we
//! observe round-trip behaviour, then assert that a save → load
//! cycle returns the same payload (and an absent key returns None).
//! Body-replacement mutations on `load`, `save`, `delete`, `cycle`,
//! `prune_expired`, `cleanup_expired`, and `init_schema` are caught
//! because the mutated body either returns a wrong value or fails
//! to apply the real side effect (so a follow-up observation
//! disagrees with the original).
use super::*;
use crate::session::data::SessionData;
use crate::session::id::SessionId;
use axess_rng::SystemRng;
use sqlx::sqlite::SqlitePoolOptions;

async fn memory_pool() -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite must connect")
}

async fn store() -> SqliteSessionStore {
    let pool = memory_pool().await;
    let store = SqliteSessionStore::plaintext(pool);
    store.init_schema().await.expect("init_schema");
    store
}

fn sample_id() -> SessionId {
    SessionId::new(&SystemRng)
}

fn payload_with_custom() -> SessionData {
    SessionData {
        custom: serde_json::json!({"k": "v"}),
        ..SessionData::default()
    }
}

/// A zero TTL writes an already-expired row, so `update` must say the
/// session was not kept; a sub-second TTL is raised to one second and
/// the session stays loadable.
#[tokio::test]
async fn zero_ttl_update_reports_false_and_sub_second_ttl_stays_loadable() {
    let store = store().await;
    let id = sample_id();
    store
        .save(&id, &payload_with_custom(), Duration::from_secs(60))
        .await
        .unwrap();
    let kept = store
        .update(&id, &payload_with_custom(), Duration::ZERO)
        .await
        .unwrap();
    assert!(
        !kept,
        "an update that expires the row at once is not a keep"
    );
    assert!(store.load(&id).await.unwrap().is_none());

    let id2 = sample_id();
    store
        .save(&id2, &payload_with_custom(), Duration::from_millis(500))
        .await
        .unwrap();
    assert!(
        store.load(&id2).await.unwrap().is_some(),
        "a sub-second TTL must not produce a row that can never load"
    );
}

#[tokio::test]
async fn init_schema_creates_sessions_table() {
    // Pins line 90 body against `Ok(())`. After init_schema, an
    // INSERT into `sessions` succeeds; if the body was replaced
    // by `Ok(())`, the table would not exist and the save below
    // would fail.
    let store = store().await;
    let result = store
        .save(
            &sample_id(),
            &SessionData::default(),
            Duration::from_secs(60),
        )
        .await;
    assert!(
        result.is_ok(),
        "save after init_schema must succeed: {result:?}"
    );
}

#[tokio::test]
async fn save_then_load_returns_persisted_payload() {
    // Pins lines 165 (load body), 187 (save body) against
    // `Ok(None)`, `Ok(Some(Default::default()))`, and `Ok(())`.
    // The mutations would either drop the persisted row or
    // return a default; the round-trip catches both.
    let store = store().await;
    let id = sample_id();
    let data = payload_with_custom();

    store
        .save(&id, &data, Duration::from_secs(60))
        .await
        .expect("save");

    let loaded = store.load(&id).await.expect("load").expect("Some");
    assert_eq!(
        serde_json::to_string(&data).unwrap(),
        serde_json::to_string(&loaded).unwrap(),
        "load must return what save persisted; kills Ok(None) AND Ok(Some(Default))"
    );
}

#[tokio::test]
async fn load_of_absent_key_returns_none() {
    // Kill `Ok(Some(Default::default()))` mutation on load;
    // a row that was never saved must come back as None, not
    // a default-constructed SessionData.
    let store = store().await;
    let loaded = store.load(&sample_id()).await.expect("load");
    assert!(
        loaded.is_none(),
        "absent key must yield None, not Some(Default)"
    );
}

#[tokio::test]
async fn delete_actually_removes_row() {
    // Pins line 208 body against `Ok(())`. With the mutation,
    // delete still returns Ok(()), but the row remains;
    // load() afterwards would still find it.
    let store = store().await;
    let id = sample_id();
    let data = payload_with_custom();
    store
        .save(&id, &data, Duration::from_secs(60))
        .await
        .expect("save");
    assert!(store.load(&id).await.expect("load before delete").is_some());

    store.delete(&id).await.expect("delete");
    let after = store.load(&id).await.expect("load after delete");
    assert!(
        after.is_none(),
        "delete must remove the row; mutated body would leave it"
    );
}

#[tokio::test]
async fn cycle_atomically_swaps_session_ids() {
    // Pins line 223 body against `Ok(())`. Real cycle replaces
    // old_id row with new_id row; mutated cycle returns Ok(())
    // without doing the swap; so old row stays and new row
    // never appears.
    let store = store().await;
    let old = sample_id();
    let new = sample_id();
    let data = payload_with_custom();
    store
        .save(&old, &data, Duration::from_secs(60))
        .await
        .expect("save");

    assert_eq!(
        store
            .cycle(&old, &new, &data, Duration::from_secs(60), true)
            .await
            .expect("cycle"),
        CycleOutcome::Rotated
    );

    assert!(
        store.load(&old).await.expect("load old").is_none(),
        "old id must be gone after cycle"
    );
    assert!(
        store.load(&new).await.expect("load new").is_some(),
        "new id must exist after cycle; kills cycle->Ok(()) mutant"
    );
}

#[tokio::test]
async fn cleanup_expired_returns_real_row_count() {
    // Pins line 111 against `Ok(0)` and `Ok(1)` mutations.
    // Save two sessions with negative TTL (already expired);
    // cleanup_expired must return 2, not 0 or 1.
    let store = store().await;
    let id1 = sample_id();
    let id2 = sample_id();

    // Insert directly with an expires_at in the past; the
    // `save` helper would use the configured clock, so reach
    // into the SQL layer with a hand-rolled INSERT instead.
    for id in [&id1, &id2] {
        sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?1, '{}', 0)")
            .bind(id.to_string())
            .execute(&store.pool)
            .await
            .expect("manual insert");
    }

    let removed = store.cleanup_expired().await.expect("cleanup_expired");
    assert_eq!(
        removed, 2,
        "cleanup_expired must report the real row-count; kills Ok(0) and Ok(1)"
    );
}

#[tokio::test]
async fn prune_expired_trait_surface_matches_inherent() {
    // Pins line 252 body against `Ok(0)` and `Ok(1)`. After
    // inserting three expired rows, prune_expired must
    // delegate to cleanup_expired and return 3.
    let store = store().await;
    for _ in 0..3 {
        sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?1, '{}', 0)")
            .bind(SessionId::new(&SystemRng).to_string())
            .execute(&store.pool)
            .await
            .expect("manual insert");
    }
    let removed = store.prune_expired().await.expect("prune_expired");
    assert_eq!(removed, 3);
}

// log_cleanup_outcome is now shared in `sql_helpers` and pinned by tests
// there; the per-backend duplicates were dropped to keep one source of
// truth. The cleanup-pipeline shape (label propagation, debug-only-on-
// positive, warn-on-err) is unchanged.
