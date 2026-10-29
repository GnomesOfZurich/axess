//! The queries the request path and the sweep run are served by indexes in
//! the order they need, not by a sort over every matching row.

use super::*;

async fn plan(store: &SqliteDeviceStore, sql: &str) -> String {
    // `sql` is one of the literal statements below, never input.
    let rows: Vec<(i64, i64, i64, String)> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
            .bind("t")
            .bind(vec![0u8; 32])
            .fetch_all(&store.pool)
            .await
            .unwrap();
    rows.iter()
        .map(|r| r.3.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

/// `find_by_fingerprint` reads the newest sighting from the index, with no
/// temporary sort: the cost no longer grows with the devices that share a
/// fingerprint.
#[tokio::test]
async fn the_fingerprint_lookup_is_served_in_order_by_its_index() {
    let store = fresh_store().await;
    let detail = plan(
        &store,
        "SELECT id FROM devices WHERE tenant_id = ?1 AND fingerprint_hash = ?2 \
         ORDER BY last_seen_at DESC, id ASC LIMIT 1",
    )
    .await;
    assert!(
        detail.contains("idx_devices_fingerprint_seen"),
        "plan: {detail}"
    );
    assert!(!detail.contains("TEMP B-TREE"), "plan sorts: {detail}");
}

/// The sweep stages that demote by age use the level-and-age index.
#[tokio::test]
async fn the_sweep_stages_use_their_indexes() {
    let store = fresh_store().await;
    let aged = plan(
        &store,
        "UPDATE devices SET trust_level = 'Seen' WHERE tenant_id = ?1 AND id IN \
         (SELECT id FROM devices WHERE tenant_id = ?1 \
          AND trust_level = 'Trusted' AND last_seen_at < length(?2) LIMIT 1000)",
    )
    .await;
    assert!(aged.contains("idx_devices_sweep"), "plan: {aged}");
    let purge = plan(
        &store,
        "DELETE FROM devices WHERE tenant_id = ?1 AND id IN \
         (SELECT id FROM devices WHERE tenant_id = ?1 AND trust_level = 'Revoked' \
          AND revoked_at IS NOT NULL AND revoked_at < length(?2) LIMIT 1000)",
    )
    .await;
    assert!(purge.contains("idx_devices_revoked_at"), "plan: {purge}");
}

/// The plain fingerprint index of earlier releases is dropped by
/// `init_schema`, and running it again changes nothing.
#[tokio::test]
async fn init_schema_replaces_the_old_fingerprint_index_once() {
    let store = fresh_store().await;
    sqlx::query("CREATE INDEX idx_devices_fingerprint ON devices (tenant_id, fingerprint_hash)")
        .execute(&store.pool)
        .await
        .unwrap();
    store.init_schema().await.unwrap();
    store.init_schema().await.unwrap();
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'devices' \
         AND name LIKE 'idx_devices_%' ORDER BY name",
    )
    .fetch_all(&store.pool)
    .await
    .unwrap();
    assert!(
        !names.contains(&"idx_devices_fingerprint".to_string()),
        "{names:?}"
    );
    assert!(
        names.contains(&"idx_devices_fingerprint_seen".to_string()),
        "{names:?}"
    );
}
