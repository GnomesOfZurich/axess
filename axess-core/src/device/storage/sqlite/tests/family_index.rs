//! A device with many refresh families is indexed completely, in batches
//! that stay under the tightest dialect's bind-parameter cap.

use super::*;
use crate::device::storage::sql_common::FAMILY_INSERT_CHUNK;

/// SQLite's default `SQLITE_MAX_VARIABLE_NUMBER`.
const SQLITE_VARIABLE_CAP: usize = 32_766;

fn refresh(family: String) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family,
        issued_at: now_at(10, 0),
        last_used_at: now_at(10, 0),
    }
}

/// A batch binds three variables per family.
const _: () = assert!(FAMILY_INSERT_CHUNK * 3 <= SQLITE_VARIABLE_CAP);

#[tokio::test]
async fn a_device_with_many_families_is_indexed_across_chunk_boundaries() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    let count = FAMILY_INSERT_CHUNK * 2 + 200;
    let device = build_device(
        &t,
        Some(&u),
        &d,
        1,
        (0..count).map(|i| refresh(format!("fam-{i}"))).collect(),
    );
    store.save(&device, chrono::Utc::now()).await.unwrap();

    for i in [0, FAMILY_INSERT_CHUNK - 1, FAMILY_INSERT_CHUNK, count - 1] {
        let found = store
            .find_by_refresh_family(&t, &format!("fam-{i}"))
            .await
            .unwrap();
        assert_eq!(found.len(), 1, "fam-{i}");
    }
    let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM device_bindings_refresh")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(rows, count as i64);

    // Saving again rewrites the index rather than duplicating it.
    store.save(&device, chrono::Utc::now()).await.unwrap();
    let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM device_bindings_refresh")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(rows, count as i64);
}
