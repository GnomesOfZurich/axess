//! Re-seal of stale bindings blobs found by a read.

use sqlx::MySqlPool;

use crate::device::storage::sql_common::{Reseal, note_reseal};

/// Replace each stale bindings blob read by a lookup with its current-format
/// form. Every write is conditional on the exact bytes that were read, so a
/// save that landed since is never overwritten, and a failure is logged
/// without failing the read.
pub(super) async fn reseal_rows(pool: &MySqlPool, reseals: impl IntoIterator<Item = Reseal>) {
    for r in reseals {
        let result = sqlx::query(
            "UPDATE devices SET bindings = ? WHERE tenant_id = ? AND id = ? AND CAST(bindings AS BINARY) = CAST(? AS BINARY)",
        )
        .bind(&r.blob).bind(&r.tenant).bind(&r.id).bind(&r.stored)
        .execute(pool)
        .await
        .map(|done| done.rows_affected());
        note_reseal(result, &r);
    }
}
