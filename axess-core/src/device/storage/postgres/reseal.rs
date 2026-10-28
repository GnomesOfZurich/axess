//! Re-seal of stale bindings blobs found by a read.

use sqlx::PgPool;

use crate::device::storage::sql_common::{Reseal, note_reseal};

/// Replace each stale bindings blob read by a lookup with its current-format
/// form. Every write is conditional on the exact bytes that were read, so a
/// save that landed since is never overwritten, and a failure is logged
/// without failing the read.
pub(super) async fn reseal_rows(pool: &PgPool, reseals: impl IntoIterator<Item = Reseal>) {
    for r in reseals {
        let result = sqlx::query(
            "UPDATE devices SET bindings = $3 WHERE tenant_id = $1 AND id = $2 AND bindings = $4",
        )
        .bind(&r.tenant)
        .bind(&r.id)
        .bind(&r.blob)
        .bind(&r.stored)
        .execute(pool)
        .await
        .map(|done| done.rows_affected());
        note_reseal(result, &r);
    }
}
