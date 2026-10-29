//! The retention sweep of the postgres device store.
//!
//! Each stage runs in batches of [`SWEEP_BATCH`] rows (see
//! [`sweep_batches`](crate::device::storage::sweep_batches)), so no statement
//! holds the locks of a whole tenant's table.

use sqlx::PgPool;

use crate::device::storage::sql_common::{SqlDeviceStoreError, SweepCutoffs};
use crate::device::storage::sweep_batches::{SWEEP_BATCH, in_batches};
use crate::device::store::SweepCounts;

/// Run the retention transitions against `tenant`'s rows.
pub(super) async fn run(
    pool: &PgPool,
    tenant: &str,
    cutoffs: &SweepCutoffs,
) -> Result<SweepCounts, SqlDeviceStoreError> {
    run_in_batches(pool, tenant, cutoffs, SWEEP_BATCH)
        .await
        .map(|(counts, _)| counts)
}

/// [`run`] with the batch size chosen, also returning how many statements ran.
pub(super) async fn run_in_batches(
    pool: &PgPool,
    tenant: &str,
    cutoffs: &SweepCutoffs,
    batch: i64,
) -> Result<(SweepCounts, u32), SqlDeviceStoreError> {
    // Stage 0: a revoked row saved without a revocation time (by an older
    // version) starts its grace now, so stage 3 can age it out. Not counted:
    // no level changes.
    let (_, s0) = in_batches(batch, || async move {
        sqlx::query(
            "UPDATE devices SET revoked_at = $2 WHERE tenant_id = $1 AND id IN (SELECT id FROM devices WHERE tenant_id = $1 AND trust_level = 'Revoked' AND revoked_at IS NULL LIMIT $3)",
        )
        .bind(tenant)
        .bind(cutoffs.now)
        .bind(batch)
        .execute(pool)
        .await
        .map(|done| done.rows_affected())
    })
    .await?;

    // Stage 1: Trusted → Seen, stamped with the demotion. A row is
    // moved one level per sweep, so a demoted row gets its whole
    // Seen window from `now`.
    let (trusted_demoted, s1) = in_batches(batch, || async move {
        sqlx::query(
            "UPDATE devices SET trust_level = 'Seen', demoted_at = $3 WHERE tenant_id = $1 AND id IN (SELECT id FROM devices WHERE tenant_id = $1 AND trust_level = 'Trusted' AND last_seen_at < $2 LIMIT $4)",
        )
        .bind(tenant)
        .bind(cutoffs.trusted)
        .bind(cutoffs.now)
        .bind(batch)
        .execute(pool)
        .await
        .map(|done| done.rows_affected())
    })
    .await?;

    // Stage 2: Seen → Revoked once `seen_idle` has passed since the
    // later of the last sighting and the demotion. A row demoted a
    // moment ago has `demoted_at = now`, which is not before the
    // cutoff, so it is not revoked by the sweep that demoted it.
    let (seen_demoted, s2) = in_batches(batch, || async move {
        sqlx::query(
            "UPDATE devices SET trust_level = 'Revoked', revoked_at = $3, demoted_at = NULL WHERE tenant_id = $1 AND id IN (SELECT id FROM devices WHERE tenant_id = $1 AND trust_level = 'Seen' AND last_seen_at < $2 AND (demoted_at IS NULL OR demoted_at < $2) LIMIT $4)",
        )
        .bind(tenant)
        .bind(cutoffs.seen)
        .bind(cutoffs.now)
        .bind(batch)
        .execute(pool)
        .await
        .map(|done| done.rows_affected())
    })
    .await?;

    // Stage 3: Revoked → purge. ON DELETE CASCADE handles
    // the `device_bindings_refresh` rows.
    //
    // We compare against `revoked_at`, NOT `last_seen_at`, so
    // a device just demoted in stage 2 (revoked_at = now) is
    // NOT eligible for purge in this sweep; its grace clock
    // starts now and a future sweep finishes the job.
    let (purged, s3) = in_batches(batch, || async move {
        sqlx::query(
            "DELETE FROM devices WHERE tenant_id = $1 AND id IN (SELECT id FROM devices WHERE tenant_id = $1 AND trust_level = 'Revoked' AND revoked_at IS NOT NULL AND revoked_at < $2 LIMIT $3)",
        )
        .bind(tenant)
        .bind(cutoffs.grace)
        .bind(batch)
        .execute(pool)
        .await
        .map(|done| done.rows_affected())
    })
    .await?;

    Ok((
        SweepCounts {
            trusted_to_seen: trusted_demoted,
            seen_to_revoked: seen_demoted,
            revoked_purged: purged,
        },
        s0 + s1 + s2 + s3,
    ))
}
