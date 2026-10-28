//! The retention sweep of the postgres device store.

use sqlx::PgPool;

use crate::device::storage::sql_common::{SqlDeviceStoreError, SweepCutoffs};
use crate::device::store::SweepCounts;

/// Run the three retention transitions against `tenant`'s rows.
pub(super) async fn run(
    pool: &PgPool,
    tenant: &str,
    cutoffs: &SweepCutoffs,
) -> Result<SweepCounts, SqlDeviceStoreError> {
    // All three transitions are pure SQL UPDATE/DELETE with
    // affected-row counts; no row reads in user space, no
    // per-row roundtrips.

    // Stage 0: a revoked row saved without a revocation time (by an older
    // version) starts its grace now, so stage 3 can age it out. Not counted:
    // no level changes.
    sqlx::query(
        "UPDATE devices SET revoked_at = $2 WHERE tenant_id = $1 AND trust_level = 'Revoked' AND revoked_at IS NULL",
    )
    .bind(tenant)
    .bind(cutoffs.now)
    .execute(pool)
    .await?;

    // Stage 1: Trusted → Seen, stamped with the demotion. A row is
    // moved one level per sweep, so a demoted row gets its whole
    // Seen window from `now`.
    let trusted_demoted = sqlx::query(
        "UPDATE devices SET trust_level = 'Seen', demoted_at = $3 \
         WHERE tenant_id = $1 \
           AND trust_level = 'Trusted' \
           AND last_seen_at < $2",
    )
    .bind(tenant)
    .bind(cutoffs.trusted)
    .bind(cutoffs.now)
    .execute(pool)
    .await?
    .rows_affected();

    // Stage 2: Seen → Revoked once `seen_idle` has passed since the
    // later of the last sighting and the demotion. A row demoted a
    // moment ago has `demoted_at = now`, which is not before the
    // cutoff, so it is not revoked by the sweep that demoted it.
    let seen_demoted = sqlx::query(
        "UPDATE devices SET trust_level = 'Revoked', revoked_at = $3, demoted_at = NULL \
         WHERE tenant_id = $1 \
           AND trust_level = 'Seen' \
           AND last_seen_at < $2 \
           AND (demoted_at IS NULL OR demoted_at < $2)",
    )
    .bind(tenant)
    .bind(cutoffs.seen)
    .bind(cutoffs.now)
    .execute(pool)
    .await?
    .rows_affected();

    // Stage 3: Revoked → purge. ON DELETE CASCADE handles
    // the `device_bindings_refresh` rows.
    //
    // We compare against `revoked_at`, NOT `last_seen_at`, so
    // a device just demoted in stage 2 (revoked_at = now) is
    // NOT eligible for purge in this sweep; its grace clock
    // starts now and a future sweep finishes the job.
    let purged = sqlx::query(
        "DELETE FROM devices \
         WHERE tenant_id = $1 \
           AND trust_level = 'Revoked' \
           AND revoked_at IS NOT NULL \
           AND revoked_at < $2",
    )
    .bind(tenant)
    .bind(cutoffs.grace)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(SweepCounts {
        trusted_to_seen: trusted_demoted,
        seen_to_revoked: seen_demoted,
        revoked_purged: purged,
    })
}
