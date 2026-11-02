//! The device store operations that take more than one statement, written
//! once over the statements each SQL engine supplies.
//!
//! A backend implements [`DeviceSql`]: one method per statement, holding
//! only that engine's SQL, placeholders and bind order, plus the hooks that
//! serialise a create (an immediate transaction, an advisory lock, a named
//! lock). The order of the statements, the transactions around them and the
//! decisions taken between them live here, so the three stores cannot drift
//! apart in what an operation does.

use std::future::Future;

use sqlx::{Database, Pool, Transaction};

use super::{
    BindingsCodec, BindingsSwap, DeviceRow, DeviceWrite, GuardedTrustWrite, Reseal,
    SqlDeviceStoreError, SwapPlan, SweepCutoffs, TRANSITION_ATTEMPTS, bindings_update_after_miss,
    claim_after_miss, decode_optional, note_reseal, parse_stored_trust, plan_bindings_swap,
    sighting_level, transition_after_miss,
};
use crate::device::storage::sweep_batches::{SWEEP_BATCH, in_batches};
use crate::device::store::{BindingsUpdate, OwnerClaim, SweepCounts, TrustTransition};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel};

/// The statements of one SQL engine that the multi-statement device
/// operations are built from. Each method runs exactly one statement (or,
/// for the create hooks, takes or releases one lock).
pub(crate) trait DeviceSql: Send + Sync + 'static {
    /// The engine.
    type Db: Database;

    /// Begin the transaction a create of `device` runs in, serialised
    /// against every other create of its `(tenant, fingerprint, owner)`.
    fn begin_create(
        pool: &Pool<Self::Db>,
        device: &Device,
    ) -> impl Future<Output = Result<Transaction<'static, Self::Db>, SqlDeviceStoreError>> + Send;

    /// Release what [`begin_create`](Self::begin_create) took beyond the
    /// transaction itself; runs before the transaction ends, on every path.
    fn end_create(
        tx: &mut Transaction<'_, Self::Db>,
        device: &Device,
    ) -> impl Future<Output = Result<(), sqlx::Error>> + Send;

    /// The live row of `w`'s create key, newest sighting first, then the
    /// smaller id.
    fn live_of_key(
        tx: &mut Transaction<'_, Self::Db>,
        w: &DeviceWrite,
    ) -> impl Future<Output = Result<Option<DeviceRow>, sqlx::Error>> + Send;

    /// Insert `w` as a new row.
    fn insert(
        tx: &mut Transaction<'_, Self::Db>,
        w: &DeviceWrite,
    ) -> impl Future<Output = Result<(), sqlx::Error>> + Send;

    /// Insert `w`, or replace the stored row unless it is revoked, in one
    /// statement; `true` when the row now holds this write.
    fn upsert(
        tx: &mut Transaction<'_, Self::Db>,
        w: &DeviceWrite,
    ) -> impl Future<Output = Result<bool, sqlx::Error>> + Send;

    /// Replace a device's refresh-family index rows with `family_ids`
    /// (distinct already; the insert is idempotent as well).
    fn rewrite_family_index(
        tx: &mut Transaction<'_, Self::Db>,
        tenant: &str,
        device_id: &str,
        family_ids: &[String],
    ) -> impl Future<Output = Result<(), sqlx::Error>> + Send;

    /// The `(trust_level, bindings)` of a row.
    fn trust_and_bindings(
        pool: &Pool<Self::Db>,
        tenant: &str,
        device_id: &str,
    ) -> impl Future<Output = Result<Option<(String, String)>, sqlx::Error>> + Send;

    /// Write `swap.blob` where the row is not revoked and its bindings are
    /// still `swap.stored`; the number of rows written.
    fn swap_bindings(
        tx: &mut Transaction<'_, Self::Db>,
        tenant: &str,
        device_id: &str,
        swap: &BindingsSwap,
    ) -> impl Future<Output = Result<u64, sqlx::Error>> + Send;

    /// The stored `trust_level` of a row.
    fn trust_level(
        pool: &Pool<Self::Db>,
        tenant: &str,
        device_id: &str,
    ) -> impl Future<Output = Result<Option<String>, sqlx::Error>> + Send;

    /// Move `last_seen_at` forward to `ts` on a row that is not revoked.
    fn touch(
        pool: &Pool<Self::Db>,
        tenant: &str,
        device_id: &str,
        ts: i64,
    ) -> impl Future<Output = Result<(), sqlx::Error>> + Send;

    /// Apply `w` where the row is at `w.expected`; the number of rows
    /// written.
    fn guarded_trust(
        pool: &Pool<Self::Db>,
        tenant: &str,
        device_id: &str,
        w: &GuardedTrustWrite,
    ) -> impl Future<Output = Result<u64, sqlx::Error>> + Send;

    /// Set the owner to `user` where the row has none; the number of rows
    /// written.
    fn claim(
        pool: &Pool<Self::Db>,
        tenant: &str,
        device_id: &str,
        user: &str,
    ) -> impl Future<Output = Result<u64, sqlx::Error>> + Send;

    /// The owner of a row (`None` when the row is absent).
    fn owner(
        pool: &Pool<Self::Db>,
        tenant: &str,
        device_id: &str,
    ) -> impl Future<Output = Result<Option<Option<String>>, sqlx::Error>> + Send;

    /// Replace a stale bindings blob where the row still holds the bytes
    /// that were read; the number of rows written.
    fn reseal(
        pool: &Pool<Self::Db>,
        reseal: &Reseal,
    ) -> impl Future<Output = Result<u64, sqlx::Error>> + Send;

    /// Apply one retention stage to at most `batch` of `tenant`'s rows; the
    /// number of rows changed.
    fn sweep_stage(
        pool: &Pool<Self::Db>,
        stage: SweepStage,
        tenant: &str,
        cutoffs: &SweepCutoffs,
        batch: i64,
    ) -> impl Future<Output = Result<u64, sqlx::Error>> + Send;
}

/// The stages of the retention sweep, in the order a sweep runs them. Every
/// stage moves the rows it touches out of its own predicate, so a stage run
/// in batches ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SweepStage {
    /// A revoked row saved without a revocation time (by an older version)
    /// starts its grace at `now`, so the purge can age it out. Not counted:
    /// no level changes.
    StampRevoked,
    /// `Trusted` to `Seen` once `trusted_idle` has passed since the last
    /// sighting, stamped with the demotion, so a demoted row gets its whole
    /// `Seen` window from `now`.
    DemoteTrusted,
    /// `Seen` to `Revoked` once `seen_idle` has passed since the later of
    /// the last sighting and the demotion. A row demoted by this sweep has
    /// `demoted_at = now`, which is not before the cutoff.
    RevokeSeen,
    /// Delete revoked rows whose grace has passed since `revoked_at` (not
    /// `last_seen_at`, so a row revoked by this sweep is kept for its
    /// grace). The family index rows go with them by `ON DELETE CASCADE`.
    Purge,
}

/// Replace each stale bindings blob read by a lookup with its current-format
/// form. Every write is conditional on the exact bytes that were read, so a
/// save that landed since is never overwritten, and a failure is logged
/// without failing the read.
pub(crate) async fn reseal_rows<D: DeviceSql>(
    pool: &Pool<D::Db>,
    reseals: impl IntoIterator<Item = Reseal>,
) {
    for r in reseals {
        note_reseal(D::reseal(pool, &r).await, &r);
    }
}

/// Current trust level of a device row, `None` when the row is absent.
pub(crate) async fn fetch_trust_level<D: DeviceSql>(
    pool: &Pool<D::Db>,
    tenant: &str,
    device_id: &str,
) -> Result<Option<DeviceTrustLevel>, SqlDeviceStoreError> {
    parse_stored_trust(D::trust_level(pool, tenant, device_id).await?)
}

/// `save`: upsert `device` (already passed through `for_save`) and rewrite
/// its refresh-family index in one transaction, so a concurrent
/// `find_by_refresh_family` sees the index before or after, never half of
/// it. A stored revoked row is left as it is: the upsert itself refuses it,
/// in the same statement as the write.
pub(crate) async fn save<D: DeviceSql>(
    pool: Pool<D::Db>,
    codec: BindingsCodec,
    device: Device,
) -> Result<(), SqlDeviceStoreError> {
    let w = DeviceWrite::new(&codec, &device)?;
    let mut tx = pool.begin().await?;
    if !D::upsert(&mut tx, &w).await? {
        tx.rollback().await?;
        return Ok(());
    }
    D::rewrite_family_index(&mut tx, &w.tenant, &w.id, &w.family_ids).await?;
    tx.commit().await?;
    Ok(())
}

/// `create_or_find`: the live device of `device`'s create key when there is
/// one, or `device` (already passed through `for_save`) inserted with its
/// family index, serialised against every other create of that key.
pub(crate) async fn create_or_find<D: DeviceSql>(
    pool: Pool<D::Db>,
    codec: BindingsCodec,
    device: Device,
) -> Result<Device, SqlDeviceStoreError> {
    let w = DeviceWrite::new(&codec, &device)?;
    let mut tx = D::begin_create(&pool, &device).await?;
    let outcome = create_locked::<D>(&codec, &mut tx, &w).await;
    let released = D::end_create(&mut tx, &device).await;
    let (existing, reseal) = outcome?;
    released?;
    match existing {
        Some(existing) => {
            tx.rollback().await?;
            reseal_rows::<D>(&pool, reseal).await;
            Ok(existing)
        }
        None => {
            tx.commit().await?;
            Ok(device)
        }
    }
}

/// The body of `create_or_find` under the create lock: the existing live row
/// of the key when there is one (nothing is written), or the insert of `w`
/// and its family index.
async fn create_locked<D: DeviceSql>(
    codec: &BindingsCodec,
    tx: &mut Transaction<'static, D::Db>,
    w: &DeviceWrite,
) -> Result<(Option<Device>, Option<Reseal>), SqlDeviceStoreError> {
    if let (Some(existing), reseal) = decode_optional(codec, D::live_of_key(tx, w).await?)? {
        return Ok((Some(existing), reseal));
    }
    D::insert(tx, w).await?;
    D::rewrite_family_index(tx, &w.tenant, &w.id, &w.family_ids).await?;
    Ok((None, None))
}

/// `replace_bindings`: swap a device's bindings from `expected` to
/// `bindings` while the row still holds what was read, and rewrite its
/// refresh-family index in the same transaction.
pub(crate) async fn replace_bindings<D: DeviceSql>(
    pool: Pool<D::Db>,
    codec: BindingsCodec,
    tenant: String,
    device_id: String,
    expected: Vec<DeviceBinding>,
    bindings: Vec<DeviceBinding>,
) -> Result<BindingsUpdate, SqlDeviceStoreError> {
    let row = D::trust_and_bindings(&pool, &tenant, &device_id).await?;
    let swap = match plan_bindings_swap(&codec, &tenant, &device_id, row, &expected, &bindings)? {
        SwapPlan::Settled(outcome) => return Ok(outcome),
        SwapPlan::Write(swap) => swap,
    };
    let mut tx = pool.begin().await?;
    // Only the bindings column is written, only on a row that is not
    // Revoked, and only while it still holds the bytes that were read: the
    // engine evaluates the conditions and the write together, so a
    // revocation cannot be undone, a revoked device cannot gain a binding,
    // and a concurrent bindings edit makes this match no row instead of
    // being overwritten.
    if D::swap_bindings(&mut tx, &tenant, &device_id, &swap).await? == 0 {
        // Nothing written. The transaction is ended before the re-read,
        // which needs a pooled connection of its own: with a one-connection
        // pool it would otherwise wait for the connection this transaction
        // still holds.
        tx.rollback().await?;
        let current = fetch_trust_level::<D>(&pool, &tenant, &device_id).await?;
        return Ok(bindings_update_after_miss(current));
    }
    D::rewrite_family_index(&mut tx, &tenant, &device_id, &swap.family_ids).await?;
    tx.commit().await?;
    Ok(BindingsUpdate::Written)
}

/// `record_sighting`: move `last_seen_at` forward, then report the level the
/// row has now. Revoked means the sighting did not touch it; a missing row
/// is a missing device.
pub(crate) async fn record_sighting<D: DeviceSql>(
    pool: Pool<D::Db>,
    tenant: String,
    device_id: String,
    ts: i64,
) -> Result<DeviceTrustLevel, SqlDeviceStoreError> {
    D::touch(&pool, &tenant, &device_id, ts).await?;
    let level = fetch_trust_level::<D>(&pool, &tenant, &device_id).await?;
    sighting_level(level, tenant, device_id)
}

/// `set_trust_level_if`: one conditional `UPDATE` per attempt. The engine
/// checks the current level and writes in a single statement, so a
/// revocation that lands first makes this match no row instead of being
/// overwritten.
pub(crate) async fn set_trust_level_if<D: DeviceSql>(
    pool: Pool<D::Db>,
    tenant: String,
    device_id: String,
    expected: DeviceTrustLevel,
    w: GuardedTrustWrite,
) -> Result<TrustTransition, SqlDeviceStoreError> {
    for _ in 0..TRANSITION_ATTEMPTS {
        if D::guarded_trust(&pool, &tenant, &device_id, &w).await? > 0 {
            return Ok(TrustTransition::Applied);
        }
        let current = fetch_trust_level::<D>(&pool, &tenant, &device_id).await?;
        if let Some(outcome) = transition_after_miss(current, expected) {
            return Ok(outcome);
        }
        // The row is at `expected` again: the write lost a race with a
        // change that has since been undone. Try it again.
    }
    // Every attempt lost a race: the row was never found at another level,
    // so the change is neither applied nor refused.
    Err(SqlDeviceStoreError::Contended {
        tenant_id: tenant,
        device_id,
    })
}

/// `claim_owner`: one conditional `UPDATE` sets the owner only while there
/// is none, so of two users racing for an unowned device exactly one matches
/// a row; the other reads who won.
pub(crate) async fn claim_owner<D: DeviceSql>(
    pool: Pool<D::Db>,
    tenant: String,
    device_id: String,
    user: String,
) -> Result<OwnerClaim, SqlDeviceStoreError> {
    if D::claim(&pool, &tenant, &device_id, &user).await? > 0 {
        return Ok(OwnerClaim::Claimed);
    }
    let owner = D::owner(&pool, &tenant, &device_id).await?;
    Ok(claim_after_miss(owner, &user))
}

/// `sweep`: the retention stages against `tenant`'s rows, each in batches of
/// [`SWEEP_BATCH`] rows, so no statement holds the locks of a whole tenant's
/// table.
pub(crate) async fn sweep<D: DeviceSql>(
    pool: Pool<D::Db>,
    tenant: String,
    cutoffs: SweepCutoffs,
) -> Result<SweepCounts, SqlDeviceStoreError> {
    sweep_in_batches::<D>(&pool, &tenant, &cutoffs, SWEEP_BATCH)
        .await
        .map(|(counts, _)| counts)
}

/// [`sweep`] with the batch size chosen, also returning how many statements
/// ran.
pub(crate) async fn sweep_in_batches<D: DeviceSql>(
    pool: &Pool<D::Db>,
    tenant: &str,
    cutoffs: &SweepCutoffs,
    batch: i64,
) -> Result<(SweepCounts, u32), SqlDeviceStoreError> {
    let stage = |stage| {
        in_batches(batch, move || {
            D::sweep_stage(pool, stage, tenant, cutoffs, batch)
        })
    };
    let (_, s0) = stage(SweepStage::StampRevoked).await?;
    let (trusted_to_seen, s1) = stage(SweepStage::DemoteTrusted).await?;
    let (seen_to_revoked, s2) = stage(SweepStage::RevokeSeen).await?;
    let (revoked_purged, s3) = stage(SweepStage::Purge).await?;
    Ok((
        SweepCounts {
            trusted_to_seen,
            seen_to_revoked,
            revoked_purged,
        },
        s0 + s1 + s2 + s3,
    ))
}
