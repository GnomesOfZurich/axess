//! The PostgreSQL statements the multi-statement device operations
//! ([`ops`](crate::device::storage::sql_common::ops)) are built from.

use sqlx::{PgPool, Postgres, Transaction};

use crate::device::storage::sql_common::ops::{DeviceSql, SweepStage};
use crate::device::storage::sql_common::{
    BindingsSwap, DeviceRow, DeviceWrite, FAMILY_INSERT_CHUNK, GuardedTrustWrite, Reseal,
    SqlDeviceStoreError, SweepCutoffs, bind_device_write, create_lock_name, push_family_rows,
    select_devices,
};
use crate::device::types::Device;

/// The PostgreSQL dialect of the device store.
pub(super) struct PostgresSql;

impl DeviceSql for PostgresSql {
    type Db = Postgres;

    async fn begin_create(
        pool: &PgPool,
        device: &Device,
    ) -> Result<Transaction<'static, Postgres>, SqlDeviceStoreError> {
        // A transaction-scoped advisory lock on the create key serialises
        // the read and the insert against every other create of that key;
        // it is released with the transaction on every path.
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(create_lock_name(device))
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    async fn end_create(
        _tx: &mut Transaction<'_, Postgres>,
        _device: &Device,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn live_of_key(
        tx: &mut Transaction<'_, Postgres>,
        w: &DeviceWrite,
    ) -> Result<Option<DeviceRow>, sqlx::Error> {
        sqlx::query_as(select_devices!(
            "WHERE tenant_id = $1 AND fingerprint_hash = $2 AND user_id IS NOT DISTINCT FROM $3 \
               AND trust_level <> 'Revoked' \
             ORDER BY last_seen_at DESC, id ASC LIMIT 1"
        ))
        .bind(&w.tenant)
        .bind(&w.fingerprint)
        .bind(w.user_id.as_deref())
        .fetch_optional(&mut **tx)
        .await
    }

    async fn insert(
        tx: &mut Transaction<'_, Postgres>,
        w: &DeviceWrite,
    ) -> Result<(), sqlx::Error> {
        bind_device_write!(
            sqlx::query(
                "INSERT INTO devices \
                     (tenant_id, id, user_id, trust_level, fingerprint_hash, \
                      first_seen_at, last_seen_at, revoked_at, demoted_at, bindings) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            ),
            w
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn upsert(
        tx: &mut Transaction<'_, Postgres>,
        w: &DeviceWrite,
    ) -> Result<bool, sqlx::Error> {
        // The update half applies only to a row that is not revoked; the
        // conflicting row is locked and judged in the same statement as the
        // write.
        let written = bind_device_write!(
            sqlx::query(
                "INSERT INTO devices \
                     (tenant_id, id, user_id, trust_level, fingerprint_hash, \
                      first_seen_at, last_seen_at, revoked_at, demoted_at, bindings) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 ON CONFLICT (tenant_id, id) DO UPDATE SET \
                     user_id          = EXCLUDED.user_id, \
                     trust_level      = EXCLUDED.trust_level, \
                     fingerprint_hash = EXCLUDED.fingerprint_hash, \
                     first_seen_at    = EXCLUDED.first_seen_at, \
                     last_seen_at     = EXCLUDED.last_seen_at, \
                     revoked_at       = EXCLUDED.revoked_at, \
                     demoted_at       = EXCLUDED.demoted_at, \
                     bindings         = EXCLUDED.bindings \
                 WHERE devices.trust_level <> 'Revoked'",
            ),
            w
        )
        .execute(&mut **tx)
        .await?
        .rows_affected();
        Ok(written > 0)
    }

    async fn rewrite_family_index(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
        device_id: &str,
        family_ids: &[String],
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM device_bindings_refresh WHERE tenant_id = $1 AND device_id = $2")
            .bind(tenant)
            .bind(device_id)
            .execute(&mut **tx)
            .await?;
        // One multi-row insert per chunk keeps a device with many families
        // to a handful of statements, under the bind-parameter cap.
        for chunk in family_ids.chunks(FAMILY_INSERT_CHUNK) {
            let mut insert = sqlx::QueryBuilder::<Postgres>::new(
                "INSERT INTO device_bindings_refresh (tenant_id, device_id, family_id) ",
            );
            push_family_rows(&mut insert, chunk, tenant, device_id);
            insert.push(" ON CONFLICT DO NOTHING");
            insert.build().execute(&mut **tx).await?;
        }
        Ok(())
    }

    async fn trust_and_bindings(
        pool: &PgPool,
        tenant: &str,
        device_id: &str,
    ) -> Result<Option<(String, String)>, sqlx::Error> {
        sqlx::query_as("SELECT trust_level, bindings FROM devices WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(device_id)
            .fetch_optional(pool)
            .await
    }

    async fn swap_bindings(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
        device_id: &str,
        swap: &BindingsSwap,
    ) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query(
            "UPDATE devices SET bindings = $3 \
             WHERE tenant_id = $1 AND id = $2 AND trust_level <> 'Revoked' AND bindings = $4",
        )
        .bind(tenant)
        .bind(device_id)
        .bind(&swap.blob)
        .bind(&swap.stored)
        .execute(&mut **tx)
        .await?
        .rows_affected())
    }

    async fn trust_level(
        pool: &PgPool,
        tenant: &str,
        device_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar("SELECT trust_level FROM devices WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(device_id)
            .fetch_optional(pool)
            .await
    }

    async fn touch(
        pool: &PgPool,
        tenant: &str,
        device_id: &str,
        ts: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE devices SET last_seen_at = CASE \
                 WHEN trust_level <> 'Revoked' AND last_seen_at < $3 THEN $3 \
                 ELSE last_seen_at END \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(device_id)
        .bind(ts)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn guarded_trust(
        pool: &PgPool,
        tenant: &str,
        device_id: &str,
        w: &GuardedTrustWrite,
    ) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query(
            "UPDATE devices SET trust_level = $4, \
                    revoked_at = CASE WHEN $3::text = $4::text THEN revoked_at ELSE $5::bigint END, \
                    demoted_at = CASE WHEN $6::bigint = 1 THEN demoted_at ELSE $7::bigint END \
             WHERE tenant_id = $1 AND id = $2 AND trust_level = $3",
        )
        .bind(tenant)
        .bind(device_id)
        .bind(w.expected)
        .bind(w.new)
        .bind(w.revoked_at)
        .bind(w.keep_demoted)
        .bind(w.demoted_at)
        .execute(pool)
        .await?
        .rows_affected())
    }

    async fn claim(
        pool: &PgPool,
        tenant: &str,
        device_id: &str,
        user: &str,
    ) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query(
            "UPDATE devices SET user_id = $3 \
             WHERE tenant_id = $1 AND id = $2 AND user_id IS NULL",
        )
        .bind(tenant)
        .bind(device_id)
        .bind(user)
        .execute(pool)
        .await?
        .rows_affected())
    }

    async fn owner(
        pool: &PgPool,
        tenant: &str,
        device_id: &str,
    ) -> Result<Option<Option<String>>, sqlx::Error> {
        sqlx::query_scalar("SELECT user_id FROM devices WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(device_id)
            .fetch_optional(pool)
            .await
    }

    async fn reseal(pool: &PgPool, r: &Reseal) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query(
            "UPDATE devices SET bindings = $3 WHERE tenant_id = $1 AND id = $2 AND bindings = $4",
        )
        .bind(&r.tenant)
        .bind(&r.id)
        .bind(&r.blob)
        .bind(&r.stored)
        .execute(pool)
        .await?
        .rows_affected())
    }

    async fn sweep_stage(
        pool: &PgPool,
        stage: SweepStage,
        tenant: &str,
        cutoffs: &SweepCutoffs,
        batch: i64,
    ) -> Result<u64, sqlx::Error> {
        let query = match stage {
            SweepStage::StampRevoked => sqlx::query(
                "UPDATE devices SET revoked_at = $2 WHERE tenant_id = $1 AND id IN (SELECT id FROM devices WHERE tenant_id = $1 AND trust_level = 'Revoked' AND revoked_at IS NULL LIMIT $3)",
            )
            .bind(tenant)
            .bind(cutoffs.now)
            .bind(batch),
            SweepStage::DemoteTrusted => sqlx::query(
                "UPDATE devices SET trust_level = 'Seen', demoted_at = $3 WHERE tenant_id = $1 AND id IN (SELECT id FROM devices WHERE tenant_id = $1 AND trust_level = 'Trusted' AND last_seen_at < $2 LIMIT $4)",
            )
            .bind(tenant)
            .bind(cutoffs.trusted)
            .bind(cutoffs.now)
            .bind(batch),
            SweepStage::RevokeSeen => sqlx::query(
                "UPDATE devices SET trust_level = 'Revoked', revoked_at = $3, demoted_at = NULL WHERE tenant_id = $1 AND id IN (SELECT id FROM devices WHERE tenant_id = $1 AND trust_level = 'Seen' AND last_seen_at < $2 AND (demoted_at IS NULL OR demoted_at < $2) LIMIT $4)",
            )
            .bind(tenant)
            .bind(cutoffs.seen)
            .bind(cutoffs.now)
            .bind(batch),
            SweepStage::Purge => sqlx::query(
                "DELETE FROM devices WHERE tenant_id = $1 AND id IN (SELECT id FROM devices WHERE tenant_id = $1 AND trust_level = 'Revoked' AND revoked_at IS NOT NULL AND revoked_at < $2 LIMIT $3)",
            )
            .bind(tenant)
            .bind(cutoffs.grace)
            .bind(batch),
        };
        Ok(query.execute(pool).await?.rows_affected())
    }
}
