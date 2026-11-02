//! The MySQL statements the multi-statement device operations
//! ([`ops`](crate::device::storage::sql_common::ops)) are built from.
//!
//! MySQL applies a single-table `UPDATE`'s assignments left to right and a
//! later one sees the columns an earlier one changed, so `trust_level`,
//! which the other assignments read, is always assigned last.

use sqlx::{MySql, MySqlPool, Transaction};

use crate::device::storage::sql_common::ops::{DeviceSql, SweepStage};
use crate::device::storage::sql_common::{
    BindingsSwap, DeviceRow, DeviceWrite, FAMILY_INSERT_CHUNK, GuardedTrustWrite, Reseal,
    SqlDeviceStoreError, SweepCutoffs, bind_device_write, create_lock_name, index_follows_write,
    push_family_rows, select_devices,
};
use crate::device::types::Device;

/// How long a create waits for the named lock of its key before it fails;
/// a holder is one short transaction, so a longer wait means a stuck one.
const CREATE_LOCK_WAIT_SECS: i64 = 5;

/// The MySQL dialect of the device store.
pub(super) struct MysqlSql;

impl DeviceSql for MysqlSql {
    type Db = MySql;

    async fn begin_create(
        pool: &MySqlPool,
        device: &Device,
    ) -> Result<Transaction<'static, MySql>, SqlDeviceStoreError> {
        // A named lock on the create key serialises the read and the insert
        // against every other create of that key. The lock belongs to the
        // connection, not the transaction, so `end_create` releases it on
        // every path before the connection goes back to the pool.
        let mut tx = pool.begin().await?;
        let taken: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, ?)")
            .bind(create_lock_name(device))
            .bind(CREATE_LOCK_WAIT_SECS)
            .fetch_one(&mut *tx)
            .await?;
        if taken != Some(1) {
            return Err(SqlDeviceStoreError::CreateLockTimeout {
                tenant_id: device.tenant_id.to_string(),
            });
        }
        Ok(tx)
    }

    async fn end_create(
        tx: &mut Transaction<'_, MySql>,
        device: &Device,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DO RELEASE_LOCK(?)")
            .bind(create_lock_name(device))
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn live_of_key(
        tx: &mut Transaction<'_, MySql>,
        w: &DeviceWrite,
    ) -> Result<Option<DeviceRow>, sqlx::Error> {
        sqlx::query_as(select_devices!(
            "WHERE tenant_id = ? AND fingerprint_hash = ? AND user_id <=> ? \
               AND trust_level <> 'Revoked' \
             ORDER BY last_seen_at DESC, id ASC LIMIT 1"
        ))
        .bind(&w.tenant)
        .bind(&w.fingerprint)
        .bind(w.user_id.as_deref())
        .fetch_optional(&mut **tx)
        .await
    }

    async fn insert(tx: &mut Transaction<'_, MySql>, w: &DeviceWrite) -> Result<(), sqlx::Error> {
        bind_device_write!(
            sqlx::query(
                "INSERT INTO devices \
                     (tenant_id, id, user_id, trust_level, fingerprint_hash, \
                      first_seen_at, last_seen_at, revoked_at, demoted_at, bindings) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ),
            w
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn upsert(tx: &mut Transaction<'_, MySql>, w: &DeviceWrite) -> Result<bool, sqlx::Error> {
        // Every assignment keeps the stored value of a revoked row, in the
        // same statement as the write. `VALUES(col)` reads the value that
        // would have been inserted; it works back to MySQL 5.7 and MariaDB
        // 10.x, where the `AS new` row alias is MySQL 8.0.20+ only.
        bind_device_write!(
            sqlx::query(
                "INSERT INTO devices \
                     (tenant_id, id, user_id, trust_level, fingerprint_hash, \
                      first_seen_at, last_seen_at, revoked_at, demoted_at, bindings) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                     user_id          = IF(trust_level = 'Revoked', user_id, VALUES(user_id)), \
                     fingerprint_hash = IF(trust_level = 'Revoked', fingerprint_hash, VALUES(fingerprint_hash)), \
                     first_seen_at    = IF(trust_level = 'Revoked', first_seen_at, VALUES(first_seen_at)), \
                     last_seen_at     = IF(trust_level = 'Revoked', last_seen_at, VALUES(last_seen_at)), \
                     revoked_at       = IF(trust_level = 'Revoked', revoked_at, VALUES(revoked_at)), \
                     demoted_at       = IF(trust_level = 'Revoked', demoted_at, VALUES(demoted_at)), \
                     bindings         = IF(trust_level = 'Revoked', bindings, VALUES(bindings)), \
                     trust_level      = IF(trust_level = 'Revoked', trust_level, VALUES(trust_level))",
            ),
            w
        )
        .execute(&mut **tx)
        .await?;
        // The affected-row count cannot tell whether the row now holds this
        // write: the driver connects with CLIENT_FOUND_ROWS, under which an
        // insert and a revoked row kept as it was both count one. The upsert
        // locked the row, so this read sees what it left; ciphertext differs
        // on every encode, so the stored bytes are this write's own only when
        // the upsert wrote them.
        let stored: Option<String> =
            sqlx::query_scalar("SELECT bindings FROM devices WHERE tenant_id = ? AND id = ?")
                .bind(&w.tenant)
                .bind(&w.id)
                .fetch_optional(&mut **tx)
                .await?;
        Ok(index_follows_write(stored.as_deref(), &w.bindings))
    }

    async fn rewrite_family_index(
        tx: &mut Transaction<'_, MySql>,
        tenant: &str,
        device_id: &str,
        family_ids: &[String],
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM device_bindings_refresh WHERE tenant_id = ? AND device_id = ?")
            .bind(tenant)
            .bind(device_id)
            .execute(&mut **tx)
            .await?;
        // One multi-row insert per chunk keeps a device with many families
        // to a handful of statements, under the bind-parameter cap.
        for chunk in family_ids.chunks(FAMILY_INSERT_CHUNK) {
            let mut insert = sqlx::QueryBuilder::<MySql>::new(
                "INSERT INTO device_bindings_refresh (tenant_id, device_id, family_id) ",
            );
            push_family_rows(&mut insert, chunk, tenant, device_id);
            insert.push(" ON DUPLICATE KEY UPDATE family_id = family_id");
            insert.build().execute(&mut **tx).await?;
        }
        Ok(())
    }

    async fn trust_and_bindings(
        pool: &MySqlPool,
        tenant: &str,
        device_id: &str,
    ) -> Result<Option<(String, String)>, sqlx::Error> {
        sqlx::query_as("SELECT trust_level, bindings FROM devices WHERE tenant_id = ? AND id = ?")
            .bind(tenant)
            .bind(device_id)
            .fetch_optional(pool)
            .await
    }

    async fn swap_bindings(
        tx: &mut Transaction<'_, MySql>,
        tenant: &str,
        device_id: &str,
        swap: &BindingsSwap,
    ) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query(
            "UPDATE devices SET bindings = ? \
             WHERE tenant_id = ? AND id = ? AND trust_level <> 'Revoked' \
               AND CAST(bindings AS BINARY) = CAST(? AS BINARY)",
        )
        .bind(&swap.blob)
        .bind(tenant)
        .bind(device_id)
        .bind(&swap.stored)
        .execute(&mut **tx)
        .await?
        .rows_affected())
    }

    async fn trust_level(
        pool: &MySqlPool,
        tenant: &str,
        device_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar("SELECT trust_level FROM devices WHERE tenant_id = ? AND id = ?")
            .bind(tenant)
            .bind(device_id)
            .fetch_optional(pool)
            .await
    }

    async fn touch(
        pool: &MySqlPool,
        tenant: &str,
        device_id: &str,
        ts: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE devices SET last_seen_at = CASE \
                 WHEN trust_level <> 'Revoked' AND last_seen_at < ? THEN ? \
                 ELSE last_seen_at END \
             WHERE tenant_id = ? AND id = ?",
        )
        .bind(ts)
        .bind(ts)
        .bind(tenant)
        .bind(device_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn guarded_trust(
        pool: &MySqlPool,
        tenant: &str,
        device_id: &str,
        w: &GuardedTrustWrite,
    ) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query(
            "UPDATE devices SET \
                    demoted_at = CASE WHEN ? = 1 THEN demoted_at ELSE ? END, \
                    revoked_at = CASE WHEN ? = ? THEN revoked_at ELSE ? END, \
                    trust_level = ? \
             WHERE tenant_id = ? AND id = ? AND trust_level = ?",
        )
        .bind(w.keep_demoted)
        .bind(w.demoted_at)
        .bind(w.expected)
        .bind(w.new)
        .bind(w.revoked_at)
        .bind(w.new)
        .bind(tenant)
        .bind(device_id)
        .bind(w.expected)
        .execute(pool)
        .await?
        .rows_affected())
    }

    async fn claim(
        pool: &MySqlPool,
        tenant: &str,
        device_id: &str,
        user: &str,
    ) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query(
            "UPDATE devices SET user_id = ? \
             WHERE tenant_id = ? AND id = ? AND user_id IS NULL",
        )
        .bind(user)
        .bind(tenant)
        .bind(device_id)
        .execute(pool)
        .await?
        .rows_affected())
    }

    async fn owner(
        pool: &MySqlPool,
        tenant: &str,
        device_id: &str,
    ) -> Result<Option<Option<String>>, sqlx::Error> {
        sqlx::query_scalar("SELECT user_id FROM devices WHERE tenant_id = ? AND id = ?")
            .bind(tenant)
            .bind(device_id)
            .fetch_optional(pool)
            .await
    }

    async fn reseal(pool: &MySqlPool, r: &Reseal) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query(
            "UPDATE devices SET bindings = ? \
             WHERE tenant_id = ? AND id = ? AND CAST(bindings AS BINARY) = CAST(? AS BINARY)",
        )
        .bind(&r.blob)
        .bind(&r.tenant)
        .bind(&r.id)
        .bind(&r.stored)
        .execute(pool)
        .await?
        .rows_affected())
    }

    async fn sweep_stage(
        pool: &MySqlPool,
        stage: SweepStage,
        tenant: &str,
        cutoffs: &SweepCutoffs,
        batch: i64,
    ) -> Result<u64, sqlx::Error> {
        let query = match stage {
            SweepStage::StampRevoked => sqlx::query(
                "UPDATE devices SET revoked_at = ? WHERE tenant_id = ? AND trust_level = 'Revoked' AND revoked_at IS NULL LIMIT ?",
            )
            .bind(cutoffs.now)
            .bind(tenant)
            .bind(batch),
            SweepStage::DemoteTrusted => sqlx::query(
                "UPDATE devices SET trust_level = 'Seen', demoted_at = ? WHERE tenant_id = ? AND trust_level = 'Trusted' AND last_seen_at < ? LIMIT ?",
            )
            .bind(cutoffs.now)
            .bind(tenant)
            .bind(cutoffs.trusted)
            .bind(batch),
            SweepStage::RevokeSeen => sqlx::query(
                "UPDATE devices SET trust_level = 'Revoked', revoked_at = ?, demoted_at = NULL WHERE tenant_id = ? AND trust_level = 'Seen' AND last_seen_at < ? AND (demoted_at IS NULL OR demoted_at < ?) LIMIT ?",
            )
            .bind(cutoffs.now)
            .bind(tenant)
            .bind(cutoffs.seen)
            .bind(cutoffs.seen)
            .bind(batch),
            SweepStage::Purge => sqlx::query(
                "DELETE FROM devices WHERE tenant_id = ? AND trust_level = 'Revoked' AND revoked_at IS NOT NULL AND revoked_at < ? LIMIT ?",
            )
            .bind(tenant)
            .bind(cutoffs.grace)
            .bind(batch),
        };
        Ok(query.execute(pool).await?.rows_affected())
    }
}
