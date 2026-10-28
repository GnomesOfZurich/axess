//! SQLite-backed [`DeviceStore`] using sqlx.
//!
//! # Cross-dialect parity contract
//!
//! The device / device_bindings_refresh schema is intentionally
//! duplicated across three dialect siblings in this directory
//! ([`sqlite`](crate::device::storage::sqlite),
//! [`postgres`](crate::device::storage::postgres),
//! [`mysql`](crate::device::storage::mysql)) rather than generated from
//! a single source; each dialect owns its idempotency quirks
//! (SQLite/Postgres accept `CREATE INDEX IF NOT EXISTS`; MySQL does
//! not and declares indexes inline in `CREATE TABLE`). Column
//! definitions and semantics MUST stay in sync across all three, a
//! change in one file is a defect until the other two catch up. No
//! automated parity test exists today; the safeguard is that all
//! three files live in the same directory and a reviewer touching one
//! sees the others immediately.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS devices (
//!     tenant_id        TEXT    NOT NULL,
//!     id               TEXT    NOT NULL,
//!     user_id          TEXT,
//!     trust_level      TEXT    NOT NULL,
//!     fingerprint_hash BLOB    NOT NULL,
//!     first_seen_at    INTEGER NOT NULL,
//!     last_seen_at     INTEGER NOT NULL,
//!     revoked_at       INTEGER,
//!     demoted_at       INTEGER,
//!     bindings         TEXT    NOT NULL,
//!     PRIMARY KEY (tenant_id, id)
//! );
//!
//! CREATE INDEX IF NOT EXISTS idx_devices_fingerprint
//!     ON devices (tenant_id, fingerprint_hash);
//! CREATE INDEX IF NOT EXISTS idx_devices_user
//!     ON devices (tenant_id, user_id, last_seen_at DESC);
//! CREATE INDEX IF NOT EXISTS idx_devices_user_fingerprint
//!     ON devices (tenant_id, user_id, fingerprint_hash, last_seen_at DESC);
//!
//! -- Index table for fast `find_by_refresh_family`. One row per
//! -- `DeviceBinding::Refresh` carried by a device.
//! CREATE TABLE IF NOT EXISTS device_bindings_refresh (
//!     tenant_id TEXT NOT NULL,
//!     device_id TEXT NOT NULL,
//!     family_id TEXT NOT NULL,
//!     PRIMARY KEY (tenant_id, device_id, family_id),
//!     FOREIGN KEY (tenant_id, device_id)
//!         REFERENCES devices (tenant_id, id) ON DELETE CASCADE
//! );
//!
//! CREATE INDEX IF NOT EXISTS idx_device_bindings_refresh_family
//!     ON device_bindings_refresh (tenant_id, family_id);
//! ```
//!
//! `demoted_at` is the instant a `Trusted` row was moved down to `Seen`; it
//! is `NULL` for a device that was never trusted and is cleared by every
//! other transition. The sweep reads it to give a demoted device its full
//! `seen_idle` window from the demotion.
//!
//! # Upgrading an existing deployment
//!
//! `CREATE TABLE IF NOT EXISTS` leaves an existing table as it is, so a
//! deployment created before `demoted_at` existed must run, once:
//!
//! ```sql
//! ALTER TABLE devices ADD COLUMN demoted_at INTEGER;
//! ```
//!
//! Rows that were already `Seen` carry `NULL` and so read as never trusted:
//! the first sweep after the upgrade revokes those idle for more than
//! `seen_idle` (30 days by default), including ones demoted earlier.
//!
//! `find_by_fingerprint_for_user` is served by
//! `idx_devices_user_fingerprint`. `init_schema` creates it on startup
//! (`IF NOT EXISTS`); to add it without running `init_schema`, run:
//!
//! ```sql
//! CREATE INDEX IF NOT EXISTS idx_devices_user_fingerprint
//!     ON devices (tenant_id, user_id, fingerprint_hash, last_seen_at DESC);
//! ```
//!
//! # Encryption
//!
//! Only the `bindings` column runs through the optional AES-256-GCM
//! envelope codec ([`SessionCrypto`]
//! reused as a generic envelope primitive). Structured columns stay
//! plaintext because every one of them needs to be index-scanned.
//! See `sql_common` for the rationale.
//!
//! # Why a separate index table for refresh-family lookups
//!
//! `find_by_refresh_family(tenant, family_id)` is on the cascade-
//! revocation hot path. Walking every `Device` row, decoding the
//! bindings blob, and filtering in-process scales O(n) in the
//! tenant's device count, unacceptable on a backend whose whole
//! point is to handle millions of rows. The `device_bindings_refresh`
//! table indexes the only field anybody queries by.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axess_clock::Clock;
#[cfg(test)]
use chrono::TimeZone;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::storage::sql_common::{
    BindingsCodec, DeviceRow, DeviceWrite, FAMILY_INSERT_CHUNK, GuardedTrustWrite,
    SqlDeviceStoreError, SwapPlan, SweepCutoffs, TRANSITION_ATTEMPTS, TrustWrite,
    bindings_update_after_miss, claim_after_miss, decode_all, decode_optional, parse_stored_trust,
    plan_bindings_swap, push_family_rows, require_row, select_devices, transition_after_miss,
    utc_to_unix,
};
use crate::device::store::{
    BindingsUpdate, DeviceStore, OwnerClaim, SweepConfig, SweepCounts, TrustTransition,
    blocks_save, for_save,
};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
use crate::session::crypto::SessionCrypto;

mod reseal;
mod sweep;

use reseal::reseal_rows;

/// SQLite-backed [`DeviceStore`].
///
/// Wrap an existing [`SqlitePool`] and call
/// [`init_schema`](Self::init_schema) once at startup. The store is
/// `Clone` (cheap: wraps `Arc`s); share across handlers / tasks.
///
/// # Encryption
///
/// The primary constructor [`new`](Self::new) requires a
/// [`SessionCrypto`] envelope key. The `bindings` column is encrypted
/// before storage and decrypted on load. Use
/// [`plaintext`](Self::plaintext) only for local development and
/// testing.
#[derive(Clone)]
pub struct SqliteDeviceStore {
    pool: SqlitePool,
    codec: BindingsCodec,
    sweep_config: SweepConfig,
}

impl SqliteDeviceStore {
    /// Create an encrypted store (recommended for production).
    pub fn new(pool: SqlitePool, crypto: SessionCrypto) -> Self {
        Self {
            pool,
            codec: BindingsCodec::encrypted(crypto),
            sweep_config: SweepConfig::default(),
        }
    }

    /// Create a plaintext store (development/testing only). Logs a
    /// warning so production builds don't accidentally pick this path.
    pub fn plaintext(pool: SqlitePool) -> Self {
        tracing::warn!(
            "SqliteDeviceStore created without encryption; \
             do not use in production"
        );
        Self {
            pool,
            codec: BindingsCodec::plaintext(),
            sweep_config: SweepConfig::default(),
        }
    }

    /// Has no effect: every time-dependent method of the store is given the
    /// instant it works from, so there is no clock to inject.
    #[deprecated(note = "the store reads time only from the `now` its methods are given")]
    pub fn with_clock(self, clock: Arc<dyn Clock>) -> Self {
        let _ = clock;
        self
    }

    /// Override the [`SweepConfig`] driving the retention ladder.
    pub fn with_sweep_config(mut self, config: SweepConfig) -> Self {
        self.sweep_config = config;
        self
    }

    /// Borrow the underlying [`SqlitePool`] for tests that assert
    /// against the raw schema.
    #[doc(hidden)]
    pub fn pool_for_test(&self) -> &SqlitePool {
        &self.pool
    }

    /// Create the `devices` and `device_bindings_refresh` tables and
    /// supporting indexes. Idempotent: safe to call on every startup.
    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS devices (
                tenant_id        TEXT    NOT NULL,
                id               TEXT    NOT NULL,
                user_id          TEXT,
                trust_level      TEXT    NOT NULL,
                fingerprint_hash BLOB    NOT NULL,
                first_seen_at    INTEGER NOT NULL,
                last_seen_at     INTEGER NOT NULL,
                revoked_at       INTEGER,
                demoted_at       INTEGER,
                bindings         TEXT    NOT NULL,
                PRIMARY KEY (tenant_id, id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_devices_fingerprint \
             ON devices (tenant_id, fingerprint_hash)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_devices_user \
             ON devices (tenant_id, user_id, last_seen_at DESC)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_devices_user_fingerprint \
             ON devices (tenant_id, user_id, fingerprint_hash, last_seen_at DESC)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS device_bindings_refresh (
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                family_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, device_id, family_id),
                FOREIGN KEY (tenant_id, device_id)
                    REFERENCES devices (tenant_id, id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_device_bindings_refresh_family \
             ON device_bindings_refresh (tenant_id, family_id)",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// Current trust level of a device row, `None` when the row is absent.
async fn fetch_trust_level(
    pool: &SqlitePool,
    tenant: &str,
    device_id: &str,
) -> Result<Option<DeviceTrustLevel>, SqlDeviceStoreError> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT trust_level FROM devices WHERE tenant_id = ?1 AND id = ?2")
            .bind(tenant)
            .bind(device_id)
            .fetch_optional(pool)
            .await?;
    parse_stored_trust(stored)
}

/// Replace a device's refresh-family index rows inside `tx`. The family
/// ids are already distinct ([`refresh_family_ids`]) and the insert is
/// idempotent as well, so a repeated family can never violate the primary
/// key and abort the surrounding transaction.
async fn rewrite_family_index(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant: &str,
    device_id: &str,
    family_ids: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM device_bindings_refresh WHERE tenant_id = ?1 AND device_id = ?2")
        .bind(tenant)
        .bind(device_id)
        .execute(&mut **tx)
        .await?;
    // One multi-row insert per chunk keeps a device with many families to a
    // handful of statements, well under every dialect's bind-parameter cap.
    for chunk in family_ids.chunks(FAMILY_INSERT_CHUNK) {
        let mut insert = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT OR IGNORE INTO device_bindings_refresh (tenant_id, device_id, family_id) ",
        );
        push_family_rows(&mut insert, chunk, tenant, device_id);
        insert.build().execute(&mut **tx).await?;
    }
    Ok(())
}

impl DeviceStore for SqliteDeviceStore {
    type Error = SqlDeviceStoreError;

    fn load(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let pool = self.pool.clone();
        let codec = self.codec.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        async move {
            let row: Option<DeviceRow> =
                sqlx::query_as(select_devices!("WHERE tenant_id = ?1 AND id = ?2"))
                    .bind(&tenant)
                    .bind(&device_id)
                    .fetch_optional(&pool)
                    .await?;
            let (device, reseal) = decode_optional(&codec, row)?;
            reseal_rows(&pool, reseal).await;
            Ok(device)
        }
    }

    fn find_by_fingerprint(
        &self,
        tenant_id: &TenantId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let pool = self.pool.clone();
        let codec = self.codec.clone();
        let tenant = tenant_id.to_string();
        let bytes = hash.as_bytes().to_vec();
        async move {
            let row: Option<DeviceRow> = sqlx::query_as(select_devices!(
                "WHERE tenant_id = ?1 AND fingerprint_hash = ?2 \
                 ORDER BY last_seen_at DESC, id ASC LIMIT 1"
            ))
            .bind(&tenant)
            .bind(&bytes)
            .fetch_optional(&pool)
            .await?;
            let (device, reseal) = decode_optional(&codec, row)?;
            reseal_rows(&pool, reseal).await;
            Ok(device)
        }
    }

    fn find_by_fingerprint_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let pool = self.pool.clone();
        let codec = self.codec.clone();
        let tenant = tenant_id.to_string();
        let uid = user_id.to_string();
        let bytes = hash.as_bytes().to_vec();
        async move {
            let row: Option<DeviceRow> = sqlx::query_as(select_devices!(
                "WHERE tenant_id = ?1 AND user_id = ?2 AND fingerprint_hash = ?3 \
                 ORDER BY last_seen_at DESC, id ASC LIMIT 1"
            ))
            .bind(&tenant)
            .bind(&uid)
            .bind(&bytes)
            .fetch_optional(&pool)
            .await?;
            let (device, reseal) = decode_optional(&codec, row)?;
            reseal_rows(&pool, reseal).await;
            Ok(device)
        }
    }

    fn find_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        let pool = self.pool.clone();
        let codec = self.codec.clone();
        let tenant = tenant_id.to_string();
        let uid = user_id.to_string();
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        async move {
            let rows: Vec<DeviceRow> = sqlx::query_as(select_devices!(
                "WHERE tenant_id = ?1 AND user_id = ?2 \
                 ORDER BY last_seen_at DESC, id ASC LIMIT ?3"
            ))
            .bind(&tenant)
            .bind(&uid)
            .bind(limit_i64)
            .fetch_all(&pool)
            .await?;
            let (devices, reseals) = decode_all(&codec, rows)?;
            reseal_rows(&pool, reseals).await;
            Ok(devices)
        }
    }

    fn find_by_refresh_family(
        &self,
        tenant_id: &TenantId,
        family_id: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        let pool = self.pool.clone();
        let codec = self.codec.clone();
        let tenant = tenant_id.to_string();
        let family = family_id.to_string();
        async move {
            let rows: Vec<DeviceRow> = sqlx::query_as(
                "SELECT d.tenant_id, d.id, d.user_id, d.trust_level, d.fingerprint_hash, \
                        d.first_seen_at, d.last_seen_at, d.revoked_at, d.demoted_at, d.bindings \
                 FROM devices d \
                 INNER JOIN device_bindings_refresh r \
                   ON d.tenant_id = r.tenant_id AND d.id = r.device_id \
                 WHERE r.tenant_id = ?1 AND r.family_id = ?2 \
                 ORDER BY d.last_seen_at DESC, d.id ASC",
            )
            .bind(&tenant)
            .bind(&family)
            .fetch_all(&pool)
            .await?;
            let (devices, reseals) = decode_all(&codec, rows)?;
            reseal_rows(&pool, reseals).await;
            Ok(devices)
        }
    }

    fn save(
        &self,
        device: &Device,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let pool = self.pool.clone();
        let codec = self.codec.clone();
        let device = for_save(device, now);
        async move {
            let w = DeviceWrite::new(&codec, &device)?;

            // Wrap the device-row upsert and the refresh-binding index
            // refresh in a single transaction so a concurrent
            // `find_by_refresh_family` either sees the pre-update or
            // the post-update set, never a partially-updated index.
            let mut tx = pool.begin().await?;

            // A save never un-revokes: a device loaded before a revocation
            // and saved after it leaves the revoked row as it is. The row
            // is read (and, where the engine supports it, locked) in the
            // transaction that then writes it.
            let stored: Option<String> = sqlx::query_scalar(
                "SELECT trust_level FROM devices WHERE tenant_id = ?1 AND id = ?2",
            )
            .bind(&w.tenant)
            .bind(&w.id)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(stored) = parse_stored_trust(stored)?
                && blocks_save(stored, device.trust_level)
            {
                return Ok(());
            }

            sqlx::query(
                r#"
                INSERT INTO devices
                    (tenant_id, id, user_id, trust_level, fingerprint_hash,
                     first_seen_at, last_seen_at, revoked_at, demoted_at, bindings)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(tenant_id, id) DO UPDATE SET
                    user_id          = excluded.user_id,
                    trust_level      = excluded.trust_level,
                    fingerprint_hash = excluded.fingerprint_hash,
                    first_seen_at    = excluded.first_seen_at,
                    last_seen_at     = excluded.last_seen_at,
                    revoked_at       = excluded.revoked_at,
                    demoted_at       = excluded.demoted_at,
                    bindings         = excluded.bindings
                "#,
            )
            .bind(&w.tenant)
            .bind(&w.id)
            .bind(w.user_id.as_deref())
            .bind(w.trust)
            .bind(&w.fingerprint)
            .bind(w.first_seen_at)
            .bind(w.last_seen_at)
            .bind(w.revoked_at)
            .bind(w.demoted_at)
            .bind(&w.bindings)
            .execute(&mut *tx)
            .await?;

            rewrite_family_index(&mut tx, &w.tenant, &w.id, &w.family_ids).await?;

            tx.commit().await?;
            Ok(())
        }
    }

    fn record_sighting(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let pool = self.pool.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        let ts = utc_to_unix(now);
        async move {
            let updated = sqlx::query(
                "UPDATE devices SET last_seen_at = CASE \
                     WHEN trust_level <> 'Revoked' AND last_seen_at < ?3 THEN ?3 \
                     ELSE last_seen_at END \
                 WHERE tenant_id = ?1 AND id = ?2",
            )
            .bind(&tenant)
            .bind(&device_id)
            .bind(ts)
            .execute(&pool)
            .await?
            .rows_affected();
            require_row(updated, tenant, device_id)
        }
    }

    fn set_trust_level(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let pool = self.pool.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        let w = TrustWrite::new(level, now);
        async move {
            // The CASE reads the row's level from before this statement's
            // assignments.
            let updated = sqlx::query(
                "UPDATE devices SET trust_level = ?3, revoked_at = ?4, \
                        demoted_at = CASE WHEN ?5 = 0 THEN NULL \
                                          WHEN trust_level = 'Trusted' THEN ?6 \
                                          ELSE demoted_at END \
                 WHERE tenant_id = ?1 AND id = ?2",
            )
            .bind(&tenant)
            .bind(&device_id)
            .bind(w.trust)
            .bind(w.revoked_at)
            .bind(w.to_seen)
            .bind(w.now)
            .execute(&pool)
            .await?
            .rows_affected();
            require_row(updated, tenant, device_id)
        }
    }

    fn set_trust_level_if(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<TrustTransition, Self::Error>> + Send {
        let pool = self.pool.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        let w = GuardedTrustWrite::new(expected, level, now);
        async move {
            // One conditional UPDATE: the engine checks the current level
            // and writes in a single statement, so a revocation that lands
            // first makes this match no row instead of being overwritten.
            for _ in 0..TRANSITION_ATTEMPTS {
                let updated = sqlx::query("UPDATE devices SET trust_level = ?4, revoked_at = ?5, demoted_at = CASE WHEN ?6 = 1 THEN demoted_at ELSE ?7 END WHERE tenant_id = ?1 AND id = ?2 AND trust_level = ?3")
            .bind(&tenant)
            .bind(&device_id)
            .bind(w.expected)
            .bind(w.new)
            .bind(w.revoked_at)
            .bind(w.keep_demoted)
            .bind(w.demoted_at)
            .execute(&pool)
            .await?
            .rows_affected();
                if updated > 0 {
                    return Ok(TrustTransition::Applied);
                }
                let current = fetch_trust_level(&pool, &tenant, &device_id).await?;
                if let Some(outcome) = transition_after_miss(current, expected) {
                    return Ok(outcome);
                }
                // The row is at `expected` again: the write lost a race with
                // a change that has since been undone. Try it again.
            }
            Ok(TrustTransition::Refused { current: expected })
        }
    }

    fn replace_bindings(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        _now: DateTime<Utc>,
    ) -> impl Future<Output = Result<BindingsUpdate, Self::Error>> + Send {
        let pool = self.pool.clone();
        let codec = self.codec.clone();
        let expected = expected.to_vec();
        let bindings = bindings.to_vec();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        async move {
            let row: Option<(String, String)> = sqlx::query_as(
                "SELECT trust_level, bindings FROM devices WHERE tenant_id = ?1 AND id = ?2",
            )
            .bind(&tenant)
            .bind(&device_id)
            .fetch_optional(&pool)
            .await?;
            let swap =
                match plan_bindings_swap(&codec, &tenant, &device_id, row, &expected, &bindings)? {
                    SwapPlan::Settled(outcome) => return Ok(outcome),
                    SwapPlan::Write(swap) => swap,
                };
            let mut tx = pool.begin().await?;
            // Only the bindings column is written, only on a row that is not
            // Revoked, and only while it still holds the bytes that were
            // read: the engine evaluates the conditions and the write
            // together, so a revocation cannot be undone, a revoked device
            // cannot gain a binding, and a concurrent bindings edit makes
            // this match no row instead of being overwritten.
            let updated = sqlx::query("UPDATE devices SET bindings = ?3 WHERE tenant_id = ?1 AND id = ?2 AND trust_level <> 'Revoked' AND bindings = ?4")
                .bind(&tenant)
                .bind(&device_id)
                .bind(&swap.blob)
                .bind(&swap.stored)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            if updated == 0 {
                // Nothing written. The transaction is ended before the
                // re-read, which needs a pooled connection of its own: with
                // a one-connection pool it would otherwise wait for the
                // connection this transaction still holds.
                tx.rollback().await?;
                let current = fetch_trust_level(&pool, &tenant, &device_id).await?;
                return Ok(bindings_update_after_miss(current));
            }
            rewrite_family_index(&mut tx, &tenant, &device_id, &swap.family_ids).await?;
            tx.commit().await?;
            Ok(BindingsUpdate::Written)
        }
    }

    fn claim_owner(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        user: &UserId,
        _now: DateTime<Utc>,
    ) -> impl Future<Output = Result<OwnerClaim, Self::Error>> + Send {
        let pool = self.pool.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        let user = user.to_string();
        async move {
            // One conditional UPDATE: the owner is set only while there is
            // none, so of two users racing for an unowned device exactly one
            // matches a row.
            let updated = sqlx::query(
                "UPDATE devices SET user_id = ?3 \
                 WHERE tenant_id = ?1 AND id = ?2 AND user_id IS NULL",
            )
            .bind(&tenant)
            .bind(&device_id)
            .bind(&user)
            .execute(&pool)
            .await?
            .rows_affected();
            if updated > 0 {
                return Ok(OwnerClaim::Claimed);
            }
            let owner: Option<Option<String>> =
                sqlx::query_scalar("SELECT user_id FROM devices WHERE tenant_id = ?1 AND id = ?2")
                    .bind(&tenant)
                    .bind(&device_id)
                    .fetch_optional(&pool)
                    .await?;
            Ok(claim_after_miss(owner, &user))
        }
    }

    fn find_active_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        let pool = self.pool.clone();
        let codec = self.codec.clone();
        let tenant = tenant_id.to_string();
        let uid = user_id.to_string();
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        async move {
            // The Revoked filter is part of the WHERE clause, so it is
            // applied before ORDER BY ... LIMIT: revoked rows never use up
            // the limit.
            let rows: Vec<DeviceRow> = sqlx::query_as(select_devices!(
                "WHERE tenant_id = ?1 AND user_id = ?2 \
                   AND trust_level <> 'Revoked' \
                 ORDER BY last_seen_at DESC, id ASC LIMIT ?3"
            ))
            .bind(&tenant)
            .bind(&uid)
            .bind(limit_i64)
            .fetch_all(&pool)
            .await?;
            let (devices, reseals) = decode_all(&codec, rows)?;
            reseal_rows(&pool, reseals).await;
            Ok(devices)
        }
    }

    fn delete(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let pool = self.pool.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        async move {
            // FK ON DELETE CASCADE removes the matching
            // `device_bindings_refresh` rows.
            sqlx::query("DELETE FROM devices WHERE tenant_id = ?1 AND id = ?2")
                .bind(&tenant)
                .bind(&device_id)
                .execute(&pool)
                .await?;
            Ok(())
        }
    }

    fn sweep(
        &self,
        tenant_id: &TenantId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        let pool = self.pool.clone();
        let cutoffs = SweepCutoffs::new(&self.sweep_config, now);
        let tenant = tenant_id.to_string();
        async move { sweep::run(&pool, &tenant, &cutoffs).await }
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────

use crate::health::{HealthCheck, HealthStatus};

impl HealthCheck for SqliteDeviceStore {
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async {
            match tokio::time::timeout(
                Duration::from_secs(2),
                sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool),
            )
            .await
            {
                Ok(Ok(_)) => HealthStatus::Healthy,
                Ok(Err(e)) => HealthStatus::Unhealthy(format!("sqlite SELECT 1 failed: {e}")),
                Err(_) => HealthStatus::Unhealthy("sqlite SELECT 1 timeout (2s)".into()),
            }
        })
    }
}
#[cfg(test)]
mod tests;

/// Store constructor shared with tests in other modules.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// A plaintext store over one in-memory connection, schema applied.
    pub(crate) async fn store() -> SqliteDeviceStore {
        super::tests::fresh_store().await
    }
}
