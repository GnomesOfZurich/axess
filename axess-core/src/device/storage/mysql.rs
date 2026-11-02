//! MySQL/MariaDB-backed [`DeviceStore`] using sqlx.
//!
//! # Cross-dialect parity contract
//!
//! See [`crate::device::storage::sqlite`] for the cross-dialect
//! contract: this file MUST stay column-for-column in sync with its
//! [`sqlite`](crate::device::storage::sqlite) and
//! [`postgres`](crate::device::storage::postgres) siblings. MySQL's
//! `CREATE INDEX` is not idempotent, so indexes are declared inline in
//! `CREATE TABLE` here where the other two dialects use standalone
//! `CREATE INDEX IF NOT EXISTS` statements: that dialect delta is
//! expected, not a divergence.
//!
//! # Schema
//!

//! ```sql
//! CREATE TABLE IF NOT EXISTS devices (
//!     tenant_id        VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
//!     id               VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
//!     user_id          VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
//!     trust_level      VARCHAR(16)    NOT NULL,
//!     fingerprint_hash VARBINARY(32)  NOT NULL,
//!     first_seen_at    BIGINT         NOT NULL,
//!     last_seen_at     BIGINT         NOT NULL,
//!     revoked_at       BIGINT,
//!     demoted_at       BIGINT,
//!     bindings         MEDIUMTEXT     NOT NULL,
//!     PRIMARY KEY (tenant_id, id),
//!     INDEX idx_devices_fingerprint_seen (tenant_id, fingerprint_hash, last_seen_at DESC, id ASC),
//!     INDEX idx_devices_sweep (tenant_id, trust_level, last_seen_at),
//!     INDEX idx_devices_revoked_at (tenant_id, trust_level, revoked_at),
//!     INDEX idx_devices_user (tenant_id, user_id, last_seen_at DESC, id ASC),
//!     INDEX idx_devices_user_fingerprint (tenant_id, user_id, fingerprint_hash, last_seen_at DESC, id ASC)
//! );
//!
//! CREATE TABLE IF NOT EXISTS device_bindings_refresh (
//!     tenant_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
//!     device_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
//!     family_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
//!     PRIMARY KEY (tenant_id, device_id, family_id),
//!     INDEX idx_device_bindings_refresh_family (tenant_id, family_id),
//!     CONSTRAINT fk_device_bindings_refresh_device
//!         FOREIGN KEY (tenant_id, device_id)
//!         REFERENCES devices (tenant_id, id) ON DELETE CASCADE
//! );
//! ```
//!
//! `bindings` is `MEDIUMTEXT` (16 MiB), not `TEXT` (64 KiB): the column holds
//! the base64 of the serialised, optionally encrypted binding list, which
//! outgrows 64 KiB for a device with many refresh and WebAuthn bindings, and
//! MySQL in strict mode then rejects the write. `family_id` is compared
//! with a binary collation (`utf8mb4_bin`): refresh-family ids are
//! case-sensitive opaque tokens, and the default case-insensitive collation
//! would let `find_by_refresh_family("Fam")` match, and revoke, the devices
//! of family `fam`, and would make two distinct families collide on the
//! primary key.
//!
//! # Upgrading an existing deployment
//!
//! `CREATE TABLE IF NOT EXISTS` leaves tables that already exist as they
//! are, so a deployment created before these two column definitions must
//! run, once:
//!
//! ```sql
//! ALTER TABLE devices
//!     MODIFY bindings MEDIUMTEXT NOT NULL;
//! ALTER TABLE device_bindings_refresh
//!     MODIFY family_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
//! ```
//!
//! The id columns are compared with a binary collation too (see
//! `DEVICES_DDL`): without it `tenant_id`, `id` and `user_id` use the
//! table's default, case-insensitive collation, so a device id differing
//! only in case resolves to the same row. A deployment created before this
//! must also run, once. The foreign key has to be dropped while the columns
//! it ties together change collation, and re-added after:
//!
//! ```sql
//! ALTER TABLE device_bindings_refresh
//!     DROP FOREIGN KEY fk_device_bindings_refresh_device;
//! ALTER TABLE devices
//!     MODIFY tenant_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
//!     MODIFY id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
//!     MODIFY user_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
//! ALTER TABLE device_bindings_refresh
//!     MODIFY tenant_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
//!     MODIFY device_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
//! ALTER TABLE device_bindings_refresh
//!     ADD CONSTRAINT fk_device_bindings_refresh_device
//!         FOREIGN KEY (tenant_id, device_id)
//!         REFERENCES devices (tenant_id, id) ON DELETE CASCADE;
//! ```
//!
//! The `devices` change rebuilds its primary key and fails with a
//! duplicate-key error if two stored ids differ only in case; resolve those
//! rows first (the refresh index is rebuilt from `devices.bindings` on the
//! next `save`).
//!
//! A deployment created before `demoted_at` existed (the instant a
//! `Trusted` row was moved down to `Seen`, `NULL` for a device that was
//! never trusted) must also run:
//!
//! ```sql
//! ALTER TABLE devices ADD COLUMN demoted_at BIGINT NULL AFTER revoked_at;
//! ```
//!
//! Rows that were already `Seen` carry `NULL` and so read as never trusted:
//! the first sweep after the upgrade revokes those idle for more than
//! `seen_idle` (30 days by default), including ones demoted earlier.
//!
//! The second statement rebuilds the table's primary key; it fails with a
//! duplicate-key error if two stored family ids differ only in case, in
//! which case delete the rows of the family that is not meant to exist
//! (the index is rebuilt from `devices.bindings` on the next `save`).
//!
//! A deployment created before `find_by_fingerprint_for_user` existed must
//! also add the index that serves it (`CREATE TABLE IF NOT EXISTS` does not
//! touch an existing table):
//!
//! ```sql
//! ALTER TABLE devices ADD INDEX idx_devices_user_fingerprint
//!     (tenant_id, user_id, fingerprint_hash, last_seen_at DESC, id ASC);
//! ```
//!
//! A deployment created before the fingerprint and retention indexes were
//! tuned replaces the plain fingerprint index with one that serves
//! `find_by_fingerprint` in order, and adds the two the sweep reads through
//! (`CREATE TABLE IF NOT EXISTS` does not touch an existing table):
//!
//! ```sql
//! ALTER TABLE devices
//!     DROP INDEX idx_devices_fingerprint,
//!     ADD INDEX idx_devices_fingerprint_seen
//!         (tenant_id, fingerprint_hash, last_seen_at DESC, id ASC),
//!     ADD INDEX idx_devices_sweep (tenant_id, trust_level, last_seen_at),
//!     ADD INDEX idx_devices_revoked_at (tenant_id, trust_level, revoked_at);
//! ```
//!
//! A deployment whose sighting indexes were created all ascending (releases
//! before the descending key parts) rebuilds them so the lookups ordered
//! `last_seen_at DESC, id ASC` read from the index without a filesort
//! (MySQL 8.0 and later; MariaDB before 10.8 ignores the direction):
//!
//! ```sql
//! ALTER TABLE devices
//!     DROP INDEX idx_devices_fingerprint_seen,
//!     ADD INDEX idx_devices_fingerprint_seen
//!         (tenant_id, fingerprint_hash, last_seen_at DESC, id ASC),
//!     DROP INDEX idx_devices_user,
//!     ADD INDEX idx_devices_user (tenant_id, user_id, last_seen_at DESC, id ASC),
//!     DROP INDEX idx_devices_user_fingerprint,
//!     ADD INDEX idx_devices_user_fingerprint
//!         (tenant_id, user_id, fingerprint_hash, last_seen_at DESC, id ASC);
//! ```
//!
//! MySQL `CREATE INDEX` is not idempotent (no `IF NOT EXISTS` for
//! indexes pre-MySQL 8.0.29 / MariaDB 10.5.4), so indexes are
//! declared inline in `CREATE TABLE`. Mirrors the dialect strategy
//! used by [`crate::session::storage::mysql::MysqlSessionStore`].
//!
//! The three sighting indexes end in `last_seen_at DESC, id ASC`, the
//! order the lookups ask for, so MySQL 8 reads the newest rows straight
//! from the index: the live test
//! `the_sighting_lookups_read_their_index_without_a_sort` checks each plan
//! for its index and for the absence of a sort.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axess_clock::Clock;
use chrono::{DateTime, Utc};
use sqlx::MySqlPool;

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::storage::sql_common::{
    BindingsCodec, DeviceRow, GuardedTrustWrite, SqlDeviceStoreError, SweepCutoffs, TrustWrite,
    decode_all, decode_optional, require_row, select_devices, utc_to_unix,
};
use crate::device::store::{
    BindingsUpdate, DeviceStore, OwnerClaim, SweepConfig, SweepCounts, TrustTransition, for_save,
};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
use crate::session::crypto::SessionCrypto;

mod schema;
mod statements;

use crate::device::storage::sql_common::ops;
use statements::MysqlSql as Sql;

/// The newest sighting of a fingerprint, read in order from
/// `idx_devices_fingerprint_seen`.
const FIND_BY_FINGERPRINT: &str = select_devices!(
    "WHERE tenant_id = ? AND fingerprint_hash = ? \
     ORDER BY last_seen_at DESC, id ASC LIMIT 1"
);

/// The newest sighting of a fingerprint among one owner's devices, read in
/// order from `idx_devices_user_fingerprint`.
const FIND_BY_FINGERPRINT_FOR_USER: &str = select_devices!(
    "WHERE tenant_id = ? AND user_id = ? AND fingerprint_hash = ? \
     ORDER BY last_seen_at DESC, id ASC LIMIT 1"
);

/// One owner's devices, newest sighting first, read in order from
/// `idx_devices_user`.
const FIND_FOR_USER: &str = select_devices!(
    "WHERE tenant_id = ? AND user_id = ? \
     ORDER BY last_seen_at DESC, id ASC LIMIT ?"
);

/// MySQL/MariaDB-backed [`DeviceStore`].
///
/// Wrap an existing [`MySqlPool`] and call
/// [`init_schema`](Self::init_schema) once at startup.
///
/// # Encryption
///
/// Same shape as
/// [`PostgresDeviceStore`](super::postgres::PostgresDeviceStore): the
/// optional [`SessionCrypto`] envelope is applied to the bindings
/// blob only.
///
/// # Compatibility
///
/// Tested against MySQL 8.x and MariaDB 10.5+. MySQL 5.7 is not
/// supported on the session backend either; the upsert syntax
/// (`ON DUPLICATE KEY UPDATE … VALUES(col)`) works there but
/// `VARBINARY(32)` and `BIGINT` semantics match.
#[derive(Clone)]
pub struct MysqlDeviceStore {
    pool: MySqlPool,
    codec: BindingsCodec,
    sweep_config: SweepConfig,
}

impl MysqlDeviceStore {
    /// Create an encrypted store (recommended for production).
    pub fn new(pool: MySqlPool, crypto: SessionCrypto) -> Self {
        Self {
            pool,
            codec: BindingsCodec::encrypted(crypto),
            sweep_config: SweepConfig::default(),
        }
    }

    /// Create a plaintext store (development/testing only).
    pub fn plaintext(pool: MySqlPool) -> Self {
        tracing::warn!(
            "MysqlDeviceStore created without encryption; \
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
}

impl DeviceStore for MysqlDeviceStore {
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
                sqlx::query_as(select_devices!("WHERE tenant_id = ? AND id = ?"))
                    .bind(&tenant)
                    .bind(&device_id)
                    .fetch_optional(&pool)
                    .await?;
            let (device, reseal) = decode_optional(&codec, row)?;
            ops::reseal_rows::<Sql>(&pool, reseal).await;
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
            let row: Option<DeviceRow> = sqlx::query_as(FIND_BY_FINGERPRINT)
                .bind(&tenant)
                .bind(&bytes)
                .fetch_optional(&pool)
                .await?;
            let (device, reseal) = decode_optional(&codec, row)?;
            ops::reseal_rows::<Sql>(&pool, reseal).await;
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
            let row: Option<DeviceRow> = sqlx::query_as(FIND_BY_FINGERPRINT_FOR_USER)
                .bind(&tenant)
                .bind(&uid)
                .bind(&bytes)
                .fetch_optional(&pool)
                .await?;
            let (device, reseal) = decode_optional(&codec, row)?;
            ops::reseal_rows::<Sql>(&pool, reseal).await;
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
            let rows: Vec<DeviceRow> = sqlx::query_as(FIND_FOR_USER)
                .bind(&tenant)
                .bind(&uid)
                .bind(limit_i64)
                .fetch_all(&pool)
                .await?;
            let (devices, reseals) = decode_all(&codec, rows)?;
            ops::reseal_rows::<Sql>(&pool, reseals).await;
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
                 WHERE r.tenant_id = ? AND r.family_id = ? \
                 ORDER BY d.last_seen_at DESC, d.id ASC",
            )
            .bind(&tenant)
            .bind(&family)
            .fetch_all(&pool)
            .await?;
            let (devices, reseals) = decode_all(&codec, rows)?;
            ops::reseal_rows::<Sql>(&pool, reseals).await;
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
        ops::save::<Sql>(pool, codec, device)
    }

    fn create_or_find(
        &self,
        device: &Device,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Device, Self::Error>> + Send {
        let pool = self.pool.clone();
        let codec = self.codec.clone();
        let device = for_save(device, now);
        ops::create_or_find::<Sql>(pool, codec, device)
    }

    fn record_sighting(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<DeviceTrustLevel, Self::Error>> + Send {
        ops::record_sighting::<Sql>(
            self.pool.clone(),
            tenant_id.to_string(),
            id.to_string(),
            utc_to_unix(now),
        )
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
            // MySQL applies a single-table UPDATE's assignments left to
            // right and later ones see the earlier results, so `demoted_at`
            // is assigned BEFORE `trust_level`: its CASE must read the level
            // the row had before this statement.
            let updated = sqlx::query(
                "UPDATE devices SET \
                        demoted_at = CASE WHEN ? = 0 THEN NULL \
                                          WHEN trust_level = 'Trusted' THEN ? \
                                          ELSE demoted_at END, \
                        revoked_at = CASE WHEN ? = 'Revoked' AND trust_level = 'Revoked' \
                                               AND revoked_at IS NOT NULL THEN revoked_at \
                                          ELSE ? END, \
                        trust_level = ? \
                 WHERE tenant_id = ? AND id = ?",
            )
            .bind(w.to_seen)
            .bind(w.now)
            .bind(w.trust)
            .bind(w.revoked_at)
            .bind(w.trust)
            .bind(&tenant)
            .bind(&device_id)
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
        ops::set_trust_level_if::<Sql>(
            self.pool.clone(),
            tenant_id.to_string(),
            id.to_string(),
            expected,
            GuardedTrustWrite::new(expected, level, now),
        )
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
        ops::replace_bindings::<Sql>(pool, codec, tenant, device_id, expected, bindings)
    }

    fn claim_owner(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        user: &UserId,
        _now: DateTime<Utc>,
    ) -> impl Future<Output = Result<OwnerClaim, Self::Error>> + Send {
        ops::claim_owner::<Sql>(
            self.pool.clone(),
            tenant_id.to_string(),
            id.to_string(),
            user.to_string(),
        )
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
                "WHERE tenant_id = ? AND user_id = ? \
                   AND trust_level <> 'Revoked' \
                 ORDER BY last_seen_at DESC, id ASC LIMIT ?"
            ))
            .bind(&tenant)
            .bind(&uid)
            .bind(limit_i64)
            .fetch_all(&pool)
            .await?;
            let (devices, reseals) = decode_all(&codec, rows)?;
            ops::reseal_rows::<Sql>(&pool, reseals).await;
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
            sqlx::query("DELETE FROM devices WHERE tenant_id = ? AND id = ?")
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
        ops::sweep::<Sql>(pool, tenant, cutoffs)
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────

use crate::health::{HealthCheck, HealthStatus};

impl HealthCheck for MysqlDeviceStore {
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
                Ok(Err(e)) => HealthStatus::Unhealthy(format!("mysql SELECT 1 failed: {e}")),
                Err(_) => HealthStatus::Unhealthy("mysql SELECT 1 timeout (2s)".into()),
            }
        })
    }
}

#[cfg(test)]
mod tests;
