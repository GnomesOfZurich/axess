//! SQLite-backed [`DeviceStore`] using sqlx.
//!
//! # Cross-dialect parity contract
//!
//! The device / device_bindings_refresh schema is written once per
//! dialect sibling in this directory
//! ([`sqlite`](crate::device::storage::sqlite),
//! [`postgres`](crate::device::storage::postgres),
//! [`mysql`](crate::device::storage::mysql)); each dialect owns its
//! idempotency quirks (SQLite/Postgres accept `CREATE INDEX IF NOT
//! EXISTS`; MySQL does not and declares indexes inline in `CREATE
//! TABLE`). Column definitions and semantics MUST stay in sync across
//! all three. The operations that take more than one statement (`save`,
//! `create_or_find`, `replace_bindings`, `record_sighting`,
//! `set_trust_level_if`, `claim_owner`) are written once in
//! `sql_common::ops` over the statements each dialect supplies, and the
//! same contract tests run against every backend.
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
//! CREATE INDEX IF NOT EXISTS idx_devices_fingerprint_seen
//!     ON devices (tenant_id, fingerprint_hash, last_seen_at DESC, id);
//! CREATE INDEX IF NOT EXISTS idx_devices_sweep
//!     ON devices (tenant_id, trust_level, last_seen_at);
//! CREATE INDEX IF NOT EXISTS idx_devices_revoked_at
//!     ON devices (tenant_id, revoked_at) WHERE trust_level = 'Revoked';
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
//! `init_schema` also creates `idx_devices_fingerprint_seen` (the lookup by
//! fingerprint in sorted order, replacing the plain `idx_devices_fingerprint`,
//! which it drops), and `idx_devices_sweep` and `idx_devices_revoked_at` for
//! the retention sweep. Run `init_schema` once after upgrading.
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
use statements::SqliteSql as Sql;

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
            let row: Option<DeviceRow> = sqlx::query_as(select_devices!(
                "WHERE tenant_id = ?1 AND fingerprint_hash = ?2 \
                 ORDER BY last_seen_at DESC, id ASC LIMIT 1"
            ))
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
                 WHERE r.tenant_id = ?1 AND r.family_id = ?2 \
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
            // The CASE reads the row's level from before this statement's
            // assignments.
            let updated = sqlx::query(
                "UPDATE devices SET trust_level = ?3, \
                        revoked_at = CASE WHEN ?3 = 'Revoked' AND trust_level = 'Revoked' \
                                               AND revoked_at IS NOT NULL THEN revoked_at \
                                          ELSE ?4 END, \
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
        ops::sweep::<Sql>(pool, tenant, cutoffs)
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
