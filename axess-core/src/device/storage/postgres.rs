//! PostgreSQL-backed [`DeviceStore`] using sqlx.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS devices (
//!     tenant_id        TEXT   NOT NULL,
//!     id               TEXT   NOT NULL,
//!     user_id          TEXT,
//!     trust_level      TEXT   NOT NULL,
//!     fingerprint_hash BYTEA  NOT NULL,
//!     first_seen_at    BIGINT NOT NULL,
//!     last_seen_at     BIGINT NOT NULL,
//!     revoked_at       BIGINT,
//!     bindings         TEXT   NOT NULL,
//!     PRIMARY KEY (tenant_id, id)
//! );
//!
//! CREATE INDEX IF NOT EXISTS idx_devices_fingerprint
//!     ON devices (tenant_id, fingerprint_hash);
//! CREATE INDEX IF NOT EXISTS idx_devices_user
//!     ON devices (tenant_id, user_id, last_seen_at DESC);
//!
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
//! Mirrors [`super::sqlite::SqliteDeviceStore`] with the SQL-dialect
//! changes Postgres requires (`$1` binds, `BIGINT`, `BYTEA`).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use sqlx::PgPool;

use axess_clock::{Clock, SystemClock};

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::storage::sql_common::{BindingsCodec, SqlDeviceStoreError, trust_level_codec};
use crate::device::store::{DeviceStore, SweepConfig, SweepCounts};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
use crate::session::crypto::SessionCrypto;

/// PostgreSQL-backed [`DeviceStore`].
///
/// Wrap an existing [`PgPool`] and call
/// [`init_schema`](Self::init_schema) once at startup.
///
/// # Encryption
///
/// Same shape as
/// [`SqliteDeviceStore`](super::sqlite::SqliteDeviceStore): the
/// optional [`SessionCrypto`] envelope is applied to the bindings
/// blob only.
#[derive(Clone)]
pub struct PostgresDeviceStore {
    pool: PgPool,
    codec: BindingsCodec,
    clock: Arc<dyn Clock>,
    sweep_config: SweepConfig,
}

impl PostgresDeviceStore {
    /// Create an encrypted store (recommended for production).
    pub fn new(pool: PgPool, crypto: SessionCrypto) -> Self {
        Self {
            pool,
            codec: BindingsCodec::encrypted(crypto),
            clock: Arc::new(SystemClock),
            sweep_config: SweepConfig::default(),
        }
    }

    /// Create a plaintext store (development/testing only).
    pub fn plaintext(pool: PgPool) -> Self {
        tracing::warn!(
            "PostgresDeviceStore created without encryption; \
             do not use in production"
        );
        Self {
            pool,
            codec: BindingsCodec::plaintext(),
            clock: Arc::new(SystemClock),
            sweep_config: SweepConfig::default(),
        }
    }

    /// Inject a [`Clock`] for deterministic-simulation testing.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Override the [`SweepConfig`] driving the retention ladder.
    pub fn with_sweep_config(mut self, config: SweepConfig) -> Self {
        self.sweep_config = config;
        self
    }

    /// Create tables + indexes. Idempotent.
    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS devices (
                tenant_id        TEXT   NOT NULL,
                id               TEXT   NOT NULL,
                user_id          TEXT,
                trust_level      TEXT   NOT NULL,
                fingerprint_hash BYTEA  NOT NULL,
                first_seen_at    BIGINT NOT NULL,
                last_seen_at     BIGINT NOT NULL,
                revoked_at       BIGINT,
                bindings         TEXT   NOT NULL,
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

    fn decode_row(&self, row: DeviceRow) -> Result<Device, SqlDeviceStoreError> {
        let DeviceRow {
            tenant_id,
            id,
            user_id,
            trust_level,
            fingerprint_hash,
            first_seen_at,
            last_seen_at,
            revoked_at,
            bindings,
        } = row;

        let tenant = TenantId::try_new(&tenant_id)
            .map_err(|e| SqlDeviceStoreError::MalformedRow(format!("tenant_id: {e}")))?;
        let device_id = DeviceId::try_new(&id)
            .map_err(|e| SqlDeviceStoreError::MalformedRow(format!("device id: {e}")))?;
        let user = match user_id {
            Some(u) => Some(
                UserId::try_new(&u)
                    .map_err(|e| SqlDeviceStoreError::MalformedRow(format!("user_id: {e}")))?,
            ),
            None => None,
        };

        let trust = trust_level_codec::from_str(&trust_level)
            .ok_or(SqlDeviceStoreError::UnknownTrustLevel(trust_level))?;

        let fp_bytes: [u8; 32] = fingerprint_hash
            .try_into()
            .map_err(|_| SqlDeviceStoreError::MalformedRow("fingerprint_hash length".into()))?;

        let first = unix_to_utc(first_seen_at)?;
        let last = unix_to_utc(last_seen_at)?;
        let revoked = match revoked_at {
            Some(t) => Some(unix_to_utc(t)?),
            None => None,
        };

        let bindings = self.codec.decode(&bindings)?;

        Ok(Device {
            id: device_id,
            tenant_id: tenant,
            user_id: user,
            trust_level: trust,
            fingerprint_hash: FingerprintHash::from_bytes(fp_bytes),
            first_seen_at: first,
            last_seen_at: last,
            revoked_at: revoked,
            bindings,
        })
    }
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    tenant_id: String,
    id: String,
    user_id: Option<String>,
    trust_level: String,
    fingerprint_hash: Vec<u8>,
    first_seen_at: i64,
    last_seen_at: i64,
    revoked_at: Option<i64>,
    bindings: String,
}

fn unix_to_utc(secs: i64) -> Result<DateTime<Utc>, SqlDeviceStoreError> {
    Utc.timestamp_opt(secs, 0).single().ok_or_else(|| {
        SqlDeviceStoreError::MalformedRow(format!("unrepresentable Unix timestamp: {secs}"))
    })
}

fn utc_to_unix(dt: DateTime<Utc>) -> i64 {
    dt.timestamp()
}

fn refresh_family_ids(bindings: &[DeviceBinding]) -> Vec<String> {
    bindings
        .iter()
        .filter_map(|b| match b {
            DeviceBinding::Refresh { family_id, .. } => Some(family_id.clone()),
            _ => None,
        })
        .collect()
}

impl DeviceStore for PostgresDeviceStore {
    type Error = SqlDeviceStoreError;

    fn load(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let pool = self.pool.clone();
        let store = self.clone();
        let tenant = tenant_id.to_string().to_string();
        let device_id = id.to_string().to_string();
        async move {
            let row: Option<DeviceRow> = sqlx::query_as(
                "SELECT tenant_id, id, user_id, trust_level, fingerprint_hash, \
                        first_seen_at, last_seen_at, revoked_at, bindings \
                 FROM devices WHERE tenant_id = $1 AND id = $2",
            )
            .bind(&tenant)
            .bind(&device_id)
            .fetch_optional(&pool)
            .await?;

            match row {
                Some(r) => Ok(Some(store.decode_row(r)?)),
                None => Ok(None),
            }
        }
    }

    fn find_by_fingerprint(
        &self,
        tenant_id: &TenantId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let pool = self.pool.clone();
        let store = self.clone();
        let tenant = tenant_id.to_string().to_string();
        let bytes = hash.as_bytes().to_vec();
        async move {
            let row: Option<DeviceRow> = sqlx::query_as(
                "SELECT tenant_id, id, user_id, trust_level, fingerprint_hash, \
                        first_seen_at, last_seen_at, revoked_at, bindings \
                 FROM devices WHERE tenant_id = $1 AND fingerprint_hash = $2 \
                 ORDER BY last_seen_at DESC LIMIT 1",
            )
            .bind(&tenant)
            .bind(&bytes)
            .fetch_optional(&pool)
            .await?;

            match row {
                Some(r) => Ok(Some(store.decode_row(r)?)),
                None => Ok(None),
            }
        }
    }

    fn find_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        let pool = self.pool.clone();
        let store = self.clone();
        let tenant = tenant_id.to_string().to_string();
        let uid = user_id.to_string().to_string();
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        async move {
            let rows: Vec<DeviceRow> = sqlx::query_as(
                "SELECT tenant_id, id, user_id, trust_level, fingerprint_hash, \
                        first_seen_at, last_seen_at, revoked_at, bindings \
                 FROM devices WHERE tenant_id = $1 AND user_id = $2 \
                 ORDER BY last_seen_at DESC LIMIT $3",
            )
            .bind(&tenant)
            .bind(&uid)
            .bind(limit_i64)
            .fetch_all(&pool)
            .await?;

            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                out.push(store.decode_row(r)?);
            }
            Ok(out)
        }
    }

    fn find_by_refresh_family(
        &self,
        tenant_id: &TenantId,
        family_id: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        let pool = self.pool.clone();
        let store = self.clone();
        let tenant = tenant_id.to_string().to_string();
        let family = family_id.to_string();
        async move {
            let rows: Vec<DeviceRow> = sqlx::query_as(
                "SELECT d.tenant_id, d.id, d.user_id, d.trust_level, d.fingerprint_hash, \
                        d.first_seen_at, d.last_seen_at, d.revoked_at, d.bindings \
                 FROM devices d \
                 INNER JOIN device_bindings_refresh r \
                   ON d.tenant_id = r.tenant_id AND d.id = r.device_id \
                 WHERE r.tenant_id = $1 AND r.family_id = $2 \
                 ORDER BY d.last_seen_at DESC",
            )
            .bind(&tenant)
            .bind(&family)
            .fetch_all(&pool)
            .await?;

            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                out.push(store.decode_row(r)?);
            }
            Ok(out)
        }
    }

    fn save(&self, device: &Device) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let pool = self.pool.clone();
        let codec = self.codec.clone();
        let device = device.clone();
        async move {
            let bindings_blob = codec.encode(&device.bindings)?;
            let trust = trust_level_codec::to_str(device.trust_level);
            let fp = device.fingerprint_hash.as_bytes().to_vec();
            let user_id_col = device.user_id.as_ref().map(|u| u.to_string().to_string());
            let first = utc_to_unix(device.first_seen_at);
            let last = utc_to_unix(device.last_seen_at);
            let revoked = device.revoked_at.map(utc_to_unix);
            let family_ids = refresh_family_ids(&device.bindings);
            let tenant = device.tenant_id.to_string().to_string();
            let id = device.id.to_string().to_string();

            let mut tx = pool.begin().await?;

            sqlx::query(
                r#"
                INSERT INTO devices
                    (tenant_id, id, user_id, trust_level, fingerprint_hash,
                     first_seen_at, last_seen_at, revoked_at, bindings)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (tenant_id, id) DO UPDATE SET
                    user_id          = EXCLUDED.user_id,
                    trust_level      = EXCLUDED.trust_level,
                    fingerprint_hash = EXCLUDED.fingerprint_hash,
                    first_seen_at    = EXCLUDED.first_seen_at,
                    last_seen_at     = EXCLUDED.last_seen_at,
                    revoked_at       = EXCLUDED.revoked_at,
                    bindings         = EXCLUDED.bindings
                "#,
            )
            .bind(&tenant)
            .bind(&id)
            .bind(user_id_col.as_deref())
            .bind(trust)
            .bind(&fp)
            .bind(first)
            .bind(last)
            .bind(revoked)
            .bind(&bindings_blob)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "DELETE FROM device_bindings_refresh \
                 WHERE tenant_id = $1 AND device_id = $2",
            )
            .bind(&tenant)
            .bind(&id)
            .execute(&mut *tx)
            .await?;

            for family_id in &family_ids {
                sqlx::query(
                    "INSERT INTO device_bindings_refresh \
                     (tenant_id, device_id, family_id) VALUES ($1, $2, $3)",
                )
                .bind(&tenant)
                .bind(&id)
                .bind(family_id)
                .execute(&mut *tx)
                .await?;
            }

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
        let tenant = tenant_id.to_string().to_string();
        let device_id = id.to_string().to_string();
        let ts = utc_to_unix(now);
        async move {
            sqlx::query(
                "UPDATE devices SET last_seen_at = $3 \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(&tenant)
            .bind(&device_id)
            .bind(ts)
            .execute(&pool)
            .await?;
            Ok(())
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
        let tenant = tenant_id.to_string().to_string();
        let device_id = id.to_string().to_string();
        let trust = trust_level_codec::to_str(level);
        let ts = utc_to_unix(now);
        let revoked_at = match level {
            DeviceTrustLevel::Revoked => Some(ts),
            _ => None,
        };
        async move {
            sqlx::query(
                "UPDATE devices SET trust_level = $3, revoked_at = $4 \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(&tenant)
            .bind(&device_id)
            .bind(trust)
            .bind(revoked_at)
            .execute(&pool)
            .await?;
            Ok(())
        }
    }

    fn delete(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let pool = self.pool.clone();
        let tenant = tenant_id.to_string().to_string();
        let device_id = id.to_string().to_string();
        async move {
            sqlx::query("DELETE FROM devices WHERE tenant_id = $1 AND id = $2")
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
        let cfg = self.sweep_config;
        let tenant = tenant_id.to_string().to_string();
        let now_secs = utc_to_unix(now);
        async move {
            let trusted_cutoff = now_secs - cfg.trusted_idle.num_seconds();
            let seen_cutoff = now_secs - cfg.seen_idle.num_seconds();
            let grace_cutoff = now_secs - cfg.revoked_grace.num_seconds();

            let trusted_demoted = sqlx::query(
                "UPDATE devices SET trust_level = 'Seen' \
                 WHERE tenant_id = $1 \
                   AND trust_level = 'Trusted' \
                   AND last_seen_at < $2",
            )
            .bind(&tenant)
            .bind(trusted_cutoff)
            .execute(&pool)
            .await?
            .rows_affected();

            let seen_demoted = sqlx::query(
                "UPDATE devices SET trust_level = 'Revoked', revoked_at = $3 \
                 WHERE tenant_id = $1 \
                   AND trust_level = 'Seen' \
                   AND last_seen_at < $2",
            )
            .bind(&tenant)
            .bind(seen_cutoff)
            .bind(now_secs)
            .execute(&pool)
            .await?
            .rows_affected();

            let purged = sqlx::query(
                "DELETE FROM devices \
                 WHERE tenant_id = $1 \
                   AND trust_level = 'Revoked' \
                   AND revoked_at IS NOT NULL \
                   AND revoked_at < $2",
            )
            .bind(&tenant)
            .bind(grace_cutoff)
            .execute(&pool)
            .await?
            .rows_affected();

            Ok(SweepCounts {
                trusted_to_seen: trusted_demoted,
                seen_to_revoked: seen_demoted,
                revoked_purged: purged,
            })
        }
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────

use crate::health::{HealthCheck, HealthStatus};

impl HealthCheck for PostgresDeviceStore {
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
                Ok(Err(e)) => HealthStatus::Unhealthy(format!("postgres SELECT 1 failed: {e}")),
                Err(_) => HealthStatus::Unhealthy("postgres SELECT 1 timeout (2s)".into()),
            }
        })
    }
}

// Integration tests live in `axess-core/tests/postgres_device_store.rs`
//; they require a running Postgres at $POSTGRES_URL and run with
// `cargo test -- --ignored`. Mirrors the pattern used by
// `tests/postgres_store.rs` for the session-store equivalent.
