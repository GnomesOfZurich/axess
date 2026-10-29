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
//!     INDEX idx_devices_fingerprint_seen (tenant_id, fingerprint_hash, last_seen_at, id),
//!     INDEX idx_devices_sweep (tenant_id, trust_level, last_seen_at),
//!     INDEX idx_devices_revoked_at (tenant_id, trust_level, revoked_at),
//!     INDEX idx_devices_user (tenant_id, user_id, last_seen_at),
//!     INDEX idx_devices_user_fingerprint (tenant_id, user_id, fingerprint_hash, last_seen_at)
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
//!     (tenant_id, user_id, fingerprint_hash, last_seen_at);
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
//!         (tenant_id, fingerprint_hash, last_seen_at, id),
//!     ADD INDEX idx_devices_sweep (tenant_id, trust_level, last_seen_at),
//!     ADD INDEX idx_devices_revoked_at (tenant_id, trust_level, revoked_at);
//! ```
//!
//! MySQL `CREATE INDEX` is not idempotent (no `IF NOT EXISTS` for
//! indexes pre-MySQL 8.0.29 / MariaDB 10.5.4), so indexes are
//! declared inline in `CREATE TABLE`. Mirrors the dialect strategy
//! used by [`crate::session::storage::mysql::MysqlSessionStore`].
//!
//! `last_seen_at` index does not include `DESC` because MySQL did
//! not support descending indexes until 8.0; the optimiser handles
//! descending range scans on an ascending index acceptably for the
//! row counts this surface deals with.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axess_clock::Clock;
use chrono::{DateTime, Utc};
use sqlx::MySqlPool;

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::storage::sql_common::{
    BindingsCodec, DeviceRow, DeviceWrite, GuardedTrustWrite, SqlDeviceStoreError, SwapPlan,
    SweepCutoffs, TRANSITION_ATTEMPTS, TrustWrite, bindings_update_after_miss, claim_after_miss,
    decode_all, decode_optional, index_follows_write, parse_stored_trust, plan_bindings_swap,
    require_row, select_devices, sighting_level, transition_after_miss, utc_to_unix,
};
use crate::device::store::{
    BindingsUpdate, DeviceStore, OwnerClaim, SweepConfig, SweepCounts, TrustTransition,
    blocks_save, for_save,
};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
use crate::session::crypto::SessionCrypto;

mod family;
mod reseal;
mod schema;
mod sweep;

use reseal::reseal_rows;

use family::{fetch_trust_level, rewrite_family_index};

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

#[cfg(test)]
mod schema_tests;

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
                "WHERE tenant_id = ? AND fingerprint_hash = ? \
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
                "WHERE tenant_id = ? AND user_id = ? AND fingerprint_hash = ? \
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
                "WHERE tenant_id = ? AND user_id = ? \
                 ORDER BY last_seen_at DESC, id ASC LIMIT ?"
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
                 WHERE r.tenant_id = ? AND r.family_id = ? \
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

            // MySQL upsert: `INSERT … ON DUPLICATE KEY UPDATE col = VALUES(col)`.
            // MySQL applies the assignments left to right and a later one
            // sees the columns an earlier one changed, so `trust_level`,
            // which every guard reads, is assigned last.
            // `VALUES(col)` reads the value that would have been inserted; works
            // back to MySQL 5.7 and MariaDB 10.x. The modern `AS new` row-alias
            // form is MySQL 8.0.20+ only; staying on `VALUES(...)` keeps
            // MariaDB compatibility without a version-check branch.
            //
            // Wrap the device-row upsert and the refresh-binding index
            // refresh in a single transaction so a concurrent
            // `find_by_refresh_family` either sees the pre-update or
            // the post-update set, never a partially-updated index.
            let mut tx = pool.begin().await?;

            // A save never un-revokes: a device loaded before a revocation
            // and saved after it leaves the revoked row as it is. The row is
            // read here only to skip the index rewrite and the write; the
            // upsert below carries the same rule itself, so a revocation
            // that lands between the two statements is still not undone.
            // (No `FOR UPDATE`: on an absent row it takes a gap lock, and
            // two first saves would deadlock on their inserts.)
            let stored: Option<String> = sqlx::query_scalar(
                "SELECT trust_level FROM devices WHERE tenant_id = ? AND id = ?",
            )
            .bind(&w.tenant)
            .bind(&w.id)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(stored) = parse_stored_trust(stored)?
                && blocks_save(stored)
            {
                return Ok(());
            }

            sqlx::query(
                r#"
                INSERT INTO devices
                    (tenant_id, id, user_id, trust_level, fingerprint_hash,
                     first_seen_at, last_seen_at, revoked_at, demoted_at, bindings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    user_id          = IF(trust_level = 'Revoked', user_id, VALUES(user_id)),
                    fingerprint_hash = IF(trust_level = 'Revoked', fingerprint_hash, VALUES(fingerprint_hash)),
                    first_seen_at    = IF(trust_level = 'Revoked', first_seen_at, VALUES(first_seen_at)),
                    last_seen_at     = IF(trust_level = 'Revoked', last_seen_at, VALUES(last_seen_at)),
                    revoked_at       = IF(trust_level = 'Revoked', revoked_at, VALUES(revoked_at)),
                    demoted_at       = IF(trust_level = 'Revoked', demoted_at, VALUES(demoted_at)),
                    bindings         = IF(trust_level = 'Revoked', bindings, VALUES(bindings)),
                    trust_level      = IF(trust_level = 'Revoked', trust_level, VALUES(trust_level))
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

            // The upsert leaves a row that was revoked meanwhile exactly as
            // it was, so the refresh-family index follows the bindings the
            // row holds now, not the ones this save carried. Ciphertext
            // differs on every encode, so the stored bytes are this save's
            // own only when the upsert wrote them.
            let stored: Option<String> =
                sqlx::query_scalar("SELECT bindings FROM devices WHERE tenant_id = ? AND id = ?")
                    .bind(&w.tenant)
                    .bind(&w.id)
                    .fetch_optional(&mut *tx)
                    .await?;
            if index_follows_write(stored.as_deref(), &w.bindings) {
                rewrite_family_index(&mut tx, &w.tenant, &w.id, &w.family_ids).await?;
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
    ) -> impl Future<Output = Result<DeviceTrustLevel, Self::Error>> + Send {
        let pool = self.pool.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        let ts = utc_to_unix(now);
        async move {
            sqlx::query(
                "UPDATE devices SET last_seen_at = CASE \
                     WHEN trust_level <> 'Revoked' AND last_seen_at < ? THEN ? \
                     ELSE last_seen_at END \
                 WHERE tenant_id = ? AND id = ?",
            )
            .bind(ts)
            .bind(ts)
            .bind(&tenant)
            .bind(&device_id)
            .execute(&pool)
            .await?;
            // The level the row has now: Revoked means the sighting did not
            // touch it. A missing row is a missing device.
            sighting_level(
                fetch_trust_level(&pool, &tenant, &device_id).await?,
                tenant,
                device_id,
            )
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
        let pool = self.pool.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        let w = GuardedTrustWrite::new(expected, level, now);
        async move {
            // One conditional UPDATE: the engine checks the current level
            // and writes in a single statement, so a revocation that lands
            // first makes this match no row instead of being overwritten.
            for _ in 0..TRANSITION_ATTEMPTS {
                let updated = sqlx::query("UPDATE devices SET demoted_at = CASE WHEN ? = 1 THEN demoted_at ELSE ? END, revoked_at = CASE WHEN ? = ? THEN revoked_at ELSE ? END, trust_level = ? WHERE tenant_id = ? AND id = ? AND trust_level = ?")
            .bind(w.keep_demoted)
            .bind(w.demoted_at)
            .bind(w.expected)
            .bind(w.new)
            .bind(w.revoked_at)
            .bind(w.new)
            .bind(&tenant)
            .bind(&device_id)
            .bind(w.expected)
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
            // Every attempt lost a race: the row was never found at another
            // level, so the change is neither applied nor refused.
            Err(SqlDeviceStoreError::Contended {
                tenant_id: tenant,
                device_id,
            })
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
                "SELECT trust_level, bindings FROM devices WHERE tenant_id = ? AND id = ?",
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
            let updated = sqlx::query("UPDATE devices SET bindings = ? WHERE tenant_id = ? AND id = ? AND trust_level <> 'Revoked' AND CAST(bindings AS BINARY) = CAST(? AS BINARY)")
                .bind(&swap.blob)
                .bind(&tenant)
                .bind(&device_id)
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
                "UPDATE devices SET user_id = ? \
                 WHERE tenant_id = ? AND id = ? AND user_id IS NULL",
            )
            .bind(&user)
            .bind(&tenant)
            .bind(&device_id)
            .execute(&pool)
            .await?
            .rows_affected();
            if updated > 0 {
                return Ok(OwnerClaim::Claimed);
            }
            let owner: Option<Option<String>> =
                sqlx::query_scalar("SELECT user_id FROM devices WHERE tenant_id = ? AND id = ?")
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
        async move { sweep::run(&pool, &tenant, &cutoffs).await }
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

#[cfg(test)]
mod reseal_tests;
