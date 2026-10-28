//! MySQL- and MariaDB-backed session store using sqlx.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS sessions (
//!   id VARCHAR(64) PRIMARY KEY,
//!   data MEDIUMTEXT NOT NULL,
//!   data_bin LONGBLOB,
//!   expires_at BIGINT NOT NULL,
//!   INDEX idx_sessions_expires_at (expires_at)
//! );
//! ```
//!
//! The schema mirrors the Postgres backend (text `data`, BIGINT
//! Unix-epoch-seconds expiry) so the same codec output round-trips
//! identically across SQL backends. Only the DDL dialect, placeholder
//! syntax (`?` vs `$N`), and UPSERT idiom differ.
//!
//! `data` is `MEDIUMTEXT` (16 MiB), not `TEXT` (64 KiB): the column holds the
//! base64 of the serialised, optionally encrypted session, and a session
//! whose custom data approaches its own size limit outgrows 64 KiB, which
//! MySQL in strict mode then rejects on write.
//!
//! # Upgrading an existing deployment
//!
//! `CREATE TABLE IF NOT EXISTS` leaves an existing table as it is, so a
//! deployment created with `data TEXT` must run, once:
//!
//! ```sql
//! ALTER TABLE sessions MODIFY data MEDIUMTEXT NOT NULL;
//! ```
//!
//! and, for the binary column, once, before the new code serves a request
//! (a load selects `data_bin`):
//!
//! ```sql
//! ALTER TABLE sessions ADD COLUMN data_bin LONGBLOB NULL;
//! ```
//!
//! `data_bin` holds the session as raw bytes (MessagePack, sealed with
//! AES-256-GCM when encryption is on). `data` is the base64 text column of
//! earlier releases: rows written by them keep working because a load reads
//! `data_bin` first and falls back to `data`, and every save writes
//! `data_bin` and empties `data`, so a legacy row is rewritten when it is
//! loaded (the store re-seals it) or saved. `data` stays `NOT NULL`, so new rows carry an
//! empty string there. Rolling back to the earlier release afterwards cannot
//! read a row this release saved (the text column is empty): that user signs
//! in again.

use crate::session::storage::session_codec::{SessionCodec, SqlStoreError, expires_at};
use crate::session::storage::sql_helpers::log_cleanup_outcome;
use crate::session::{
    data::SessionData,
    id::SessionId,
    store::{CycleOutcome, SessionStore},
};
use axess_clock::{Clock, SystemClock};
use sqlx::MySqlPool;
use std::sync::Arc;
use std::time::Duration;

/// The `sessions` table. `data` is `MEDIUMTEXT`: see the module docs.
const SESSIONS_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(64) PRIMARY KEY,
    data MEDIUMTEXT NOT NULL,
    data_bin LONGBLOB,
    expires_at BIGINT NOT NULL,
    INDEX idx_sessions_expires_at (expires_at)
)
"#;

/// Backward-compatible alias: adopters can write `MysqlStoreError`
/// for readability; the underlying type is the shared [`SqlStoreError`].
pub type MysqlStoreError = SqlStoreError;

/// MySQL/MariaDB session store with AES-256-GCM encryption at rest.
///
/// Wrap an existing [`MySqlPool`] and call [`init_schema`](Self::init_schema)
/// once at startup. **Production deployments must also schedule
/// cleanup** of expired session rows: either by calling
/// [`spawn_cleanup_task`](Self::spawn_cleanup_task) at startup, configuring
/// the MySQL event scheduler with an equivalent DELETE statement, or
/// running an external job that invokes [`cleanup_expired`](Self::cleanup_expired).
///
/// # Encryption
///
/// The primary constructor [`new`](MysqlSessionStore::new) requires a
/// [`SessionCrypto`](crate::session::crypto::SessionCrypto) key: session
/// data is encrypted before storage and decrypted on load. For local
/// development or testing where encryption is not needed, use
/// [`plaintext`](MysqlSessionStore::plaintext) instead.
///
/// ```rust,ignore
/// use axess::session::SessionCrypto;
///
/// let store = MysqlSessionStore::new(pool, SessionCrypto::new(key));
/// store.init_schema().await?;
/// let _cleanup = store.spawn_cleanup_task(std::time::Duration::from_secs(3600));
/// ```
#[derive(Clone)]
pub struct MysqlSessionStore {
    pool: MySqlPool,
    codec: SessionCodec,
    clock: Arc<dyn Clock>,
}

impl MysqlSessionStore {
    /// Create an **encrypted** store (recommended for production).
    pub fn new(pool: MySqlPool, crypto: crate::session::crypto::SessionCrypto) -> Self {
        Self {
            pool,
            codec: SessionCodec::encrypted(crypto),
            clock: Arc::new(SystemClock),
        }
    }

    /// Create a **plaintext** store (development/testing only).
    pub fn plaintext(pool: MySqlPool) -> Self {
        tracing::warn!(
            "MysqlSessionStore created without encryption; \
             do not use in production"
        );
        Self {
            pool,
            codec: SessionCodec::plaintext(),
            clock: Arc::new(SystemClock),
        }
    }

    /// Inject a [`Clock`] for deterministic-simulation testing.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Create the `sessions` table and index if they don't already exist.
    ///
    /// MySQL's `CREATE INDEX` is not idempotent (no `IF NOT EXISTS`
    /// for indexes before MariaDB 10.5.4 / MySQL 8.0.29), so the
    /// index is declared inline in the CREATE TABLE statement instead.
    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        sqlx::query(SESSIONS_DDL).execute(&self.pool).await?;

        Ok(())
    }

    /// Re-seal a row that was read in an older form (a blob without the
    /// current row binding, or the legacy text column) in the current
    /// format. Best effort: the write is conditional on the row still
    /// holding exactly the bytes that were read, so a save that landed
    /// meanwhile is never overwritten, and the row keeps its expiry. A
    /// failure is logged and the row is re-sealed by its next save.
    async fn reseal(
        &self,
        id: &SessionId,
        data: &SessionData,
        binary: Option<&[u8]>,
        text: &str,
        now: i64,
    ) {
        let sealed = match self.codec.encode_bytes(id, data) {
            Ok(sealed) => sealed,
            Err(e) => {
                tracing::warn!(error = %e, "could not re-seal a stale session row");
                return;
            }
        };
        let id_str = id.to_string();
        let result = match binary {
            Some(old) => {
                sqlx::query(
                    "UPDATE sessions SET data = '', data_bin = ? \
                     WHERE id = ? AND expires_at > ? AND data_bin = ?",
                )
                .bind(&sealed)
                .bind(&id_str)
                .bind(now)
                .bind(old)
                .execute(&self.pool)
                .await
            }
            None => {
                sqlx::query(
                    "UPDATE sessions SET data = '', data_bin = ? \
                     WHERE id = ? AND expires_at > ? AND data_bin IS NULL AND data = ?",
                )
                .bind(&sealed)
                .bind(&id_str)
                .bind(now)
                .bind(text)
                .execute(&self.pool)
                .await
            }
        };
        if let Err(e) = result {
            tracing::warn!(error = %e, "could not re-seal a stale session row");
        }
    }

    /// Delete all sessions whose `expires_at` is in the past.
    pub async fn cleanup_expired(&self) -> Result<u64, sqlx::Error> {
        let now = self.clock.now().timestamp();
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Spawn a background task that calls [`cleanup_expired`](Self::cleanup_expired)
    /// on a fixed interval. See the Postgres backend doc for the rationale
    /// (same shape, same lifetime requirements).
    pub fn spawn_cleanup_task(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                log_cleanup_outcome("mysql", store.cleanup_expired().await);
            }
        })
    }
}

impl SessionStore for MysqlSessionStore {
    type Error = SqlStoreError;

    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        let id_str = id.to_string();
        let now = self.clock.now().timestamp();

        let row: Option<(Option<Vec<u8>>, String)> =
            sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = ? AND expires_at > ?")
                .bind(&id_str)
                .bind(now)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((binary, text)) => {
                let (data, stale) = self.codec.decode_row(id, binary.as_deref(), &text)?;
                if stale {
                    self.reseal(id, &data, binary.as_deref(), &text, now).await;
                }
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    async fn save(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        let id_str = id.to_string();
        let encoded = self.codec.encode_bytes(id, data)?;
        let exp = expires_at(&*self.clock, ttl);

        // MySQL UPSERT; `ON DUPLICATE KEY UPDATE` updates the existing
        // row when the primary key collides. `VALUES(col)` references
        // the value the INSERT attempted to write; deprecated in
        // MySQL 8.0.20 in favour of `... AS new ON DUPLICATE KEY UPDATE
        // col = new.col`, but `VALUES(col)` still works and is
        // compatible with MariaDB through 10.x.
        sqlx::query(
            r#"
            INSERT INTO sessions (id, data, data_bin, expires_at)
            VALUES (?, '', ?, ?)
            ON DUPLICATE KEY UPDATE data = '', data_bin = VALUES(data_bin), expires_at = VALUES(expires_at)
            "#,
        )
        .bind(&id_str)
        .bind(&encoded)
        .bind(exp)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        let id_str = id.to_string();
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn update(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        let id_str = id.to_string();
        let encoded = self.codec.encode_bytes(id, data)?;
        let exp = expires_at(&*self.clock, ttl);
        let now = self.clock.now().timestamp();

        let result = sqlx::query(
            "UPDATE sessions SET data = '', data_bin = ?, expires_at = ? \
             WHERE id = ? AND expires_at > ?",
        )
        .bind(&encoded)
        .bind(exp)
        .bind(&id_str)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn cycle(
        &self,
        old_id: &SessionId,
        new_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        let encoded = self.codec.encode_bytes(new_id, data)?;
        let exp = expires_at(&*self.clock, ttl);
        let now = self.clock.now().timestamp();
        let old_str = old_id.to_string();
        let new_str = new_id.to_string();

        let mut tx = self.pool.begin().await?;

        // The delete of the old row comes first and decides whether the
        // rotation may proceed: it takes the row lock, so a logout that
        // deleted the row first leaves nothing to remove here, and a logout
        // that arrives later waits for this transaction. With `require_old`
        // a delete that removed no live row rolls the transaction back (by
        // dropping it) instead of writing the authenticated data under the
        // new id.
        if old_str == new_str {
            if require_old {
                let replaced = sqlx::query(
                    "UPDATE sessions SET data = '', data_bin = ?, expires_at = ? \
                     WHERE id = ? AND expires_at > ?",
                )
                .bind(&encoded)
                .bind(exp)
                .bind(&new_str)
                .bind(now)
                .execute(&mut *tx)
                .await?;
                if replaced.rows_affected() == 0 {
                    return Ok(CycleOutcome::SessionGone);
                }
                tx.commit().await?;
                return Ok(CycleOutcome::Rotated);
            }
        } else {
            let removed = sqlx::query("DELETE FROM sessions WHERE id = ? AND expires_at > ?")
                .bind(&old_str)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            if require_old && removed.rows_affected() == 0 {
                return Ok(CycleOutcome::SessionGone);
            }
            if removed.rows_affected() == 0 {
                // An expired remnant of the old id is removed too.
                sqlx::query("DELETE FROM sessions WHERE id = ?")
                    .bind(&old_str)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        sqlx::query(
            r#"
            INSERT INTO sessions (id, data, data_bin, expires_at)
            VALUES (?, '', ?, ?)
            ON DUPLICATE KEY UPDATE data = '', data_bin = VALUES(data_bin), expires_at = VALUES(expires_at)
            "#,
        )
        .bind(&new_str)
        .bind(&encoded)
        .bind(exp)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(CycleOutcome::Rotated)
    }

    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        Ok(self.cleanup_expired().await?)
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────────────

use crate::health::{HealthCheck, HealthStatus};
use crate::session::storage::sql_helpers::sql_health_probe;

impl HealthCheck for MysqlSessionStore {
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(sql_health_probe(
            "mysql",
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool),
        ))
    }
}

// ── Store<SessionId, SessionData> ────────────────────────────────────────────
//
// surface; see the same impl on `SqliteSessionStore` /
// `PostgresSessionStore` for rationale. Identical body shape.

impl crate::store::Store<SessionId, SessionData> for MysqlSessionStore {
    type Error = SqlStoreError;

    fn get(
        &self,
        key: &SessionId,
    ) -> impl std::future::Future<Output = Result<Option<SessionData>, Self::Error>> + Send {
        <Self as SessionStore>::load(self, key)
    }

    fn put(
        &self,
        key: &SessionId,
        value: &SessionData,
        ttl: Duration,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        <Self as SessionStore>::save(self, key, value, ttl)
    }

    fn delete(
        &self,
        key: &SessionId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        <Self as SessionStore>::delete(self, key)
    }

    fn prune_expired(&self) -> impl std::future::Future<Output = Result<u64, Self::Error>> + Send {
        <Self as SessionStore>::prune_expired(self)
    }
}

#[cfg(test)]
mod schema_tests;

#[cfg(test)]
mod live_tests;

#[cfg(test)]
mod mysql_tests {
    //! Pin every `<impl SessionStore for MysqlSessionStore>` body
    //! against `Ok(...)` body-replacement mutations without requiring a
    //! live MySQL/MariaDB. Strategy mirrors the Postgres backend: a
    //! `MySqlPool` created via `connect_lazy` against a port that
    //! refuses connections produces a deterministic `sqlx::Error` on the
    //! first DB round-trip. Real impl: returns `Err`. Mutated impl:
    //! returns `Ok(...)`. The two are distinguishable.
    use super::*;
    use crate::session::data::SessionData;
    use crate::session::id::SessionId;
    use crate::testing::mock_tracing::TracingCapture;
    use sqlx::mysql::MySqlPoolOptions;

    fn unreachable_pool() -> MySqlPool {
        // 127.0.0.1:1; port 1 is reserved IANA and never opened by
        // local services. `connect_lazy` does not initiate a
        // connection, so this constructor itself never blocks; the
        // first query will fail with ECONNREFUSED in well under the
        // 200 ms acquire timeout.
        MySqlPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("mysql://user:pass@127.0.0.1:1/nodb")
            .expect("connect_lazy must parse a valid URL")
    }

    fn store() -> MysqlSessionStore {
        MysqlSessionStore::plaintext(unreachable_pool())
    }

    fn sample_id() -> SessionId {
        SessionId::new(&axess_rng::SystemRng)
    }

    #[tokio::test]
    async fn plaintext_constructor_emits_warning() {
        let capture = TracingCapture::install();
        drop(MysqlSessionStore::plaintext(unreachable_pool()));
        assert!(
            capture.contains_at_level(tracing::Level::WARN, "without encryption"),
            "plaintext() must warn operators; captured events: {:#?}",
            capture.events()
        );
    }

    #[tokio::test]
    async fn load_propagates_connection_error_not_ok_none() {
        let result = store().load(&sample_id()).await;
        assert!(
            result.is_err(),
            "load must propagate sqlx error from an unreachable pool, \
             not silently return an Ok variant"
        );
    }

    #[tokio::test]
    async fn save_propagates_connection_error_not_ok_unit() {
        let result = store()
            .save(
                &sample_id(),
                &SessionData::default(),
                Duration::from_secs(60),
            )
            .await;
        assert!(
            result.is_err(),
            "save must propagate sqlx error, not Ok(())"
        );
    }

    #[tokio::test]
    async fn delete_propagates_connection_error_not_ok_unit() {
        let result = store().delete(&sample_id()).await;
        assert!(
            result.is_err(),
            "delete must propagate sqlx error, not Ok(())"
        );
    }

    #[tokio::test]
    async fn cycle_propagates_connection_error_not_ok_unit() {
        let result = store()
            .cycle(
                &sample_id(),
                &sample_id(),
                &SessionData::default(),
                Duration::from_secs(60),
                true,
            )
            .await;
        assert!(
            result.is_err(),
            "cycle must propagate sqlx error, not Ok(())"
        );
    }

    #[tokio::test]
    async fn prune_expired_propagates_connection_error_not_ok_count() {
        let result = store().prune_expired().await;
        assert!(
            result.is_err(),
            "prune_expired must propagate sqlx error, not an Ok(u64) count"
        );
    }

    #[tokio::test]
    async fn cleanup_expired_propagates_connection_error_not_ok_count() {
        let result = store().cleanup_expired().await;
        assert!(
            result.is_err(),
            "cleanup_expired must propagate sqlx error, not an Ok(u64) count"
        );
    }

    #[tokio::test]
    async fn init_schema_propagates_connection_error_not_ok_unit() {
        let result = store().init_schema().await;
        assert!(
            result.is_err(),
            "init_schema must propagate sqlx error, not Ok(())"
        );
    }

    #[tokio::test]
    async fn health_check_returns_unhealthy_on_unreachable_pool() {
        let status = store().check().await;
        assert!(
            matches!(status, HealthStatus::Unhealthy(_)),
            "check() must report Unhealthy against unreachable pool, got {status:?}"
        );
    }
}
