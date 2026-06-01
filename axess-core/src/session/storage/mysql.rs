//! MySQL- and MariaDB-backed session store using sqlx.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS sessions (
//!   id VARCHAR(64) PRIMARY KEY,
//!   data TEXT NOT NULL,
//!   expires_at BIGINT NOT NULL,
//!   INDEX idx_sessions_expires_at (expires_at)
//! );
//! ```
//!
//! The schema mirrors the Postgres backend (TEXT data, BIGINT
//! Unix-epoch-seconds expiry) so the same codec output round-trips
//! identically across SQL backends. Only the DDL dialect, placeholder
//! syntax (`?` vs `$N`), and UPSERT idiom differ.

use crate::session::storage::session_codec::{SessionCodec, SqlStoreError, expires_at};
use crate::session::storage::sql_helpers::log_cleanup_outcome;
use crate::session::{data::SessionData, id::SessionId, store::SessionStore};
use axess_clock::{Clock, SystemClock};
use sqlx::MySqlPool;
use std::sync::Arc;
use std::time::Duration;

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
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id VARCHAR(64) PRIMARY KEY,
                data TEXT NOT NULL,
                expires_at BIGINT NOT NULL,
                INDEX idx_sessions_expires_at (expires_at)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
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

        let row: Option<(String,)> =
            sqlx::query_as("SELECT data FROM sessions WHERE id = ? AND expires_at > ?")
                .bind(&id_str)
                .bind(now)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((stored,)) => Ok(Some(self.codec.decode(&stored)?)),
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
        let encoded = self.codec.encode(data)?;
        let exp = expires_at(&*self.clock, ttl);

        // MySQL UPSERT; `ON DUPLICATE KEY UPDATE` updates the existing
        // row when the primary key collides. `VALUES(col)` references
        // the value the INSERT attempted to write; deprecated in
        // MySQL 8.0.20 in favour of `... AS new ON DUPLICATE KEY UPDATE
        // col = new.col`, but `VALUES(col)` still works and is
        // compatible with MariaDB through 10.x.
        sqlx::query(
            r#"
            INSERT INTO sessions (id, data, expires_at)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE data = VALUES(data), expires_at = VALUES(expires_at)
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

    async fn cycle(
        &self,
        old_id: &SessionId,
        new_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        let encoded = self.codec.encode(data)?;
        let exp = expires_at(&*self.clock, ttl);
        let old_str = old_id.to_string();
        let new_str = new_id.to_string();

        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(&old_str)
            .execute(&mut *tx)
            .await?;

        sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?, ?, ?)")
            .bind(&new_str)
            .bind(&encoded)
            .bind(exp)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
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
