//! PostgreSQL-backed session store using sqlx.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS sessions (
//!   id TEXT PRIMARY KEY,
//!   data TEXT NOT NULL,
//!   expires_at BIGINT NOT NULL
//! );
//!
//! CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
//! ```

use crate::session::storage::session_codec::{SessionCodec, SqlStoreError, expires_at};
use crate::session::storage::sql_helpers::log_cleanup_outcome;
use crate::session::{data::SessionData, id::SessionId, store::SessionStore};
use axess_clock::{Clock, SystemClock};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

/// Backward-compatible type alias. Use [`SqlStoreError`] directly in new code.
pub type PostgresStoreError = SqlStoreError;

/// PostgreSQL-backed session store with AES-256-GCM encryption at rest.
///
/// Wrap an existing [`PgPool`] and call [`init_schema`](Self::init_schema) once at startup.
/// **Production deployments must also schedule cleanup** of expired session
/// rows: either by calling [`spawn_cleanup_task`](Self::spawn_cleanup_task)
/// at startup, configuring `pg_cron` on the database side, or running an
/// external job that invokes [`cleanup_expired`](Self::cleanup_expired).
/// Without one of these, the `sessions` table grows unbounded.
///
/// # Encryption
///
/// The primary constructor [`new`](PostgresSessionStore::new) requires a
/// [`SessionCrypto`](crate::session::crypto::SessionCrypto) key; session data
/// is encrypted before storage and decrypted on load.
///
/// For local development or testing where encryption is not needed, use
/// [`plaintext`](PostgresSessionStore::plaintext) instead.
///
/// ```rust,ignore
/// use axess::session::SessionCrypto;
///
/// // Production: encrypted (required).
/// let store = PostgresSessionStore::new(pool, SessionCrypto::new(key));
///
/// // Development only: plaintext (explicit opt-out).
/// let store = PostgresSessionStore::plaintext(pool);
/// ```
#[derive(Clone)]
pub struct PostgresSessionStore {
    pool: PgPool,
    codec: SessionCodec,
    clock: Arc<dyn Clock>,
}

impl PostgresSessionStore {
    /// Create an **encrypted** store (recommended for production).
    pub fn new(pool: PgPool, crypto: crate::session::crypto::SessionCrypto) -> Self {
        Self {
            pool,
            codec: SessionCodec::encrypted(crypto),
            clock: Arc::new(SystemClock),
        }
    }

    /// Create a **plaintext** store (development/testing only).
    pub fn plaintext(pool: PgPool) -> Self {
        tracing::warn!(
            "PostgresSessionStore created without encryption; \
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
    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                expires_at BIGINT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Delete all sessions whose `expires_at` is in the past.
    pub async fn cleanup_expired(&self) -> Result<u64, sqlx::Error> {
        let now = self.clock.now().timestamp();
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Spawn a background task that calls [`cleanup_expired`](Self::cleanup_expired) on a fixed interval.
    ///
    /// SQL stores accumulate expired session rows forever unless something
    /// removes them. Production deployments **must** either call this
    /// helper once at startup, run an external scheduled job (e.g. `pg_cron`
    /// on the database side), or accept unbounded table growth. The
    /// returned [`tokio::task::JoinHandle`] aborts the loop when dropped,
    /// so store it for the lifetime of the application.
    ///
    /// Errors from `cleanup_expired` are logged at `warn` and swallowed;
    /// the loop keeps running so a single transient DB blip does not
    /// silently halt cleanup forever.
    ///
    /// ```rust,ignore
    /// let store = PostgresSessionStore::new(pool, crypto);
    /// store.init_schema().await?;
    /// let _cleanup = store.spawn_cleanup_task(std::time::Duration::from_secs(3600));
    /// ```
    pub fn spawn_cleanup_task(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                log_cleanup_outcome("postgres", store.cleanup_expired().await);
            }
        })
    }
}

impl SessionStore for PostgresSessionStore {
    type Error = SqlStoreError;

    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        let id_str = id.to_string();
        let now = self.clock.now().timestamp();

        let row: Option<(String,)> =
            sqlx::query_as("SELECT data FROM sessions WHERE id = $1 AND expires_at > $2")
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

        sqlx::query(
            r#"
            INSERT INTO sessions (id, data, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at
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
        sqlx::query("DELETE FROM sessions WHERE id = $1")
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

        sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(&old_str)
            .execute(&mut *tx)
            .await?;

        sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES ($1, $2, $3)")
            .bind(&new_str)
            .bind(&encoded)
            .bind(exp)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        // Trait surface over the existing inherent
        // `cleanup_expired`; applications that hold a `dyn SessionStore`
        // can now drive the sweep without downcasting.
        Ok(self.cleanup_expired().await?)
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────────────

use crate::health::{HealthCheck, HealthStatus};
use crate::session::storage::sql_helpers::sql_health_probe;

impl HealthCheck for PostgresSessionStore {
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(sql_health_probe(
            "postgres",
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool),
        ))
    }
}

// ── Store<SessionId, SessionData> ────────────────────────────────────────────
//
// surface; see the same impl on `SqliteSessionStore` for the
// rationale. Identical body shape (forwards to `SessionStore`).

impl crate::store::Store<SessionId, SessionData> for PostgresSessionStore {
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
mod postgres_tests {
    //! Pin every `<impl SessionStore for PostgresSessionStore>` body
    //! against `Ok(...)` body-replacement mutations without requiring a live
    //! Postgres. Strategy: a `PgPool` created via `connect_lazy` against a
    //! port that refuses connections produces a deterministic `sqlx::Error`
    //! on the first DB round-trip. Real impl: returns `Err`. Mutated impl:
    //! returns `Ok(...)`. The two are distinguishable, so the mutation is
    //! caught.
    use super::*;
    use crate::session::data::SessionData;
    use crate::session::id::SessionId;
    use crate::testing::mock_tracing::TracingCapture;
    use sqlx::postgres::PgPoolOptions;

    fn unreachable_pool() -> PgPool {
        // 127.0.0.1:1; port 1 is reserved IANA and never opened by
        // local services. `connect_lazy_with` does not initiate a
        // connection, so this constructor itself never blocks; the
        // first query will fail with ECONNREFUSED in well under the
        // 200 ms acquire timeout.
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("postgres://user:pass@127.0.0.1:1/nodb")
            .expect("connect_lazy must parse a valid URL")
    }

    fn store() -> PostgresSessionStore {
        PostgresSessionStore::plaintext(unreachable_pool())
    }

    fn sample_id() -> SessionId {
        SessionId::new(&axess_rng::SystemRng)
    }

    #[tokio::test]
    async fn plaintext_constructor_emits_warning() {
        // Pins line 71 against `-> Default::default()` (unviable; no
        // `Default` impl exists) AND the inline `tracing::warn!`
        // diagnostic against accidental removal during refactors.
        let capture = TracingCapture::install();
        drop(PostgresSessionStore::plaintext(unreachable_pool()));
        assert!(
            capture.contains_at_level(tracing::Level::WARN, "without encryption"),
            "plaintext() must warn operators; captured events: {:#?}",
            capture.events()
        );
    }

    #[tokio::test]
    async fn load_propagates_connection_error_not_ok_none() {
        // Pins line 162 body against `Ok(None)` and
        // `Ok(Some(Default::default()))` mutations.
        let result = store().load(&sample_id()).await;
        assert!(
            result.is_err(),
            "load must propagate sqlx error from an unreachable pool, \
             not silently return an Ok variant"
        );
    }

    #[tokio::test]
    async fn save_propagates_connection_error_not_ok_unit() {
        // Pins line 184 body against `Ok(())`.
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
        // Pins line 205 body against `Ok(())`.
        let result = store().delete(&sample_id()).await;
        assert!(
            result.is_err(),
            "delete must propagate sqlx error, not Ok(())"
        );
    }

    #[tokio::test]
    async fn cycle_propagates_connection_error_not_ok_unit() {
        // Pins line 220 body against `Ok(())`. Even though `cycle` opens
        // a transaction with two statements, the *begin* fails first
        // against an unreachable pool; so we observe Err from the very
        // first await.
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
        // Pins line 247 body against `Ok(0)` and `Ok(1)`. `prune_expired`
        // is a thin wrapper around `cleanup_expired`, which is itself
        // covered below; this test specifically guards the trait surface.
        let result = store().prune_expired().await;
        assert!(
            result.is_err(),
            "prune_expired must propagate sqlx error, not an Ok(u64) count"
        );
    }

    #[tokio::test]
    async fn cleanup_expired_propagates_connection_error_not_ok_count() {
        // Pins line 111 body against `Ok(0)` and `Ok(1)` mutations on
        // the inherent `cleanup_expired` method.
        let result = store().cleanup_expired().await;
        assert!(
            result.is_err(),
            "cleanup_expired must propagate sqlx error, not an Ok(u64) count"
        );
    }

    #[tokio::test]
    async fn init_schema_propagates_connection_error_not_ok_unit() {
        // Pins line 90 body against `Ok(())`.
        let result = store().init_schema().await;
        assert!(
            result.is_err(),
            "init_schema must propagate sqlx error, not Ok(())"
        );
    }

    #[tokio::test]
    async fn health_check_returns_unhealthy_on_unreachable_pool() {
        // Pins line 259 body against `Pin::new(...)`-style mutations
        // that would degrade the response to a default future. The
        // original yields a real `HealthStatus::Unhealthy(_)` against
        // an unreachable pool.
        let status = store().check().await;
        assert!(
            matches!(status, HealthStatus::Unhealthy(_)),
            "check() must report Unhealthy against unreachable pool, got {status:?}"
        );
    }
}
