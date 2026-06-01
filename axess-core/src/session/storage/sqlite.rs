//! SQLite-backed session store using sqlx.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS sessions (
//!   id TEXT PRIMARY KEY,           -- UUID as hyphenated string
//!   data TEXT NOT NULL,            -- JSON-encoded SessionData
//!   expires_at INTEGER NOT NULL    -- Unix timestamp seconds
//! );
//! ```

use crate::session::storage::session_codec::{SessionCodec, SqlStoreError, expires_at};
use crate::session::storage::sql_helpers::log_cleanup_outcome;
use crate::session::{data::SessionData, id::SessionId, store::SessionStore};
use axess_clock::{Clock, SystemClock};
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;

/// Backward-compatible type alias. Use [`SqlStoreError`] directly in new code.
pub type SqliteStoreError = SqlStoreError;

/// SQLite-backed session store with AES-256-GCM encryption at rest.
///
/// Wrap an existing [`SqlitePool`] and call [`init_schema`](Self::init_schema) once at startup.
/// **Production deployments must also schedule cleanup** of expired session
/// rows: either by calling [`spawn_cleanup_task`](Self::spawn_cleanup_task)
/// at startup or by running an external job that invokes
/// [`cleanup_expired`](Self::cleanup_expired). Without one of these, the
/// `sessions` table grows unbounded.
///
/// # Encryption
///
/// The primary constructor [`new`](SqliteSessionStore::new) requires a
/// [`SessionCrypto`](crate::session::crypto::SessionCrypto) key; session data
/// is encrypted before storage and decrypted on load.
///
/// For local development or testing where encryption is not needed, use
/// [`plaintext`](SqliteSessionStore::plaintext) instead. This is an
/// explicit opt-out so that production code never accidentally stores
/// sessions unencrypted.
///
/// ```rust,ignore
/// use axess::session::SessionCrypto;
///
/// // Production: encrypted (required).
/// let store = SqliteSessionStore::new(pool, SessionCrypto::new(key));
///
/// // Development only: plaintext (explicit opt-out).
/// let store = SqliteSessionStore::plaintext(pool);
/// ```
#[derive(Clone)]
pub struct SqliteSessionStore {
    pool: SqlitePool,
    codec: SessionCodec,
    clock: Arc<dyn Clock>,
}

impl SqliteSessionStore {
    /// Create an **encrypted** store (recommended for production).
    pub fn new(pool: SqlitePool, crypto: crate::session::crypto::SessionCrypto) -> Self {
        Self {
            pool,
            codec: SessionCodec::encrypted(crypto),
            clock: Arc::new(SystemClock),
        }
    }

    /// Create a **plaintext** store (development/testing only).
    pub fn plaintext(pool: SqlitePool) -> Self {
        tracing::warn!(
            "SqliteSessionStore created without encryption; \
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

    /// Create the `sessions` table if it doesn't already exist.
    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL
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
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < ?1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Spawn a background task that calls [`cleanup_expired`](Self::cleanup_expired) on a fixed interval.
    ///
    /// SQL stores accumulate expired session rows forever unless something
    /// removes them. Production deployments **must** either call this helper
    /// once at startup, run an external scheduled job, or accept unbounded
    /// table growth. The returned [`tokio::task::JoinHandle`] aborts the
    /// loop when dropped, so store it for the lifetime of the application
    /// (typically alongside your shutdown signal).
    ///
    /// Errors from `cleanup_expired` are logged at `warn` and swallowed;
    /// the loop keeps running so a single transient DB blip does not
    /// silently halt cleanup forever.
    ///
    /// ```rust,ignore
    /// let store = SqliteSessionStore::new(pool, crypto);
    /// store.init_schema().await?;
    /// let _cleanup = store.spawn_cleanup_task(std::time::Duration::from_secs(3600));
    /// ```
    pub fn spawn_cleanup_task(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate first tick; `tokio::time::interval` fires
            // once at t=0 by default, which would race with `init_schema`
            // and any seeded test data.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                log_cleanup_outcome("sqlite", store.cleanup_expired().await);
            }
        })
    }
}

impl SessionStore for SqliteSessionStore {
    type Error = SqlStoreError;

    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        let id_str = id.to_string();
        let now = self.clock.now().timestamp();

        let row: Option<(String,)> =
            sqlx::query_as("SELECT data FROM sessions WHERE id = ?1 AND expires_at > ?2")
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
            VALUES (?1, ?2, ?3)
            ON CONFLICT(id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at
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
        sqlx::query("DELETE FROM sessions WHERE id = ?1")
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

        sqlx::query("DELETE FROM sessions WHERE id = ?1")
            .bind(&old_str)
            .execute(&mut *tx)
            .await?;

        sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?1, ?2, ?3)")
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
        // `cleanup_expired`. Backends that already provide this as a
        // typed inherent method delegate so callers can drive the sweep
        // generically (e.g. on application startup, or from a generic
        // operations endpoint).
        Ok(self.cleanup_expired().await?)
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────────────

use crate::health::{HealthCheck, HealthStatus};
use crate::session::storage::sql_helpers::sql_health_probe;

impl HealthCheck for SqliteSessionStore {
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(sql_health_probe(
            "sqlite",
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool),
        ))
    }
}

// ── Store<SessionId, SessionData> ────────────────────────────────────────────
//
// surface; adopters that hold an `Arc<dyn Store<SessionId, SessionData>>`
// or a generic `S: Store<SessionId, SessionData>` can program against any
// backend uniformly. The `SessionStore` trait stays the primary surface
// (it carries the `cycle` + `find_sessions_for_user` session-domain
// primitives `Store` doesn't); this impl is the bridge to the generic
// world. The session-domain `prune_expired` and the `Store::prune_expired`
// share the same body since both delegate to `cleanup_expired`.

impl crate::store::Store<SessionId, SessionData> for SqliteSessionStore {
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
mod sqlite_tests {
    //! Pin every inherent and `SessionStore` body for
    //! `SqliteSessionStore`. Uses a real in-memory SQLite pool so we
    //! observe round-trip behaviour, then assert that a save → load
    //! cycle returns the same payload (and an absent key returns None).
    //! Body-replacement mutations on `load`, `save`, `delete`, `cycle`,
    //! `prune_expired`, `cleanup_expired`, and `init_schema` are caught
    //! because the mutated body either returns a wrong value or fails
    //! to apply the real side effect (so a follow-up observation
    //! disagrees with the original).
    use super::*;
    use crate::session::data::SessionData;
    use crate::session::id::SessionId;
    use axess_rng::SystemRng;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite must connect")
    }

    async fn store() -> SqliteSessionStore {
        let pool = memory_pool().await;
        let store = SqliteSessionStore::plaintext(pool);
        store.init_schema().await.expect("init_schema");
        store
    }

    fn sample_id() -> SessionId {
        SessionId::new(&SystemRng)
    }

    fn payload_with_custom() -> SessionData {
        SessionData {
            custom: serde_json::json!({"k": "v"}),
            ..SessionData::default()
        }
    }

    #[tokio::test]
    async fn init_schema_creates_sessions_table() {
        // Pins line 90 body against `Ok(())`. After init_schema, an
        // INSERT into `sessions` succeeds; if the body was replaced
        // by `Ok(())`, the table would not exist and the save below
        // would fail.
        let store = store().await;
        let result = store
            .save(
                &sample_id(),
                &SessionData::default(),
                Duration::from_secs(60),
            )
            .await;
        assert!(
            result.is_ok(),
            "save after init_schema must succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn save_then_load_returns_persisted_payload() {
        // Pins lines 165 (load body), 187 (save body) against
        // `Ok(None)`, `Ok(Some(Default::default()))`, and `Ok(())`.
        // The mutations would either drop the persisted row or
        // return a default; the round-trip catches both.
        let store = store().await;
        let id = sample_id();
        let data = payload_with_custom();

        store
            .save(&id, &data, Duration::from_secs(60))
            .await
            .expect("save");

        let loaded = store.load(&id).await.expect("load").expect("Some");
        assert_eq!(
            serde_json::to_string(&data).unwrap(),
            serde_json::to_string(&loaded).unwrap(),
            "load must return what save persisted; kills Ok(None) AND Ok(Some(Default))"
        );
    }

    #[tokio::test]
    async fn load_of_absent_key_returns_none() {
        // Kill `Ok(Some(Default::default()))` mutation on load;
        // a row that was never saved must come back as None, not
        // a default-constructed SessionData.
        let store = store().await;
        let loaded = store.load(&sample_id()).await.expect("load");
        assert!(
            loaded.is_none(),
            "absent key must yield None, not Some(Default)"
        );
    }

    #[tokio::test]
    async fn delete_actually_removes_row() {
        // Pins line 208 body against `Ok(())`. With the mutation,
        // delete still returns Ok(()), but the row remains;
        // load() afterwards would still find it.
        let store = store().await;
        let id = sample_id();
        let data = payload_with_custom();
        store
            .save(&id, &data, Duration::from_secs(60))
            .await
            .expect("save");
        assert!(store.load(&id).await.expect("load before delete").is_some());

        store.delete(&id).await.expect("delete");
        let after = store.load(&id).await.expect("load after delete");
        assert!(
            after.is_none(),
            "delete must remove the row; mutated body would leave it"
        );
    }

    #[tokio::test]
    async fn cycle_atomically_swaps_session_ids() {
        // Pins line 223 body against `Ok(())`. Real cycle replaces
        // old_id row with new_id row; mutated cycle returns Ok(())
        // without doing the swap; so old row stays and new row
        // never appears.
        let store = store().await;
        let old = sample_id();
        let new = sample_id();
        let data = payload_with_custom();
        store
            .save(&old, &data, Duration::from_secs(60))
            .await
            .expect("save");

        store
            .cycle(&old, &new, &data, Duration::from_secs(60))
            .await
            .expect("cycle");

        assert!(
            store.load(&old).await.expect("load old").is_none(),
            "old id must be gone after cycle"
        );
        assert!(
            store.load(&new).await.expect("load new").is_some(),
            "new id must exist after cycle; kills cycle->Ok(()) mutant"
        );
    }

    #[tokio::test]
    async fn cleanup_expired_returns_real_row_count() {
        // Pins line 111 against `Ok(0)` and `Ok(1)` mutations.
        // Save two sessions with negative TTL (already expired);
        // cleanup_expired must return 2, not 0 or 1.
        let store = store().await;
        let id1 = sample_id();
        let id2 = sample_id();

        // Insert directly with an expires_at in the past; the
        // `save` helper would use the configured clock, so reach
        // into the SQL layer with a hand-rolled INSERT instead.
        for id in [&id1, &id2] {
            sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?1, '{}', 0)")
                .bind(id.to_string())
                .execute(&store.pool)
                .await
                .expect("manual insert");
        }

        let removed = store.cleanup_expired().await.expect("cleanup_expired");
        assert_eq!(
            removed, 2,
            "cleanup_expired must report the real row-count; kills Ok(0) and Ok(1)"
        );
    }

    #[tokio::test]
    async fn prune_expired_trait_surface_matches_inherent() {
        // Pins line 252 body against `Ok(0)` and `Ok(1)`. After
        // inserting three expired rows, prune_expired must
        // delegate to cleanup_expired and return 3.
        let store = store().await;
        for _ in 0..3 {
            sqlx::query("INSERT INTO sessions (id, data, expires_at) VALUES (?1, '{}', 0)")
                .bind(SessionId::new(&SystemRng).to_string())
                .execute(&store.pool)
                .await
                .expect("manual insert");
        }
        let removed = store.prune_expired().await.expect("prune_expired");
        assert_eq!(removed, 3);
    }

    // log_cleanup_outcome is now shared in `sql_helpers` and pinned by tests
    // there; the per-backend duplicates were dropped to keep one source of
    // truth. The cleanup-pipeline shape (label propagation, debug-only-on-
    // positive, warn-on-err) is unchanged.
}
