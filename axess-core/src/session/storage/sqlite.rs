//! SQLite-backed session store using sqlx.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS sessions (
//!   id TEXT PRIMARY KEY,           -- UUID as hyphenated string
//!   data TEXT NOT NULL,            -- legacy base64 form; empty on rows this release saves
//!   data_bin BLOB,                 -- MessagePack SessionData (AES-256-GCM sealed when encryption is on)
//!   expires_at INTEGER NOT NULL    -- Unix timestamp seconds
//! );
//! ```
//!
//! `data_bin` holds the session as raw bytes (MessagePack, sealed with
//! AES-256-GCM when encryption is on). `data` is the base64 text column of
//! earlier releases: rows written by them keep working because a load reads
//! `data_bin` first and falls back to `data`, and every save writes
//! `data_bin` and empties `data`, so a legacy row is rewritten when it is
//! loaded (the store re-seals it) or saved. `data` stays `NOT NULL`, so new rows carry an
//! empty string there.
//!
//! # Upgrading an existing deployment
//!
//! `CREATE TABLE IF NOT EXISTS` leaves an existing table as it is, so a
//! deployment created by an earlier release must run, once, before the new
//! code serves a request (a load selects `data_bin`):
//!
//! ```sql
//! ALTER TABLE sessions ADD COLUMN data_bin BLOB;
//! ```
//!
//! Rolling back to the earlier release afterwards is safe for rows it wrote
//! itself, but it cannot read a row this release saved (the text column is
//! empty): that user signs in again.

use crate::session::storage::session_codec::{SessionCodec, SqlStoreError, expires_at};
use crate::session::storage::sql_helpers::log_cleanup_outcome;
use crate::session::{
    data::SessionData,
    id::SessionId,
    store::{ConditionalUpdate, CycleOutcome, SessionStore},
};
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
                data_bin BLOB,
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
                    "UPDATE sessions SET data = '', data_bin = ?1 \
                     WHERE id = ?2 AND expires_at > ?3 AND data_bin = ?4",
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
                    "UPDATE sessions SET data = '', data_bin = ?1 \
                     WHERE id = ?2 AND expires_at > ?3 AND data_bin IS NULL AND data = ?4",
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
    /// table growth. Dropping the returned [`tokio::task::JoinHandle`]
    /// leaves the loop running; keep it so the shutdown path can call
    /// `abort` (typically alongside your shutdown signal). Which rows
    /// expire is decided by the injected [`Clock`]; the pacing of the
    /// sweeps is the Tokio timer's.
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

        let row: Option<(Option<Vec<u8>>, String)> =
            sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = ?1 AND expires_at > ?2")
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

        sqlx::query(
            r#"
            INSERT INTO sessions (id, data, data_bin, expires_at)
            VALUES (?1, '', ?2, ?3)
            ON CONFLICT(id) DO UPDATE SET data = '', data_bin = excluded.data_bin, expires_at = excluded.expires_at
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
            "UPDATE sessions SET data = '', data_bin = ?1, expires_at = ?2 \
             WHERE id = ?3 AND expires_at > ?4",
        )
        .bind(&encoded)
        .bind(exp)
        .bind(&id_str)
        .bind(now)
        .execute(&self.pool)
        .await?;

        // A zero TTL writes an expiry of "now": the row cannot be loaded, so
        // it is reported as not updated, as the Valkey store does.
        Ok(result.rows_affected() > 0 && exp > now)
    }

    async fn update_if_revision(
        &self,
        id: &SessionId,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        let id_str = id.to_string();
        let now = self.clock.now().timestamp();
        let exp = expires_at(&*self.clock, ttl);

        let row: Option<(Option<Vec<u8>>, String)> =
            sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = ?1 AND expires_at > ?2")
                .bind(&id_str)
                .bind(now)
                .fetch_optional(&self.pool)
                .await?;
        let Some((binary, text)) = row else {
            return Ok(ConditionalUpdate::Gone);
        };
        let (stored, _) = self.codec.decode_row(id, binary.as_deref(), &text)?;
        if stored.revision != expected_revision {
            return Ok(ConditionalUpdate::Conflict);
        }
        if exp <= now {
            // A zero TTL stores nothing loadable; as `update` does, report
            // the row as not replaced.
            return Ok(ConditionalUpdate::Gone);
        }

        // The write names the bytes that were compared, so a save that landed
        // between the read and here leaves this one with no row to replace.
        let encoded = self.codec.encode_bytes(id, data)?;
        let result = match binary {
            Some(old) => {
                sqlx::query(
                    "UPDATE sessions SET data = '', data_bin = ?1, expires_at = ?2 \
                     WHERE id = ?3 AND expires_at > ?4 AND data_bin = ?5",
                )
                .bind(&encoded)
                .bind(exp)
                .bind(&id_str)
                .bind(now)
                .bind(old)
                .execute(&self.pool)
                .await?
            }
            None => {
                sqlx::query(
                    "UPDATE sessions SET data = '', data_bin = ?1, expires_at = ?2 \
                     WHERE id = ?3 AND expires_at > ?4 AND data_bin IS NULL AND data = ?5",
                )
                .bind(&encoded)
                .bind(exp)
                .bind(&id_str)
                .bind(now)
                .bind(text)
                .execute(&self.pool)
                .await?
            }
        };
        Ok(if result.rows_affected() > 0 {
            ConditionalUpdate::Written
        } else {
            ConditionalUpdate::Conflict
        })
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
                    "UPDATE sessions SET data = '', data_bin = ?1, expires_at = ?2 \
                     WHERE id = ?3 AND expires_at > ?4",
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
            let removed = sqlx::query("DELETE FROM sessions WHERE id = ?1 AND expires_at > ?2")
                .bind(&old_str)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            if require_old && removed.rows_affected() == 0 {
                return Ok(CycleOutcome::SessionGone);
            }
            if removed.rows_affected() == 0 {
                // An expired remnant of the old id is removed too.
                sqlx::query("DELETE FROM sessions WHERE id = ?1")
                    .bind(&old_str)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        sqlx::query(
            r#"
            INSERT INTO sessions (id, data, data_bin, expires_at)
            VALUES (?1, '', ?2, ?3)
            ON CONFLICT(id) DO UPDATE SET data = '', data_bin = excluded.data_bin, expires_at = excluded.expires_at
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
mod sqlite_tests;

#[cfg(test)]
mod binary_column_tests;
#[cfg(test)]
mod binding_tests;
