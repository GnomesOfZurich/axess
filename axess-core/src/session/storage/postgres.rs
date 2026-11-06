//! PostgreSQL-backed session store using sqlx.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS sessions (
//!   id TEXT PRIMARY KEY,
//!   data TEXT NOT NULL,
//!   data_bin BYTEA,
//!   expires_at BIGINT NOT NULL
//! );
//!
//! CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
//! ```
//!
//! `data_bin` holds the session as raw bytes (MessagePack, sealed with
//! AES-256-GCM when encryption is on). `data` is the base64 text column of
//! earlier releases: rows written by them keep working because a load reads
//! `data_bin` first and falls back to `data`, and every write stores
//! `data_bin` and empties `data`. A legacy row moves to `data_bin` with its
//! next write; a load moves it only when its blob is bound to the row, since
//! a blob without a binding proves nothing about the row it sits under (see
//! `LegacyBlobs`). `data` stays `NOT NULL`, so new rows carry an empty string
//! there.
//!
//! # Upgrading an existing deployment
//!
//! `CREATE TABLE IF NOT EXISTS` leaves an existing table as it is, so a
//! deployment created by an earlier release must run, once, before the new
//! code serves a request (a load selects `data_bin`):
//!
//! ```sql
//! ALTER TABLE sessions ADD COLUMN IF NOT EXISTS data_bin BYTEA;
//! ```
//!
//! Rolling back to the earlier release afterwards is safe for rows it wrote
//! itself, but it cannot read a row this release saved (the text column is
//! empty): that user signs in again.

use crate::session::storage::session_codec::{
    DEFAULT_MAX_PAYLOAD_BYTES, Decoded, SessionCodec, SqlStoreError, expires_at,
};
use crate::session::storage::sql_helpers::log_cleanup_outcome;
use crate::session::{
    data::SessionData,
    id::SessionId,
    store::{
        ConditionalUpdate, CycleOutcome, SessionStore,
        cas::{CasRow, CasWrite, cas_by_revision, cycle_by_revision},
    },
};
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
/// [`plaintext_insecure`](PostgresSessionStore::plaintext_insecure) instead.
///
/// ```rust,ignore
/// use axess::session::SessionCrypto;
///
/// // Production: encrypted (required).
/// let store = PostgresSessionStore::new(pool, SessionCrypto::new(key));
///
/// // Development only: plaintext (explicit opt-out).
/// let store = PostgresSessionStore::plaintext_insecure(pool);
/// ```
#[derive(Clone)]
pub struct PostgresSessionStore {
    pool: PgPool,
    codec: SessionCodec,
    clock: Arc<dyn Clock>,
    /// Largest encoded payload a write accepts, in bytes.
    max_payload_bytes: usize,
}

impl PostgresSessionStore {
    /// Create an **encrypted** store (recommended for production).
    pub fn new(pool: PgPool, crypto: crate::session::crypto::SessionCrypto) -> Self {
        Self {
            pool,
            codec: SessionCodec::encrypted(crypto),
            clock: Arc::new(SystemClock),
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }

    /// Create a **plaintext** store (development/testing only).
    ///
    /// Session data (including the user id) is stored **unsealed**: anyone who
    /// can read the table can read every session. The named opt-out beside
    /// [`new`](Self::new), which takes the key; do not use in production.
    pub fn plaintext_insecure(pool: PgPool) -> Self {
        tracing::warn!(
            "PostgresSessionStore created without encryption; \
             do not use in production"
        );
        Self {
            pool,
            codec: SessionCodec::plaintext(),
            clock: Arc::new(SystemClock),
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }

    /// Set the largest encoded session payload a write accepts, in bytes
    /// (default 64 KiB, as for the Valkey store). `save`, `update`, `cycle`
    /// and the conditional updates return
    /// [`SqlStoreError::PayloadTooLarge`] over it, so session data an
    /// attacker can grow does not grow the row without bound.
    pub fn with_max_payload(mut self, max_bytes: usize) -> Self {
        self.max_payload_bytes = max_bytes;
        self
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
                data_bin BYTEA,
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
                    "UPDATE sessions SET data = '', data_bin = $1 \
                     WHERE id = $2 AND expires_at > $3 AND data_bin = $4",
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
                    "UPDATE sessions SET data = '', data_bin = $1 \
                     WHERE id = $2 AND expires_at > $3 AND data_bin IS NULL AND data = $4",
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

    /// Delete all sessions whose `expires_at` is now or in the past: the
    /// instant from which `load` no longer returns them.
    pub async fn cleanup_expired(&self) -> Result<u64, sqlx::Error> {
        let now = self.clock.now().timestamp();
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= $1")
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
    /// on the database side), or accept unbounded table growth. Dropping
    /// the returned [`tokio::task::JoinHandle`] leaves the loop running;
    /// keep it so the shutdown path can call `abort`. Which rows expire is
    /// decided by the injected [`Clock`]; the pacing of the sweeps is the
    /// Tokio timer's.
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
            // A stall (a suspended host, a slow pass) makes ticks late; the
            // default Burst then fires every missed tick back to back. Delay
            // fires once and resumes the normal spacing.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                log_cleanup_outcome("postgres", store.cleanup_expired().await);
            }
        })
    }
}

impl SessionStore for PostgresSessionStore {
    /// SQL rows hold the session as one sealed blob with no user column, so
    /// they cannot be listed by user.
    async fn find_sessions_for_user(
        &self,
        _user_id: &crate::authn::ids::UserId,
        _limit: usize,
    ) -> Result<Vec<(SessionId, SessionData)>, Self::Error> {
        Err(SqlStoreError::Unsupported("find_sessions_for_user"))
    }

    type Error = SqlStoreError;

    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        let id_str = id.to_string();
        let now = self.clock.now().timestamp();

        let row: Option<(Option<Vec<u8>>, String)> =
            sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = $1 AND expires_at > $2")
                .bind(&id_str)
                .bind(now)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((binary, text)) => {
                let Decoded { data, reseal } =
                    self.codec.decode_row(id, binary.as_deref(), &text)?;
                if reseal {
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
        if ttl.is_zero() {
            // Already expired: nothing may be stored, and a previous row under
            // this id must not outlive the expiry it was just given.
            return SessionStore::delete(self, id).await;
        }
        let id_str = id.to_string();
        let encoded = self
            .codec
            .encode_bytes_within(id, data, self.max_payload_bytes)?;
        let exp = expires_at(&*self.clock, ttl);

        sqlx::query(
            r#"
            INSERT INTO sessions (id, data, data_bin, expires_at)
            VALUES ($1, '', $2, $3)
            ON CONFLICT (id) DO UPDATE SET data = '', data_bin = EXCLUDED.data_bin, expires_at = EXCLUDED.expires_at
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

    async fn update(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        if ttl.is_zero() {
            // Already expired: nothing may stay stored under this id, and
            // the session is reported as not kept.
            SessionStore::delete(self, id).await?;
            return Ok(false);
        }
        let id_str = id.to_string();
        let encoded = self
            .codec
            .encode_bytes_within(id, data, self.max_payload_bytes)?;
        let exp = expires_at(&*self.clock, ttl);
        let now = self.clock.now().timestamp();

        let result = sqlx::query(
            "UPDATE sessions SET data = '', data_bin = $1, expires_at = $2 \
             WHERE id = $3 AND expires_at > $4",
        )
        .bind(&encoded)
        .bind(exp)
        .bind(&id_str)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn update_if_revision(
        &self,
        id: &SessionId,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        cas_by_revision(self, id, expected_revision, data, ttl).await
    }

    async fn cycle(
        &self,
        old_id: &SessionId,
        new_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        let old_str = old_id.to_string();
        let new_str = new_id.to_string();
        if ttl.is_zero() {
            // Already expired: the rotated session is stored nowhere, so both
            // rows go and the session is reported gone, never as rotated.
            sqlx::query("DELETE FROM sessions WHERE id IN ($1, $2)")
                .bind(&old_str)
                .bind(&new_str)
                .execute(&self.pool)
                .await?;
            return Ok(CycleOutcome::SessionGone);
        }
        let encoded = self
            .codec
            .encode_bytes_within(new_id, data, self.max_payload_bytes)?;
        let exp = expires_at(&*self.clock, ttl);
        let now = self.clock.now().timestamp();

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
                    "UPDATE sessions SET data = '', data_bin = $1, expires_at = $2 \
                     WHERE id = $3 AND expires_at > $4",
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
            let removed = sqlx::query("DELETE FROM sessions WHERE id = $1 AND expires_at > $2")
                .bind(&old_str)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            if require_old && removed.rows_affected() == 0 {
                return Ok(CycleOutcome::SessionGone);
            }
            if removed.rows_affected() == 0 {
                // An expired remnant of the old id is removed too.
                sqlx::query("DELETE FROM sessions WHERE id = $1")
                    .bind(&old_str)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        sqlx::query(
            r#"
            INSERT INTO sessions (id, data, data_bin, expires_at)
            VALUES ($1, '', $2, $3)
            ON CONFLICT (id) DO UPDATE SET data = '', data_bin = EXCLUDED.data_bin, expires_at = EXCLUDED.expires_at
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

    async fn cycle_if_revision(
        &self,
        old_id: &SessionId,
        new_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
        expected_revision: u64,
    ) -> Result<CycleOutcome, Self::Error> {
        cycle_by_revision(
            self,
            old_id,
            new_id,
            data,
            ttl,
            require_old,
            expected_revision,
        )
        .await
    }

    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        // Trait surface over the existing inherent
        // `cleanup_expired`; applications that hold a `dyn SessionStore`
        // can now drive the sweep without downcasting.
        Ok(self.cleanup_expired().await?)
    }
}

/// The SQL store compares the stored columns: a write names the bytes it
/// read, the only thing a statement can match on.
impl CasRow for PostgresSessionStore {
    type Seen = (Option<Vec<u8>>, String);
    type Error = SqlStoreError;

    async fn read(&self, id: &SessionId) -> Result<Option<(u64, Self::Seen)>, Self::Error> {
        let row: Option<(Option<Vec<u8>>, String)> =
            sqlx::query_as("SELECT data_bin, data FROM sessions WHERE id = $1 AND expires_at > $2")
                .bind(id.to_string())
                .bind(self.clock.now().timestamp())
                .fetch_optional(&self.pool)
                .await?;
        let Some((binary, text)) = row else {
            return Ok(None);
        };
        let stored = self.codec.decode_row(id, binary.as_deref(), &text)?.data;
        Ok(Some((stored.revision, (binary, text))))
    }

    async fn delete_if(
        &self,
        id: &SessionId,
        (binary, text): &Self::Seen,
    ) -> Result<CasWrite, Self::Error> {
        let removed = sqlx::query(
            "DELETE FROM sessions WHERE id = $1 AND data_bin IS NOT DISTINCT FROM $2 AND data = $3",
        )
        .bind(id.to_string())
        .bind(binary)
        .bind(text)
        .execute(&self.pool)
        .await?;
        Ok(if removed.rows_affected() > 0 {
            CasWrite::Done
        } else {
            CasWrite::Missed
        })
    }

    async fn replace_if(
        &self,
        id: &SessionId,
        (binary, text): &Self::Seen,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<CasWrite, Self::Error> {
        // Sealed once the row is known to be live: a session that is gone or
        // moved on costs no seal.
        let encoded = self
            .codec
            .encode_bytes_within(id, data, self.max_payload_bytes)?;
        let replaced = sqlx::query(
            "UPDATE sessions SET data = '', data_bin = $1, expires_at = $2 \
             WHERE id = $3 AND expires_at > $4 AND data_bin IS NOT DISTINCT FROM $5 AND data = $6",
        )
        .bind(&encoded)
        .bind(expires_at(&*self.clock, ttl))
        .bind(id.to_string())
        .bind(self.clock.now().timestamp())
        .bind(binary)
        .bind(text)
        .execute(&self.pool)
        .await?;
        Ok(if replaced.rows_affected() > 0 {
            CasWrite::Done
        } else {
            CasWrite::Missed
        })
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
mod live_tests;

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

    /// An encrypted store: only `plaintext_constructor_emits_warning` calls
    /// `plaintext_insecure`, so no other test hits that warning's callsite while the
    /// capture is installed.
    fn store() -> PostgresSessionStore {
        let key = std::array::from_fn(|i| u8::try_from(i).unwrap_or(0) + 1);
        PostgresSessionStore::new(
            unreachable_pool(),
            crate::session::crypto::SessionCrypto::new(key),
        )
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
        drop(PostgresSessionStore::plaintext_insecure(unreachable_pool()));
        assert!(
            capture.contains_at_level(tracing::Level::WARN, "without encryption"),
            "plaintext_insecure() must warn operators; captured events: {:#?}",
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
