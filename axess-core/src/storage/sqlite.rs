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

use crate::session::{data::SessionData, id::SessionId, store::SessionStore};
use crate::utils::random::SecureRng;
use sqlx::SqlitePool;
use std::time::Duration;

/// SQLite-backed session store.
///
/// Wrap an existing [`SqlitePool`] and call [`init_schema`] once at startup.
#[derive(Clone)]
pub struct SqliteSessionStore {
    pool: SqlitePool,
}

impl SqliteSessionStore {
    /// Create a new store wrapping the given connection pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
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
        Ok(())
    }

    /// Delete all sessions whose `expires_at` is in the past.
    ///
    /// Returns the number of rows deleted.
    pub async fn cleanup_expired(&self) -> Result<u64, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < ?1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

/// Error type for the SQLite session store.
#[derive(Debug, thiserror::Error)]
pub enum SqliteSessionStoreError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl SessionStore for SqliteSessionStore {
    type Error = SqliteSessionStoreError;

    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        let id_str = id.to_string();
        let now = chrono::Utc::now().timestamp();

        let row: Option<(String,)> =
            sqlx::query_as("SELECT data FROM sessions WHERE id = ?1 AND expires_at > ?2")
                .bind(&id_str)
                .bind(now)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((json,)) => {
                let data: SessionData = serde_json::from_str(&json)?;
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
        let json = serde_json::to_string(data)?;
        let expires_at = chrono::Utc::now().timestamp() + ttl.as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO sessions (id, data, expires_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at
            "#,
        )
        .bind(&id_str)
        .bind(&json)
        .bind(expires_at)
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
        data: &SessionData,
        ttl: Duration,
        rng: &mut impl SecureRng,
    ) -> Result<SessionId, Self::Error> {
        let new_id = SessionId::new(rng);
        let json = serde_json::to_string(data)?;
        let expires_at = chrono::Utc::now().timestamp() + ttl.as_secs() as i64;
        let old_str = old_id.to_string();
        let new_str = new_id.to_string();

        // Use a transaction to atomically delete the old and insert the new.
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM sessions WHERE id = ?1")
            .bind(&old_str)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "INSERT INTO sessions (id, data, expires_at) VALUES (?1, ?2, ?3)",
        )
        .bind(&new_str)
        .bind(&json)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(new_id)
    }
}
