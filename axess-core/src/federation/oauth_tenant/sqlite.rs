//! SQLite-backed [`TenantOAuthProviderStore`](super::TenantOAuthProviderStore).
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS tenant_oauth_providers (
//!     tenant_id TEXT    NOT NULL,
//!     name      TEXT    NOT NULL,
//!     revision  INTEGER NOT NULL,
//!     record    TEXT    NOT NULL,
//!     issuer    TEXT    GENERATED ALWAYS AS (json_extract(record, '$.issuer')) VIRTUAL,
//!     PRIMARY KEY (tenant_id, name)
//! );
//! CREATE INDEX IF NOT EXISTS tenant_oauth_providers_issuer
//!     ON tenant_oauth_providers (issuer, tenant_id, name);
//! ```
//!
//! `issuer` is derived from the record, never written, and indexed: the
//! back-channel logout endpoint, which anyone can reach, looks records up by
//! issuer on every POST, and must not scan the table to do it.
//!
//! `record` is the JSON of the [`TenantOAuthProviderRecord`]. Its credential
//! is as sealed as the record that was put: use
//! [`StoredTenantOAuthProviders::upsert`](super::StoredTenantOAuthProviders::upsert)
//! with a cipher so that a client secret or a private key never reaches the
//! table in clear text.

use super::{TenantOAuthProviderRecord, TenantOAuthProviderStore, TenantOAuthProviderStoreError};
use crate::authn::ids::TenantId;
use sqlx::SqlitePool;

/// Records in a SQLite table.
#[derive(Clone)]
pub struct SqliteTenantOAuthProviderStore {
    pool: SqlitePool,
}

fn backend(e: impl std::error::Error + Send + Sync + 'static) -> TenantOAuthProviderStoreError {
    TenantOAuthProviderStoreError::new(e)
}

impl SqliteTenantOAuthProviderStore {
    /// A store over `pool`. Call [`init_schema`](Self::init_schema) once.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create the `tenant_oauth_providers` table and its issuer index if they
    /// are not there. Idempotent: safe to call on every startup.
    ///
    /// # Errors
    ///
    /// The database error.
    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS tenant_oauth_providers (
                tenant_id TEXT    NOT NULL,
                name      TEXT    NOT NULL,
                revision  INTEGER NOT NULL,
                record    TEXT    NOT NULL,
                issuer    TEXT    GENERATED ALWAYS AS (json_extract(record, '$.issuer')) VIRTUAL,
                PRIMARY KEY (tenant_id, name)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS tenant_oauth_providers_issuer \
             ON tenant_oauth_providers (issuer, tenant_id, name)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn decode(
    json: &str,
    revision: i64,
) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
    let mut record: TenantOAuthProviderRecord = serde_json::from_str(json).map_err(backend)?;
    // The column is the source of truth for the revision.
    record.revision = u64::try_from(revision).map_err(backend)?;
    Ok(record)
}

/// The records of one issuer, through the issuer index.
const LIST_BY_ISSUER: &str = "SELECT record, revision FROM tenant_oauth_providers \
     WHERE issuer = ?1 ORDER BY tenant_id, name";

impl TenantOAuthProviderStore for SqliteTenantOAuthProviderStore {
    async fn get(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT record, revision FROM tenant_oauth_providers \
             WHERE tenant_id = ?1 AND name = ?2",
        )
        .bind(tenant.to_string())
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|(json, revision)| decode(&json, revision))
            .transpose()
    }

    async fn put(
        &self,
        mut record: TenantOAuthProviderRecord,
    ) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
        record.revision = 0;
        let json = serde_json::to_string(&record).map_err(backend)?;
        // One statement, so two writers cannot both read revision n and both
        // write n + 1.
        let (revision,): (i64,) = sqlx::query_as(
            "INSERT INTO tenant_oauth_providers (tenant_id, name, revision, record) \
             VALUES (?1, ?2, 1, ?3) \
             ON CONFLICT (tenant_id, name) DO UPDATE SET \
                 revision = tenant_oauth_providers.revision + 1, record = excluded.record \
             RETURNING revision",
        )
        .bind(record.tenant_id.to_string())
        .bind(&record.name)
        .bind(json)
        .fetch_one(&self.pool)
        .await
        .map_err(backend)?;
        record.revision = u64::try_from(revision).map_err(backend)?;
        Ok(record)
    }

    async fn put_if_revision(
        &self,
        mut record: TenantOAuthProviderRecord,
        expected: u64,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        record.revision = 0;
        let json = serde_json::to_string(&record).map_err(backend)?;
        let expected = i64::try_from(expected).map_err(backend)?;
        let row: Option<(i64,)> = sqlx::query_as(
            "UPDATE tenant_oauth_providers SET revision = revision + 1, record = ?3 \
             WHERE tenant_id = ?1 AND name = ?2 AND revision = ?4 \
             RETURNING revision",
        )
        .bind(record.tenant_id.to_string())
        .bind(&record.name)
        .bind(json)
        .bind(expected)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|(revision,)| {
            record.revision = u64::try_from(revision).map_err(backend)?;
            Ok(record)
        })
        .transpose()
    }

    async fn delete(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<bool, TenantOAuthProviderStoreError> {
        let done =
            sqlx::query("DELETE FROM tenant_oauth_providers WHERE tenant_id = ?1 AND name = ?2")
                .bind(tenant.to_string())
                .bind(name)
                .execute(&self.pool)
                .await
                .map_err(backend)?;
        Ok(done.rows_affected() > 0)
    }

    async fn list_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(LIST_BY_ISSUER)
            .bind(issuer)
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?;
        rows.iter()
            .map(|(json, revision)| decode(json, *revision))
            .collect()
    }

    async fn list(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT record, revision FROM tenant_oauth_providers \
             WHERE tenant_id = ?1 ORDER BY name",
        )
        .bind(tenant.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(|(json, revision)| decode(json, *revision))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The issuer look-up runs on every back-channel logout POST, an endpoint
    /// anyone can reach: it reads an index, not the whole table.
    #[tokio::test]
    async fn the_issuer_look_up_reads_an_index() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let store = SqliteTenantOAuthProviderStore::new(pool.clone());
        store.init_schema().await.unwrap();
        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "EXPLAIN QUERY PLAN {LIST_BY_ISSUER}"
        )))
        .bind("https://idp.example")
        .fetch_all(&pool)
        .await
        .unwrap();
        let detail: Vec<&str> = plan.iter().map(|row| row.3.as_str()).collect();
        assert!(
            detail
                .iter()
                .any(|d| d.starts_with("SEARCH tenant_oauth_providers USING")),
            "{detail:?}"
        );
        assert!(
            !detail
                .iter()
                .any(|d| d.starts_with("SCAN tenant_oauth_providers")),
            "{detail:?}"
        );
    }
}
