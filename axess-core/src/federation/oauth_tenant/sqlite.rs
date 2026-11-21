//! SQLite-backed [`TenantOAuthProviderStore`](super::TenantOAuthProviderStore).
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS tenant_oauth_providers (
//!     tenant_id TEXT    NOT NULL,
//!     name      TEXT    NOT NULL,
//!     revision  INTEGER NOT NULL,
//!     record    TEXT    NOT NULL,
//!     issuer    TEXT    GENERATED ALWAYS AS (json_extract(record, '$.issuer')) VIRTUAL,
//!     client_id TEXT    GENERATED ALWAYS AS (json_extract(record, '$.client_id')) VIRTUAL,
//!     PRIMARY KEY (tenant_id, name)
//! );
//! CREATE INDEX IF NOT EXISTS tenant_oauth_providers_issuer
//!     ON tenant_oauth_providers (issuer, tenant_id, name);
//! CREATE UNIQUE INDEX IF NOT EXISTS tenant_oauth_providers_issuer_client
//!     ON tenant_oauth_providers (issuer, client_id);
//! ```
//!
//! `issuer` and `client_id` are derived from the record, never written, and
//! indexed: the back-channel logout endpoint, which anyone can reach, looks
//! records up by issuer on every POST, and must not scan the table to do it.
//! The unique index is what keeps one `(issuer, client_id)` pair to one
//! record across tenants when several processes write the table: the
//! directory's own check holds within one process only. A write that would
//! take a held pair is refused with
//! [`TenantOAuthProviderStoreError::pair_held`].
//!
//! `record` is the JSON of the [`TenantOAuthProviderRecord`]. Its credential
//! is as sealed as the record that was put: use
//! [`StoredTenantOAuthProviders::upsert`](super::StoredTenantOAuthProviders::upsert)
//! with a cipher so that a client secret or a private key never reaches the
//! table in clear text.

use super::{
    ReassignedPair, TenantOAuthProviderRecord, TenantOAuthProviderStore,
    TenantOAuthProviderStoreError,
};
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

/// A write's error: the unique index over `(issuer, client_id)` refusing a
/// held pair is reported as such, anything else as the backend's error. The
/// primary key cannot be the constraint hit: `put` upserts on it and
/// `put_if_revision` updates in place.
fn write_error(e: sqlx::Error) -> TenantOAuthProviderStoreError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            TenantOAuthProviderStoreError::pair_held()
        }
        _ => backend(e),
    }
}

/// Rows that already hold one `(issuer, client_id)` pair more than once, found
/// when the unique index is about to be created: the operator removes or
/// re-points all but one of each before the schema can be brought up.
#[derive(Debug)]
struct CollidingPairs(Vec<(String, String, String)>);

impl std::fmt::Display for CollidingPairs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tenant_oauth_providers holds {} (issuer, client id) pair(s) registered by more than \
             one record, so the unique index over the pair cannot be created; remove or re-point \
             all but one record of each:",
            self.0.len()
        )?;
        for (issuer, client_id, records) in &self.0 {
            write!(f, " [issuer {issuer} client id {client_id}: {records}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for CollidingPairs {}

impl SqliteTenantOAuthProviderStore {
    /// A store over `pool`. Call [`init_schema`](Self::init_schema) once.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create the `tenant_oauth_providers` table, its issuer index and the
    /// unique index over `(issuer, client_id)` if they are not there, adding
    /// the `client_id` column to a table an earlier release created.
    /// Idempotent: safe to call on every startup.
    ///
    /// # Errors
    ///
    /// The database error, or [`sqlx::Error::Configuration`] naming every
    /// `(issuer, client id)` pair that existing rows hold more than once:
    /// such rows already make the pair's back-channel logout ambiguous, and
    /// the unique index is not created over them silently. Remove or re-point
    /// all but one record of each pair and start again.
    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS tenant_oauth_providers (
                tenant_id TEXT    NOT NULL,
                name      TEXT    NOT NULL,
                revision  INTEGER NOT NULL,
                record    TEXT    NOT NULL,
                issuer    TEXT    GENERATED ALWAYS AS (json_extract(record, '$.issuer')) VIRTUAL,
                client_id TEXT    GENERATED ALWAYS AS (json_extract(record, '$.client_id')) VIRTUAL,
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
        self.add_client_id_column_if_missing().await?;
        self.refuse_colliding_pairs().await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS tenant_oauth_providers_issuer_client \
             ON tenant_oauth_providers (issuer, client_id)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A table created before the unique index existed has no `client_id`
    /// column; `table_xinfo` lists generated columns, `table_info` does not.
    async fn add_client_id_column_if_missing(&self) -> Result<(), sqlx::Error> {
        let columns: Vec<(i64, String)> =
            sqlx::query_as("PRAGMA table_xinfo(tenant_oauth_providers)")
                .fetch_all(&self.pool)
                .await?;
        if columns.iter().any(|(_, name)| name == "client_id") {
            return Ok(());
        }
        sqlx::query(
            "ALTER TABLE tenant_oauth_providers ADD COLUMN client_id TEXT \
             GENERATED ALWAYS AS (json_extract(record, '$.client_id')) VIRTUAL",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Report, by name, every pair that existing rows hold more than once.
    async fn refuse_colliding_pairs(&self) -> Result<(), sqlx::Error> {
        let colliding: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT issuer, client_id, group_concat(tenant_id || ':' || name, ', ') \
             FROM tenant_oauth_providers \
             WHERE issuer IS NOT NULL AND client_id IS NOT NULL \
             GROUP BY issuer, client_id HAVING COUNT(*) > 1 \
             ORDER BY issuer, client_id",
        )
        .fetch_all(&self.pool)
        .await?;
        if colliding.is_empty() {
            return Ok(());
        }
        for (issuer, client_id, records) in &colliding {
            tracing::error!(
                issuer = %crate::authn::service::log_text::logged_request_text(issuer),
                client_id = %crate::authn::service::log_text::logged_request_text(client_id),
                records = %records,
                "tenant OAuth provider records hold one (issuer, client id) pair more than once"
            );
        }
        Err(sqlx::Error::Configuration(Box::new(CollidingPairs(
            colliding,
        ))))
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

/// Insert or replace a record, numbering its revision in the same statement.
const PUT: &str = "INSERT INTO tenant_oauth_providers (tenant_id, name, revision, record) \
     VALUES (?1, ?2, 1, ?3) \
     ON CONFLICT (tenant_id, name) DO UPDATE SET \
         revision = tenant_oauth_providers.revision + 1, record = excluded.record \
     RETURNING revision";

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
        let (revision,): (i64,) = sqlx::query_as(PUT)
            .bind(record.tenant_id.to_string())
            .bind(&record.name)
            .bind(json)
            .fetch_one(&self.pool)
            .await
            .map_err(write_error)?;
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
        .map_err(write_error)?;
        row.map(|(revision,)| {
            record.revision = u64::try_from(revision).map_err(backend)?;
            Ok(record)
        })
        .transpose()
    }

    async fn reassign_pair(
        &self,
        mut record: TenantOAuthProviderRecord,
    ) -> Result<ReassignedPair, TenantOAuthProviderStoreError> {
        record.revision = 0;
        let json = serde_json::to_string(&record).map_err(backend)?;
        // The removal and the write are one transaction, and the removal
        // takes the write lock first: no other connection writes the pair
        // in between.
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let removed: Vec<(String, i64)> = sqlx::query_as(
            "DELETE FROM tenant_oauth_providers \
             WHERE issuer = ?1 AND client_id = ?2 AND NOT (tenant_id = ?3 AND name = ?4) \
             RETURNING record, revision",
        )
        .bind(&record.issuer)
        .bind(&record.client_id)
        .bind(record.tenant_id.to_string())
        .bind(&record.name)
        .fetch_all(&mut *tx)
        .await
        .map_err(backend)?;
        let (revision,): (i64,) = sqlx::query_as(PUT)
            .bind(record.tenant_id.to_string())
            .bind(&record.name)
            .bind(json)
            .fetch_one(&mut *tx)
            .await
            .map_err(write_error)?;
        tx.commit().await.map_err(backend)?;
        let removed = removed
            .iter()
            .map(|(json, revision)| decode(json, *revision))
            .collect::<Result<_, _>>()?;
        record.revision = u64::try_from(revision).map_err(backend)?;
        Ok(ReassignedPair {
            stored: record,
            removed,
        })
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

    async fn list_all(
        &self,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT record, revision FROM tenant_oauth_providers ORDER BY tenant_id, name",
        )
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
