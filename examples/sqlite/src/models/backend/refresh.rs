//! `RefreshTokenStore` impl. `revoke_family` is a single UPDATE statement;
//! `rotate_token` and `issue_with_eviction` wrap their revoke + insert pair
//! in a `sqlx::Pool::begin()` transaction so partial-failure semantics match
//! the trait contract; either every side-effect lands or none does.

use axess::Clock;
use axess::authn::{DeviceId, UserId};
use axess::session::{RefreshToken, RefreshTokenId, RefreshTokenStore, TokenFamilyId};
use sqlx::{AssertSqlSafe, Row};

use super::{BackendError, OurBackend, parse_db_datetime};

impl RefreshTokenStore for OurBackend {
    type Error = BackendError;

    async fn store_token(&self, token: &RefreshToken) -> Result<(), Self::Error> {
        sqlx::query(
            "INSERT INTO refresh_tokens
                 (id, user_id, tenant_id, token_hash, family_id, device_id,
                  device_info, issued_at, expires_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(token.id.to_string())
        .bind(token.user_id.to_string())
        .bind(token.tenant_id.to_string())
        .bind(&token.token_hash)
        .bind(token.family_id.as_ref().map(|f| f.to_string()))
        .bind(token.device_id.as_ref().map(|d| d.to_string()))
        .bind(token.device_info.as_deref())
        .bind(token.issued_at.to_rfc3339())
        .bind(token.expires_at.to_rfc3339())
        .bind(i64::from(token.revoked))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn find_token(&self, token_hash: &str) -> Result<Option<RefreshToken>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, user_id, tenant_id, token_hash, family_id, device_id,
                    device_info, issued_at, expires_at, revoked
               FROM refresh_tokens
              WHERE token_hash = ?1",
        )
        .bind(token_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(row
            .as_ref()
            .map(|r| refresh_token_from_row(self.clock(), r)))
    }

    async fn revoke_token(&self, token_id: &RefreshTokenId) -> Result<(), Self::Error> {
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1")
            .bind(token_id.to_string())
            .execute(self.pool())
            .await?;
        Ok(())
    }

    async fn revoke_user_tokens(&self, user_id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?1")
            .bind(user_id.to_string())
            .execute(self.pool())
            .await?;
        Ok(())
    }

    async fn revoke_family(
        &self,
        user_id: &UserId,
        family_id: &TokenFamilyId,
    ) -> Result<(), Self::Error> {
        // Single statement: SQLite executes per-row UPDATE atomically within
        // one query. No window for a concurrent rotation to escape the
        // family revoke.
        sqlx::query(
            "UPDATE refresh_tokens
                SET revoked = 1
              WHERE user_id = ?1 AND family_id = ?2",
        )
        .bind(user_id.to_string())
        .bind(family_id.to_string())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn active_tokens(&self, user_id: &UserId) -> Result<Vec<RefreshToken>, Self::Error> {
        let rows = sqlx::query(
            "SELECT id, user_id, tenant_id, token_hash, family_id, device_id,
                    device_info, issued_at, expires_at, revoked
               FROM refresh_tokens
              WHERE user_id = ?1 AND revoked = 0
              ORDER BY issued_at ASC",
        )
        .bind(user_id.to_string())
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .iter()
            .map(|r| refresh_token_from_row(self.clock(), r))
            .collect())
    }

    async fn issue_with_eviction(
        &self,
        evict_ids: &[RefreshTokenId],
        new_token: &RefreshToken,
    ) -> Result<(), Self::Error> {
        // Single transaction: evictions + insert land together or neither
        // side-effect persists. Builds a parameterised IN list sized to
        // `evict_ids.len()` so the eviction step is one round trip, not N.
        let mut tx = self.pool().begin().await?;

        if !evict_ids.is_empty() {
            let placeholders = (1..=evict_ids.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!("UPDATE refresh_tokens SET revoked = 1 WHERE id IN ({placeholders})");
            let mut q = sqlx::query(AssertSqlSafe(sql.as_str()));
            for id in evict_ids {
                q = q.bind(id.to_string());
            }
            q.execute(&mut *tx).await?;
        }

        sqlx::query(
            "INSERT INTO refresh_tokens
                 (id, user_id, tenant_id, token_hash, family_id, device_id,
                  device_info, issued_at, expires_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(new_token.id.to_string())
        .bind(new_token.user_id.to_string())
        .bind(new_token.tenant_id.to_string())
        .bind(&new_token.token_hash)
        .bind(new_token.family_id.as_ref().map(|f| f.to_string()))
        .bind(new_token.device_id.as_ref().map(|d| d.to_string()))
        .bind(new_token.device_info.as_deref())
        .bind(new_token.issued_at.to_rfc3339())
        .bind(new_token.expires_at.to_rfc3339())
        .bind(i64::from(new_token.revoked))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn rotate_token(
        &self,
        parent_id: &RefreshTokenId,
        new_token: &RefreshToken,
    ) -> Result<(), Self::Error> {
        // Single transaction: parent revoke + child insert land together or
        // neither. Closes the window where a mid-rotation crash leaves the
        // user with a revoked parent and no replacement.
        let mut tx = self.pool().begin().await?;
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1")
            .bind(parent_id.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO refresh_tokens
                 (id, user_id, tenant_id, token_hash, family_id, device_id,
                  device_info, issued_at, expires_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(new_token.id.to_string())
        .bind(new_token.user_id.to_string())
        .bind(new_token.tenant_id.to_string())
        .bind(&new_token.token_hash)
        .bind(new_token.family_id.as_ref().map(|f| f.to_string()))
        .bind(new_token.device_id.as_ref().map(|d| d.to_string()))
        .bind(new_token.device_info.as_deref())
        .bind(new_token.issued_at.to_rfc3339())
        .bind(new_token.expires_at.to_rfc3339())
        .bind(i64::from(new_token.revoked))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// Hydrate a `RefreshToken` from a `refresh_tokens` row.
fn refresh_token_from_row(clock: &dyn Clock, row: &sqlx::sqlite::SqliteRow) -> RefreshToken {
    use axess::authn::TenantId;

    let id: String = row.get("id");
    let user_id: String = row.get("user_id");
    let tenant_id: String = row.get("tenant_id");
    let token_hash: String = row.get("token_hash");
    let family_id: Option<String> = row.get("family_id");
    let device_id: Option<String> = row.get("device_id");
    let device_info: Option<String> = row.get("device_info");
    let issued_at: String = row.get("issued_at");
    let expires_at: String = row.get("expires_at");
    let revoked: i64 = row.get("revoked");

    RefreshToken {
        id: RefreshTokenId::try_new(&id).expect("refresh_tokens.id must be a valid RefreshTokenId"),
        user_id: UserId::try_new(&user_id).expect("refresh_tokens.user_id invalid"),
        tenant_id: TenantId::try_new(&tenant_id).expect("refresh_tokens.tenant_id invalid"),
        token_hash,
        issued_at: parse_db_datetime(clock, &issued_at),
        expires_at: parse_db_datetime(clock, &expires_at),
        revoked: revoked != 0,
        device_info,
        family_id: family_id
            .as_deref()
            .map(|s| TokenFamilyId::try_new(s).expect("refresh_tokens.family_id invalid")),
        device_id: device_id
            .as_deref()
            .map(|s| DeviceId::try_new(s).expect("refresh_tokens.device_id invalid")),
    }
}
