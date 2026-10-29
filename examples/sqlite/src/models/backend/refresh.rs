//! `RefreshTokenStore` impl. `revoke_family` is a single UPDATE statement;
//! `rotate_token` and `issue_capped` wrap their revoke + insert pair
//! in a `sqlx::Pool::begin()` transaction so partial-failure semantics match
//! the trait contract; either every side-effect lands or none does.

use axess::authn::{DeviceId, TenantId, UserId};
use axess::session::{
    DeviceTokenRevocation, RefreshToken, RefreshTokenId, RefreshTokenStore, RevocationReason,
    RotationOutcome, TokenFamilyId,
};
use sqlx::Row;

use super::{BackendError, OurBackend};

impl RefreshTokenStore for OurBackend {
    type Error = BackendError;

    async fn store_token(&self, token: &RefreshToken) -> Result<(), Self::Error> {
        sqlx::query(
            "INSERT INTO refresh_tokens
                 (id, user_id, tenant_id, token_hash, family_id, device_id,
                  device_info, issued_at, expires_at, revoked, authn_time)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
        .bind(token.authn_time.map(|t| t.to_rfc3339()))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn find_token(&self, token_hash: &str) -> Result<Option<RefreshToken>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, user_id, tenant_id, token_hash, family_id, device_id,
                    device_info, issued_at, expires_at, revoked, authn_time,
                    revoked_reason, revoked_at
               FROM refresh_tokens
              WHERE token_hash = ?1",
        )
        .bind(token_hash)
        .fetch_optional(self.pool())
        .await?;
        row.as_ref().map(refresh_token_from_row).transpose()
    }

    async fn revoke_token(&self, token_id: &RefreshTokenId) -> Result<(), Self::Error> {
        sqlx::query(
            "UPDATE refresh_tokens
                SET revoked = 1, revoked_reason = ?2, revoked_at = ?3
              WHERE id = ?1 AND revoked = 0",
        )
        .bind(token_id.to_string())
        .bind(RevocationReason::Explicit.as_str())
        .bind(self.clock().now().to_rfc3339())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn revoke_user_tokens(&self, user_id: &UserId) -> Result<(), Self::Error> {
        sqlx::query(
            "UPDATE refresh_tokens
                SET revoked = 1, revoked_reason = ?2, revoked_at = ?3
              WHERE user_id = ?1 AND revoked = 0",
        )
        .bind(user_id.to_string())
        .bind(RevocationReason::Explicit.as_str())
        .bind(self.clock().now().to_rfc3339())
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
                SET revoked = 1, revoked_reason = ?3, revoked_at = ?4
              WHERE user_id = ?1 AND family_id = ?2 AND revoked = 0",
        )
        .bind(user_id.to_string())
        .bind(family_id.to_string())
        .bind(RevocationReason::Compromise.as_str())
        .bind(self.clock().now().to_rfc3339())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn revoke_device_tokens(
        &self,
        tenant_id: &TenantId,
        device_id: &DeviceId,
    ) -> Result<DeviceTokenRevocation, Self::Error> {
        // Single statement, scoped by tenant: a rotation racing with it
        // either lands before (and its child carries the device id, so is
        // revoked too) or after (and finds a revoked parent).
        let done = sqlx::query(
            "UPDATE refresh_tokens SET revoked = 1
              WHERE tenant_id = ?1 AND device_id = ?2 AND revoked = 0",
        )
        .bind(tenant_id.to_string())
        .bind(device_id.to_string())
        .execute(self.pool())
        .await?;
        Ok(DeviceTokenRevocation::Revoked {
            tokens: done.rows_affected(),
        })
    }

    async fn active_tokens(&self, user_id: &UserId) -> Result<Vec<RefreshToken>, Self::Error> {
        let rows = sqlx::query(
            "SELECT id, user_id, tenant_id, token_hash, family_id, device_id,
                    device_info, issued_at, expires_at, revoked, authn_time,
                    revoked_reason, revoked_at
               FROM refresh_tokens
              WHERE user_id = ?1 AND revoked = 0
              ORDER BY issued_at ASC",
        )
        .bind(user_id.to_string())
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(refresh_token_from_row).collect()
    }

    async fn issue_capped(
        &self,
        new_token: &RefreshToken,
        max_per_user: usize,
    ) -> Result<(), Self::Error> {
        // Single transaction whose first statement is the eviction UPDATE:
        // it takes SQLite's write lock before the count is read, so two
        // concurrent issues for one user run one after the other and the
        // second one counts the first one's token.
        let mut tx = self.pool().begin().await?;

        sqlx::query(
            "UPDATE refresh_tokens
                SET revoked = 1, revoked_reason = ?3, revoked_at = ?4
              WHERE id IN (
                SELECT id FROM refresh_tokens
                 WHERE user_id = ?1 AND revoked = 0
                 ORDER BY issued_at ASC
                 LIMIT MAX(0, (SELECT COUNT(*) FROM refresh_tokens
                                WHERE user_id = ?1 AND revoked = 0) - ?2 + 1))",
        )
        .bind(new_token.user_id.to_string())
        .bind(i64::try_from(max_per_user).unwrap_or(i64::MAX))
        .bind(RevocationReason::Evicted.as_str())
        .bind(self.clock().now().to_rfc3339())
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO refresh_tokens
                 (id, user_id, tenant_id, token_hash, family_id, device_id,
                  device_info, issued_at, expires_at, revoked, authn_time)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
        .bind(new_token.authn_time.map(|t| t.to_rfc3339()))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn rotate_token(
        &self,
        parent_id: &RefreshTokenId,
        new_token: &RefreshToken,
    ) -> Result<RotationOutcome, Self::Error> {
        // Single transaction: parent revoke + child insert land together or
        // neither. Closes the window where a mid-rotation crash leaves the
        // user with a revoked parent and no replacement.
        let mut tx = self.pool().begin().await?;
        // Conditional: a parent already revoked means a parallel refresh won
        // the race; nothing is inserted and the caller treats it as reuse.
        let revoked_now = sqlx::query(
            "UPDATE refresh_tokens
                SET revoked = 1, revoked_reason = ?2, revoked_at = ?3
              WHERE id = ?1 AND revoked = 0",
        )
        .bind(parent_id.to_string())
        .bind(RevocationReason::Rotated.as_str())
        .bind(new_token.issued_at.to_rfc3339())
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if revoked_now == 0 {
            tx.rollback().await?;
            return Ok(RotationOutcome::ParentAlreadyRevoked);
        }
        sqlx::query(
            "INSERT INTO refresh_tokens
                 (id, user_id, tenant_id, token_hash, family_id, device_id,
                  device_info, issued_at, expires_at, revoked, authn_time)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
        .bind(new_token.authn_time.map(|t| t.to_rfc3339()))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(RotationOutcome::Rotated)
    }
}

/// The text columns of a `refresh_tokens` row, before they are decoded.
struct RawRefreshRow {
    id: String,
    user_id: String,
    tenant_id: String,
    token_hash: String,
    family_id: Option<String>,
    device_id: Option<String>,
    device_info: Option<String>,
    issued_at: String,
    expires_at: String,
    revoked: i64,
    authn_time: Option<String>,
    revoked_reason: Option<String>,
    revoked_at: Option<String>,
}

/// Hydrate a `RefreshToken` from a `refresh_tokens` row.
fn refresh_token_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<RefreshToken, BackendError> {
    RawRefreshRow {
        id: row.get("id"),
        user_id: row.get("user_id"),
        tenant_id: row.get("tenant_id"),
        token_hash: row.get("token_hash"),
        family_id: row.get("family_id"),
        device_id: row.get("device_id"),
        device_info: row.get("device_info"),
        issued_at: row.get("issued_at"),
        expires_at: row.get("expires_at"),
        revoked: row.get("revoked"),
        authn_time: row.get("authn_time"),
        revoked_reason: row.get("revoked_reason"),
        revoked_at: row.get("revoked_at"),
    }
    .decode()
}

/// A timestamp column that must be valid. A row whose `expires_at` or
/// `issued_at` cannot be read is an integrity failure, not "now": falling
/// back to the current time would hand back a token that is neither expired
/// nor ageing, and the caller would honour it.
fn strict_datetime(
    column: &str,
    value: &str,
) -> Result<chrono::DateTime<chrono::Utc>, BackendError> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value) {
        return Ok(dt.into());
    }
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
        .map(|dt| dt.and_utc())
        .map_err(|_| BackendError::Backend(format!("refresh_tokens.{column} is not a timestamp")))
}

impl RawRefreshRow {
    /// Decode, failing closed: a malformed id or required timestamp is an
    /// error (no panic, no substituted value). `authn_time` is optional
    /// context, so an unreadable one becomes `None`, which the refresh path
    /// treats as "authentication time unknown".
    fn decode(self) -> Result<RefreshToken, BackendError> {
        use axess::authn::TenantId;
        let bad = |column: &str| BackendError::Backend(format!("refresh_tokens.{column} invalid"));
        Ok(RefreshToken {
            id: RefreshTokenId::try_new(&self.id).map_err(|_| bad("id"))?,
            user_id: UserId::try_new(&self.user_id).map_err(|_| bad("user_id"))?,
            tenant_id: TenantId::try_new(&self.tenant_id).map_err(|_| bad("tenant_id"))?,
            token_hash: self.token_hash,
            issued_at: strict_datetime("issued_at", &self.issued_at)?,
            expires_at: strict_datetime("expires_at", &self.expires_at)?,
            revoked: self.revoked != 0,
            device_info: self.device_info,
            family_id: self
                .family_id
                .as_deref()
                .map(|s| TokenFamilyId::try_new(s).map_err(|_| bad("family_id")))
                .transpose()?,
            device_id: self
                .device_id
                .as_deref()
                .map(|s| DeviceId::try_new(s).map_err(|_| bad("device_id")))
                .transpose()?,
            authn_time: self
                .authn_time
                .as_deref()
                .and_then(|t| strict_datetime("authn_time", t).ok()),
            revoked_reason: self
                .revoked_reason
                .as_deref()
                .and_then(RevocationReason::parse),
            revoked_at: self
                .revoked_at
                .as_deref()
                .and_then(|t| strict_datetime("revoked_at", t).ok()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> RawRefreshRow {
        RawRefreshRow {
            id: "00000000-0000-4000-8000-000000000001".into(),
            user_id: "00000000-0000-4000-8000-000000000002".into(),
            tenant_id: "00000000-0000-4000-8000-000000000003".into(),
            token_hash: "h".into(),
            family_id: None,
            device_id: None,
            device_info: None,
            issued_at: "2030-01-01T00:00:00Z".into(),
            expires_at: "2030-02-01T00:00:00Z".into(),
            revoked: 0,
            authn_time: Some("2030-01-01T00:00:00Z".into()),
            revoked_reason: None,
            revoked_at: None,
        }
    }

    #[test]
    fn a_well_formed_row_decodes() {
        let token = raw().decode().expect("decodes");
        assert!(token.authn_time.is_some());
    }

    #[test]
    fn a_corrupt_expiry_or_issue_time_fails_closed_instead_of_becoming_now() {
        for edit in [
            (|r: &mut RawRefreshRow| r.expires_at = "garbage".into()) as fn(&mut RawRefreshRow),
            |r| r.issued_at = String::new(),
        ] {
            let mut r = raw();
            edit(&mut r);
            assert!(r.decode().is_err());
        }
    }

    #[test]
    fn a_bad_id_is_an_error_not_a_panic() {
        let mut r = raw();
        r.id = String::new();
        assert!(r.decode().is_err());
    }

    #[test]
    fn an_unreadable_authn_time_becomes_none() {
        let mut r = raw();
        r.authn_time = Some("not a time".into());
        assert_eq!(r.decode().expect("decodes").authn_time, None);
    }
}
