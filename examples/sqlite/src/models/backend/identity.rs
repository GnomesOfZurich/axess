//! Identity-tier trait impls: `IdentityLookup`, `IdentityAuthnLog`,
//! `IdentityAdmin`.

use axess::authn::{
    AuthEvent, EntityState, LockoutPolicy, StatusDetail, Tenant, TenantId, User, UserId,
};
use chrono::{DateTime, Utc};
use sqlx::Row;
use tracing::debug;
use uuid::Uuid;

use super::{BackendError, OurBackend, entity_state_from_db, tenant_from_row, user_from_row};

impl axess::authn::IdentityLookup for OurBackend {
    type Error = BackendError;

    async fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, tenant_id, identifier, display_name, status, failed_attempts, locked_until,
                    created_by, created_at, updated_by, updated_at
             FROM users
             WHERE tenant_id = ?1 AND identifier = ?2",
        )
        .bind(tenant_id.to_string())
        .bind(identifier)
        .fetch_optional(self.pool())
        .await?;

        Ok(row.map(|r| user_from_row(self.clock(), &r)))
    }

    async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, tenant_id, identifier, display_name, status, failed_attempts, locked_until,
                    created_by, created_at, updated_by, updated_at
             FROM users
             WHERE id = ?1",
        )
        .bind(user_id.to_string())
        .fetch_optional(self.pool())
        .await?;

        Ok(row.map(|r| user_from_row(self.clock(), &r)))
    }

    async fn find_tenant(&self, identifier: &str) -> Result<Option<Tenant>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, identifier, name, status,
                    created_by, created_at, updated_by, updated_at
             FROM tenants WHERE identifier = ?1",
        )
        .bind(identifier)
        .fetch_optional(self.pool())
        .await?;

        Ok(row.map(|r| tenant_from_row(self.clock(), &r)))
    }

    async fn default_tenant(&self) -> Result<Tenant, Self::Error> {
        let row = sqlx::query(
            "SELECT id, identifier, name, status,
                    created_by, created_at, updated_by, updated_at
             FROM tenants ORDER BY rowid LIMIT 1",
        )
        .fetch_one(self.pool())
        .await?;

        Ok(tenant_from_row(self.clock(), &row))
    }

    async fn account_status(&self, user_id: &UserId) -> Result<EntityState, Self::Error> {
        let row = sqlx::query("SELECT status, locked_until FROM users WHERE id = ?1")
            .bind(user_id.to_string())
            .fetch_optional(self.pool())
            .await?;

        Ok(match row {
            None => EntityState::Guest,
            Some(r) => {
                let status: String = r.get("status");
                let locked_until: Option<String> = r.get("locked_until");
                entity_state_from_db(self.clock(), &status, locked_until.as_deref())
            }
        })
    }

    fn lockout_policy(&self) -> LockoutPolicy {
        LockoutPolicy {
            max_attempts: 5,
            duration: Some(std::time::Duration::from_secs(15 * 60)),
            ..LockoutPolicy::default()
        }
    }
}

impl axess::authn::IdentityAuthnLog for OurBackend {
    async fn record_event(&self, event: AuthEvent) -> Result<(), Self::Error> {
        let event_id = Uuid::new_v4().to_string();
        // Unresolved attribution (pre-auth failures, malformed OAuth claims)
        // persists as NULL so audit queries can distinguish "we don't know"
        // from a real principal. The schema's `user_id` / `tenant_id`
        // columns allow NULL for this reason.
        let user_id: Option<String> = event.user_id.as_ref().map(|u| u.to_string());
        let tenant_id: Option<String> = event.tenant_id.as_ref().map(|t| t.to_string());
        let session_id = event.session_id.map(|sid| sid.to_string());
        let event_type = event.event_type.to_string();
        let event_status = event.event_status.to_string();
        let event_time = DateTime::<Utc>::from_timestamp_micros(event.event_time)
            .expect("event_time micros in range")
            .to_rfc3339();
        let factor_kind = event.factor_kind.as_ref().map(|k| k.as_str().to_string());
        let ip_address = event.ip_address.as_deref().map(|s| s.to_string());
        let user_agent = event.user_agent.as_deref().map(|s| s.to_string());
        let request_id = event.request_id.as_deref().map(|s| s.to_string());
        let geo_country = event.geo_country.as_deref().map(|s| s.to_string());
        let error = event.error.as_deref().map(|s| s.to_string());

        sqlx::query(
            "INSERT INTO auth_events
             (id, user_id, tenant_id, session_id, event_type, event_status, event_time,
              factor_kind, ip_address, user_agent, request_id, geo_country, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )
        .bind(&event_id)
        .bind(&user_id)
        .bind(&tenant_id)
        .bind(&session_id)
        .bind(&event_type)
        .bind(&event_status)
        .bind(&event_time)
        .bind(&factor_kind)
        .bind(&ip_address)
        .bind(&user_agent)
        .bind(&request_id)
        .bind(&geo_country)
        .bind(&error)
        .execute(self.pool())
        .await?;

        debug!(
            event_type = %event_type,
            event_status = %event_status,
            user_id = user_id.as_deref().unwrap_or("<unattributed>"),
            "auth event recorded"
        );
        Ok(())
    }

    async fn record_failed_attempt(&self, user_id: &UserId) -> Result<u32, Self::Error> {
        sqlx::query("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?1")
            .bind(user_id.to_string())
            .execute(self.pool())
            .await?;

        let row = sqlx::query("SELECT failed_attempts FROM users WHERE id = ?1")
            .bind(user_id.to_string())
            .fetch_one(self.pool())
            .await?;

        let count: i64 = row.get("failed_attempts");
        Ok(count as u32)
    }

    async fn reset_failed_attempts(&self, user_id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("UPDATE users SET failed_attempts = 0 WHERE id = ?1")
            .bind(user_id.to_string())
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

impl axess::authn::IdentityAdmin for OurBackend {
    async fn create_user(&self, user: User) -> Result<(), Self::Error> {
        sqlx::query(
            "INSERT INTO users
                 (id, tenant_id, identifier, display_name, status,
                  created_by, created_at, updated_by, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(user.id.to_string())
        .bind(user.tenant_id.to_string())
        .bind(user.identifier.as_ref())
        .bind(user.display_name.as_ref())
        .bind(status_to_db(&user.status))
        .bind(user.created_by.to_string())
        .bind(user.created_at.to_rfc3339())
        .bind(user.updated_by.to_string())
        .bind(user.updated_at.to_rfc3339())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn create_tenant(&self, tenant: Tenant) -> Result<(), Self::Error> {
        sqlx::query(
            "INSERT INTO tenants
                 (id, identifier, name, status,
                  created_by, created_at, updated_by, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(tenant.id.to_string())
        .bind(tenant.identifier.as_ref())
        .bind(tenant.display_name.as_ref())
        .bind(status_to_db(&tenant.status))
        .bind(tenant.created_by.to_string())
        .bind(tenant.created_at.to_rfc3339())
        .bind(tenant.updated_by.to_string())
        .bind(tenant.updated_at.to_rfc3339())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn activate_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("UPDATE users SET status = 'active' WHERE id = ?1")
            .bind(user_id.to_string())
            .execute(self.pool())
            .await?;
        Ok(())
    }

    async fn suspend_user(
        &self,
        user_id: &UserId,
        detail: StatusDetail,
    ) -> Result<(), Self::Error> {
        let until = detail.until.map(|u| u.to_rfc3339());
        sqlx::query("UPDATE users SET status = 'suspended', locked_until = ?2 WHERE id = ?1")
            .bind(user_id.to_string())
            .bind(until)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    async fn record_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Self::Error> {
        // Idempotent on (user_id, hash): a re-recorded hash leaves the
        // earlier created_at untouched, which is fine for reuse-check
        // semantics (most-recent-N is a high-water mark, not a strict
        // ordering of unique insertions).
        sqlx::query(
            "INSERT INTO password_history (user_id, hash, created_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(user_id, hash) DO NOTHING",
        )
        .bind(user_id.to_string())
        .bind(hash)
        .bind(self.clock().now().to_rfc3339())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn password_history(
        &self,
        user_id: &UserId,
        count: usize,
    ) -> Result<Vec<String>, Self::Error> {
        let rows = sqlx::query(
            "SELECT hash FROM password_history
              WHERE user_id = ?1
              ORDER BY created_at DESC
              LIMIT ?2",
        )
        .bind(user_id.to_string())
        .bind(count as i64)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|r| r.get("hash")).collect())
    }

    async fn store_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        // Upsert: a new reset request invalidates any prior outstanding
        // token for the same user (a stale-token recipient cannot race
        // the legitimate one).
        sqlx::query(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(user_id) DO UPDATE SET
                 token_hash = excluded.token_hash,
                 expires_at = excluded.expires_at",
        )
        .bind(user_id.to_string())
        .bind(token_hash)
        .bind(expires_at.to_rfc3339())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn verify_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
    ) -> Result<bool, Self::Error> {
        // Single transaction: SELECT, compare in constant time, delete on
        // match (single-use). A token whose stored hash matches but has
        // expired counts as a miss and is left in place so the row expires
        // via a future sweep (the example backend does not run a periodic
        // cleaner).
        use subtle::ConstantTimeEq;

        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT token_hash, expires_at FROM password_reset_tokens WHERE user_id = ?1",
        )
        .bind(user_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            tx.commit().await?;
            return Ok(false);
        };
        let stored_hash: String = row.get("token_hash");
        let expires_at_str: String = row.get("expires_at");
        let Ok(expires_at) = DateTime::parse_from_rfc3339(&expires_at_str) else {
            tx.commit().await?;
            return Ok(false);
        };
        if expires_at.with_timezone(&Utc) <= self.clock().now() {
            tx.commit().await?;
            return Ok(false);
        }
        if stored_hash
            .as_bytes()
            .ct_eq(token_hash.as_bytes())
            .unwrap_u8()
            != 1
        {
            tx.commit().await?;
            return Ok(false);
        }

        sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ?1")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }
}

fn status_to_db(status: &EntityState) -> &'static str {
    match status {
        EntityState::Active => "active",
        EntityState::Candidate => "candidate",
        EntityState::Pending(_) => "pending",
        EntityState::Suspended(_) => "suspended",
        EntityState::Terminated(_) => "terminated",
        EntityState::Archived(_) => "archived",
        EntityState::Guest => "guest",
    }
}
