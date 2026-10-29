//! Identity-tier trait impls: `IdentityLookup`, `IdentityAuthnLog`,
//! `IdentityAdmin`.

use axess::authn::{
    AuditOutcome, AuthEvent, EntityState, LockoutPolicy, StatusDetail, Tenant, TenantId, User,
    UserId,
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

    async fn get_tenant(&self, tenant_id: &TenantId) -> Result<Option<Tenant>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, identifier, name, status,
                    created_by, created_at, updated_by, updated_at
             FROM tenants WHERE id = ?1",
        )
        .bind(tenant_id.to_string())
        .fetch_optional(self.pool())
        .await?;

        Ok(row.map(|r| tenant_from_row(self.clock(), &r)))
    }

    async fn get_user_tenant(&self, user_id: &UserId) -> Result<Option<TenantId>, Self::Error> {
        // Only the tenant column: the session validator asks on every request
        // and needs nothing else about the user.
        let tenant: Option<String> =
            sqlx::query_scalar("SELECT tenant_id FROM users WHERE id = ?1")
                .bind(user_id.to_string())
                .fetch_optional(self.pool())
                .await?;
        tenant
            .map(|t| {
                TenantId::try_new(t.as_str()).map_err(|e| {
                    BackendError::Backend(format!("users.tenant_id is not a valid TenantId: {e}"))
                })
            })
            .transpose()
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

// ANCHOR: authn_log
impl axess::authn::IdentityAuthnLog for OurBackend {
    async fn record_event(&self, event: AuthEvent) -> Result<AuditOutcome, Self::Error> {
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
        let ip_address = event.ip_address.map(|ip| ip.to_string());
        let ip_source = event.ip_source.as_str();
        let user_agent = event.user_agent.as_deref().map(|s| s.to_string());
        let request_id = event.request_id.as_deref().map(|s| s.to_string());
        let trace_id = event.trace_id.as_deref().map(|s| s.to_string());
        let geo_country = event.geo_country.as_deref().map(|s| s.to_string());
        let error = event.error.as_ref().map(|r| r.as_str().to_string());

        sqlx::query(
            "INSERT INTO auth_events
             (id, user_id, tenant_id, session_id, event_type, event_status, event_time,
              factor_kind, ip_address, ip_source, user_agent, request_id, trace_id,
              geo_country, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
        .bind(ip_source)
        .bind(&user_agent)
        .bind(&request_id)
        .bind(&trace_id)
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
        // This example writes every event. A sink that needs to protect
        // its storage under a flood of unauthenticated login attempts
        // returns `AuditOutcome::Shed` instead, on a criterion that does
        // not depend on the identifier.
        Ok(AuditOutcome::Recorded)
    }

    async fn record_failed_attempt(&self, user_id: &UserId) -> Result<u32, Self::Error> {
        // One statement: the increment and the read cannot be separated by
        // a concurrent failure. A failure older than the policy's window
        // starts the count again instead of adding to it.
        let now = self.clock().now();
        let window = chrono::Duration::from_std(
            axess::authn::IdentityLookup::lockout_policy(self).attempt_window,
        )
        .unwrap_or_else(|_| chrono::Duration::hours(1));
        let row = sqlx::query(
            "UPDATE users
             SET failed_attempts = CASE
                     WHEN last_failed_at IS NULL OR last_failed_at < ?3 THEN 1
                     ELSE failed_attempts + 1
                 END,
                 last_failed_at = ?2
             WHERE id = ?1
             RETURNING failed_attempts",
        )
        .bind(user_id.to_string())
        .bind(failure_time(now))
        .bind(failure_time(now - window))
        .fetch_one(self.pool())
        .await?;

        let count: i64 = row.get("failed_attempts");
        Ok(count as u32)
    }

    async fn reserve_attempt(
        &self,
        user_id: &UserId,
        policy: &axess::authn::LockoutPolicy,
    ) -> Result<Option<u32>, Self::Error> {
        // The test and the increment are one statement. The count is fresh
        // (replaced by one) when there is no failure, the last is older than
        // the attempt window, or a timed lockout has run out; otherwise the
        // guess is granted while the count is under the limit. When no row is
        // updated the account is at its limit and the guess is refused, so
        // parallel guesses cannot pass it.
        let now = self.clock().now();
        let back = |d: std::time::Duration| {
            failure_time(now - chrono::Duration::from_std(d).unwrap_or(chrono::Duration::hours(1)))
        };
        let window_start = back(policy.attempt_window);
        let lock_ended_by = policy.duration.map(back);
        let row = sqlx::query(
            "UPDATE users
             SET failed_attempts = CASE
                     WHEN last_failed_at IS NULL OR last_failed_at < ?3
                          OR (failed_attempts >= ?4 AND ?5 IS NOT NULL AND last_failed_at <= ?5)
                     THEN 1
                     ELSE failed_attempts + 1
                 END,
                 last_failed_at = ?2
             WHERE id = ?1
               AND (last_failed_at IS NULL OR last_failed_at < ?3
                    OR failed_attempts < ?4
                    OR (?5 IS NOT NULL AND last_failed_at <= ?5))
             RETURNING failed_attempts",
        )
        .bind(user_id.to_string())
        .bind(failure_time(now))
        .bind(window_start)
        .bind(i64::from(policy.effective_max_attempts()))
        .bind(lock_ended_by)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|row| row.get::<i64, _>("failed_attempts") as u32))
    }

    async fn release_attempt(&self, user_id: &UserId) -> Result<(), Self::Error> {
        sqlx::query(
            "UPDATE users
             SET last_failed_at = CASE WHEN failed_attempts <= 1 THEN NULL ELSE last_failed_at END,
                 failed_attempts = MAX(failed_attempts - 1, 0)
             WHERE id = ?1",
        )
        .bind(user_id.to_string())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn failed_attempts(
        &self,
        user_id: &UserId,
    ) -> Result<(u32, Option<DateTime<Utc>>), Self::Error> {
        let row = sqlx::query("SELECT failed_attempts, last_failed_at FROM users WHERE id = ?1")
            .bind(user_id.to_string())
            .fetch_optional(self.pool())
            .await?;
        let Some(row) = row else {
            return Ok((0, None));
        };
        let count: i64 = row.get("failed_attempts");
        let last: Option<String> = row.get("last_failed_at");
        let last = last
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.with_timezone(&Utc));
        // Failures older than the window have expired, as in the increment.
        let window = chrono::Duration::from_std(
            axess::authn::IdentityLookup::lockout_policy(self).attempt_window,
        )
        .unwrap_or_else(|_| chrono::Duration::hours(1));
        if last.is_some_and(|t| self.clock().now() - t > window) {
            return Ok((0, None));
        }
        Ok((count as u32, last))
    }

    async fn reset_failed_attempts(&self, user_id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("UPDATE users SET failed_attempts = 0, last_failed_at = NULL WHERE id = ?1")
            .bind(user_id.to_string())
            .execute(self.pool())
            .await?;
        Ok(())
    }
}
// ANCHOR_END: authn_log

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

    /// Erase the user in one transaction: factor configs, auth methods,
    /// password history, the pending reset token and refresh tokens are
    /// deleted, audit rows keep their place with the user column cleared
    /// (the log outlives the account but no longer names it), and the user
    /// row goes last. A missing user is `RowNotFound`.
    ///
    /// Sessions are not touched here: the example's session store keeps
    /// them encrypted under a key this backend does not hold, with no user
    /// column to select on, and the example runs no session registry to ask.
    /// The user's sessions therefore expire on their own. A deployment that
    /// tracks sessions per user in a registry invalidates
    /// that user's sessions through it alongside this call.
    async fn delete_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
        let id = user_id.to_string();
        let mut tx = self.pool().begin().await?;
        let found = sqlx::query("SELECT 1 FROM users WHERE id = ?1")
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await?;
        if found.is_none() {
            return Err(sqlx::Error::RowNotFound.into());
        }
        for statement in [
            "DELETE FROM factor_configs WHERE user_id = ?1",
            "DELETE FROM auth_methods WHERE user_id = ?1",
            "DELETE FROM password_history WHERE user_id = ?1",
            "DELETE FROM password_reset_tokens WHERE user_id = ?1",
            "DELETE FROM refresh_tokens WHERE user_id = ?1",
        ] {
            sqlx::query(statement).bind(&id).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE auth_events SET user_id = NULL WHERE user_id = ?1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
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

impl axess::authn::IdentityPasswordReset for OurBackend {
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
        now: DateTime<Utc>,
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
        if expires_at.with_timezone(&Utc) <= now {
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

    async fn check_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        // The same comparison as `verify_reset_token`, without the delete.
        use subtle::ConstantTimeEq;

        let row = sqlx::query(
            "SELECT token_hash, expires_at FROM password_reset_tokens WHERE user_id = ?1",
        )
        .bind(user_id.to_string())
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let stored_hash: String = row.get("token_hash");
        let expires_at_str: String = row.get("expires_at");
        let Ok(expires_at) = DateTime::parse_from_rfc3339(&expires_at_str) else {
            return Ok(false);
        };
        Ok(expires_at.with_timezone(&Utc) > now
            && stored_hash
                .as_bytes()
                .ct_eq(token_hash.as_bytes())
                .unwrap_u8()
                == 1)
    }
}

/// Password-reuse prevention, carved out of `IdentityAdmin` in 0.6.0.
///
/// A backend with no reuse policy simply does not implement this trait;
/// the password-change flow is then unavailable to it at compile time,
/// rather than panicking on the first change a user makes.
impl axess::authn::IdentityPasswordHistory for OurBackend {
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
}

/// A failure time in the one fixed-width form the window comparison in
/// SQL sorts correctly as text.
fn failure_time(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}
