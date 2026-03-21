//! `OurBackend` — implements both [`IdentityStore`] and [`FactorStore`] against SQLite.
//!
//! This is the only application-specific type needed for authentication.
//! All identity and factor data live in the same SQLite pool.

use axess::{
    AuthEvent, AuthMethod, AuthnScope, EntityState, FactorConfig, FactorKind, FactorStore,
    IdentityStore, LockoutPolicy, PasswordConfig, PasswordRules, StatusDetail, Tenant, TotpConfig,
    User, ZeroizedString,
};
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

// ── OurBackend ────────────────────────────────────────────────────────────────

/// SQLite-backed identity and factor store.
///
/// Implements both [`IdentityStore`] and [`FactorStore`]. Pass `backend.clone()` for
/// both type parameters when constructing [`AuthnService`].
#[derive(Clone)]
pub struct OurBackend {
    pool: SqlitePool,
}

impl OurBackend {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

// ── IdentityStore impl ────────────────────────────────────────────────────────

impl IdentityStore for OurBackend {
    type Error = BackendError;

    async fn find_user(
        &self,
        identifier: &str,
        tenant_id: &str,
    ) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, tenant_id, identifier, display_name, status, failed_attempts, locked_until
             FROM users
             WHERE tenant_id = ?1 AND identifier = ?2",
        )
        .bind(tenant_id)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| user_from_row(&r)))
    }

    async fn get_user(&self, user_id: &str) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, tenant_id, identifier, display_name, status, failed_attempts, locked_until
             FROM users
             WHERE id = ?1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| user_from_row(&r)))
    }

    async fn find_tenant(&self, identifier: &str) -> Result<Option<Tenant>, Self::Error> {
        let row =
            sqlx::query("SELECT id, identifier, name, status FROM tenants WHERE identifier = ?1")
                .bind(identifier)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map(|r| tenant_from_row(&r)))
    }

    async fn default_tenant(&self) -> Result<Tenant, Self::Error> {
        let row =
            sqlx::query("SELECT id, identifier, name, status FROM tenants ORDER BY rowid LIMIT 1")
                .fetch_one(&self.pool)
                .await?;

        Ok(tenant_from_row(&row))
    }

    async fn account_status(&self, user_id: &str) -> Result<EntityState, Self::Error> {
        let row = sqlx::query("SELECT status, locked_until FROM users WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(match row {
            None => EntityState::Guest,
            Some(r) => {
                let status: String = r.get("status");
                let locked_until: Option<String> = r.get("locked_until");
                entity_state_from_db(&status, locked_until.as_deref())
            }
        })
    }

    async fn record_event(&self, event: AuthEvent) -> Result<(), Self::Error> {
        let event_id = Uuid::new_v4().to_string();
        let user_id = event.user_id.as_ref().to_string();
        let tenant_id = event.tenant_id.as_ref().to_string();
        let session_id = event.session_id.map(|sid| sid.to_string());
        let event_type = event.event_type.to_string();
        let event_status = event.event_status.to_string();
        let event_time = event.event_time.to_rfc3339();
        let factor_kind = event.factor_kind.as_ref().map(|k| k.as_str().to_string());
        let ip_address = event.ip_address.as_deref().map(|s| s.to_string());
        let user_agent = event.user_agent.as_deref().map(|s| s.to_string());
        let error = event.error.as_deref().map(|s| s.to_string());

        sqlx::query(
            "INSERT INTO auth_events
             (id, user_id, tenant_id, session_id, event_type, event_status, event_time,
              factor_kind, ip_address, user_agent, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
        .bind(&error)
        .execute(&self.pool)
        .await?;

        debug!(
            event_type = %event_type,
            event_status = %event_status,
            user_id = %user_id,
            "auth event recorded"
        );
        Ok(())
    }

    async fn record_failed_attempt(&self, user_id: &str) -> Result<u32, Self::Error> {
        sqlx::query("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        let row = sqlx::query("SELECT failed_attempts FROM users WHERE id = ?1")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;

        let count: i64 = row.get("failed_attempts");
        Ok(count as u32)
    }

    async fn reset_failed_attempts(&self, user_id: &str) -> Result<(), Self::Error> {
        sqlx::query("UPDATE users SET failed_attempts = 0 WHERE id = ?1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn lockout_policy(&self) -> LockoutPolicy {
        LockoutPolicy {
            max_attempts: 5,
            duration: Some(std::time::Duration::from_secs(15 * 60)),
        }
    }
}

// ── FactorStore impl ──────────────────────────────────────────────────────────

impl FactorStore for OurBackend {
    type Error = BackendError;

    async fn load_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<FactorConfig>, Self::Error> {
        let kind_str = kind.as_str();

        // Scope resolution: User > Tenant > Global.
        match scope {
            AuthnScope::User { tenant_id, user_id } => {
                // 1. User scope
                if let Some(cfg) = fetch_factor_config(
                    &self.pool,
                    kind_str,
                    Some(user_id.as_ref()),
                    Some(tenant_id.as_ref()),
                )
                .await?
                {
                    return Ok(Some(cfg));
                }
                // 2. Tenant scope
                if let Some(cfg) =
                    fetch_factor_config(&self.pool, kind_str, None, Some(tenant_id.as_ref()))
                        .await?
                {
                    return Ok(Some(cfg));
                }
                // 3. Global scope
                fetch_factor_config(&self.pool, kind_str, None, None).await
            }
            AuthnScope::Tenant(tenant_id) => {
                if let Some(cfg) =
                    fetch_factor_config(&self.pool, kind_str, None, Some(tenant_id.as_ref()))
                        .await?
                {
                    return Ok(Some(cfg));
                }
                fetch_factor_config(&self.pool, kind_str, None, None).await
            }
            AuthnScope::Global => fetch_factor_config(&self.pool, kind_str, None, None).await,
        }
    }

    async fn save_factor(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> Result<(), Self::Error> {
        let kind_str = config.kind().as_str().to_string();
        let config_json = serde_json::to_string(&config)?;
        let id = Uuid::new_v4().to_string();

        let (user_id, tenant_id): (Option<String>, Option<String>) = match scope {
            AuthnScope::User { user_id, tenant_id } => {
                (Some(user_id.to_string()), Some(tenant_id.to_string()))
            }
            AuthnScope::Tenant(tid) => (None, Some(tid.to_string())),
            AuthnScope::Global => (None, None),
        };

        sqlx::query(
            "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, datetime('now'))
             ON CONFLICT(user_id, tenant_id, kind) DO UPDATE SET
                 config_json = excluded.config_json,
                 updated_at  = excluded.updated_at",
        )
        .bind(&id)
        .bind(&user_id)
        .bind(&tenant_id)
        .bind(&kind_str)
        .bind(&config_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn available_methods(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<Vec<AuthMethod>, Self::Error> {
        let rows = sqlx::query(
            "SELECT id, name, factors_json, user_id, tenant_id
             FROM auth_methods
             WHERE enabled = 1
               AND (user_id = ?1 OR (user_id IS NULL AND tenant_id = ?2))
             ORDER BY CASE WHEN user_id IS NOT NULL THEN 0 ELSE 1 END, rowid",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let mut methods = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: String = row.get("id");
            let name: String = row.get("name");
            let factors_json: String = row.get("factors_json");
            let row_user_id: Option<String> = row.get("user_id");

            let factors: Vec<FactorKind> =
                serde_json::from_str(&factors_json).unwrap_or_else(|err| {
                    warn!(
                        method_id = %id,
                        error = %err,
                        "Failed to parse factors_json; treating as empty"
                    );
                    vec![]
                });

            let scope = if row_user_id.is_some() {
                AuthnScope::User {
                    tenant_id: tenant_id.into(),
                    user_id: user_id.into(),
                }
            } else {
                AuthnScope::Tenant(tenant_id.into())
            };

            methods.push(AuthMethod {
                name: name.into(),
                factors,
                scope,
            });
        }

        Ok(methods)
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Fetch a single `FactorConfig` from `factor_configs` for the given exact scope.
///
/// Pass `None` for `user_id` / `tenant_id` to query for the global / tenant scope.
async fn fetch_factor_config(
    pool: &SqlitePool,
    kind: &str,
    user_id: Option<&str>,
    tenant_id: Option<&str>,
) -> Result<Option<FactorConfig>, BackendError> {
    // Build the WHERE clause dynamically based on which scope fields are provided.
    let (user_clause, tenant_clause) = match (user_id, tenant_id) {
        (Some(_), Some(_)) => ("user_id = ?2", "tenant_id = ?3"),
        (None, Some(_)) => ("user_id IS NULL", "tenant_id = ?2"),
        (None, None) => ("user_id IS NULL", "tenant_id IS NULL"),
        (Some(_), None) => ("user_id = ?2", "tenant_id IS NULL"),
    };

    let sql = format!(
        "SELECT config_json FROM factor_configs
         WHERE kind = ?1 AND {user_clause} AND {tenant_clause} AND enabled = 1
         LIMIT 1"
    );

    let mut q = sqlx::query(&sql).bind(kind);
    if let Some(uid) = user_id {
        q = q.bind(uid);
    }
    if let Some(tid) = tenant_id {
        q = q.bind(tid);
    }

    let row = q.fetch_optional(pool).await?;
    match row {
        None => Ok(None),
        Some(r) => {
            let json: String = r.get("config_json");
            Ok(Some(serde_json::from_str(&json)?))
        }
    }
}

fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> User {
    let id: String = row.get("id");
    let tenant_id: String = row.get("tenant_id");
    let identifier: String = row.get("identifier");
    let display_name: String = row.get("display_name");
    let status: String = row.get("status");
    let locked_until: Option<String> = row.get("locked_until");

    User {
        id: Arc::from(id.as_str()),
        tenant_id: Arc::from(tenant_id.as_str()),
        identifier: Arc::from(identifier.as_str()),
        display_name: Arc::from(display_name.as_str()),
        status: entity_state_from_db(&status, locked_until.as_deref()),
    }
}

fn tenant_from_row(row: &sqlx::sqlite::SqliteRow) -> Tenant {
    let id: String = row.get("id");
    let identifier: String = row.get("identifier");
    let name: String = row.get("name");
    let status: String = row.get("status");

    Tenant {
        id: Arc::from(id.as_str()),
        identifier: Arc::from(identifier.as_str()),
        display_name: Arc::from(name.as_str()),
        status: entity_state_from_db(&status, None),
    }
}

/// Map the DB status string (and optional `locked_until` datetime) to [`EntityState`].
fn entity_state_from_db(status: &str, locked_until: Option<&str>) -> EntityState {
    // A locked_until in the future takes priority over the status column.
    if let Some(until_str) = locked_until {
        if let Ok(until) = DateTime::parse_from_rfc3339(until_str) {
            let until: DateTime<Utc> = until.into();
            if until > Utc::now() {
                return EntityState::Suspended(StatusDetail {
                    reason: "account locked due to failed login attempts".into(),
                    since: Utc::now(),
                    until: Some(until),
                });
            }
        }
    }

    match status {
        "active" => EntityState::Active,
        "candidate" => EntityState::Candidate,
        "pending" => EntityState::Pending(StatusDetail {
            reason: "account pending activation".into(),
            since: Utc::now(),
            until: None,
        }),
        "suspended" => EntityState::Suspended(StatusDetail {
            reason: "account suspended".into(),
            since: Utc::now(),
            until: None,
        }),
        "terminated" => EntityState::Terminated(StatusDetail {
            reason: "account terminated".into(),
            since: Utc::now(),
            until: None,
        }),
        "archived" => EntityState::Archived(StatusDetail {
            reason: "account archived".into(),
            since: Utc::now(),
            until: None,
        }),
        _ => EntityState::Guest,
    }
}

// ── Seed data ─────────────────────────────────────────────────────────────────

/// Seed the database with a default tenant and two test users.
///
/// - **alice** — password-only login (`hunter2`)
/// - **bob**   — password + TOTP login (`hunter2`)
///
/// Returns Bob's TOTP secret so the caller can log it.
/// Idempotent: safe to call on every startup.
pub async fn seed(pool: &SqlitePool) -> Result<String, Box<dyn std::error::Error>> {
    let tenant_id = "00000000-0000-0000-0000-000000000001";
    let tenant_identifier = "default";

    // Tenant
    sqlx::query(
        "INSERT INTO tenants (id, identifier, name, status)
         VALUES (?1, ?2, 'Default Tenant', 'active')
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(tenant_identifier)
    .execute(pool)
    .await?;

    // Alice (password-only)
    let alice_id = "00000000-0000-0000-0000-000000000010";
    sqlx::query(
        "INSERT INTO users (id, tenant_id, identifier, display_name, status)
         VALUES (?1, ?2, 'alice', 'Alice Example', 'active')
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(alice_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    // Bob (password + TOTP)
    let bob_id = "00000000-0000-0000-0000-000000000020";
    sqlx::query(
        "INSERT INTO users (id, tenant_id, identifier, display_name, status)
         VALUES (?1, ?2, 'bob', 'Bob Example', 'active')
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(bob_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    // Password hash for "hunter2".
    let password_hash = axess_factors::generate_password_hash("hunter2");

    // Alice: password factor config at user scope.
    let alice_pw_config = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(password_hash.clone()),
        rules: PasswordRules::default(),
    });
    let alice_pw_json = serde_json::to_string(&alice_pw_config)?;
    let alice_pw_fc_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled)
         VALUES (?1, ?2, ?3, 'password', ?4, 1)
         ON CONFLICT(user_id, tenant_id, kind) DO NOTHING",
    )
    .bind(&alice_pw_fc_id)
    .bind(alice_id)
    .bind(tenant_id)
    .bind(&alice_pw_json)
    .execute(pool)
    .await?;

    // Alice: auth_method "password" at user scope.
    let alice_method_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO auth_methods (id, name, factors_json, user_id, tenant_id, enabled)
         VALUES (?1, 'password', '[\"Password\"]', ?2, ?3, 1)
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(&alice_method_id)
    .bind(alice_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    // Bob: password factor config at user scope.
    let bob_pw_config = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(password_hash),
        rules: PasswordRules::default(),
    });
    let bob_pw_json = serde_json::to_string(&bob_pw_config)?;
    let bob_pw_fc_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled)
         VALUES (?1, ?2, ?3, 'password', ?4, 1)
         ON CONFLICT(user_id, tenant_id, kind) DO NOTHING",
    )
    .bind(&bob_pw_fc_id)
    .bind(bob_id)
    .bind(tenant_id)
    .bind(&bob_pw_json)
    .execute(pool)
    .await?;

    // Bob: TOTP factor config at user scope.
    // Reuse existing secret if already seeded, so the TOTP app doesn't need to be re-enrolled.
    let existing_totp: Option<String> = sqlx::query(
        "SELECT config_json FROM factor_configs
         WHERE user_id = ?1 AND tenant_id = ?2 AND kind = 'totp'",
    )
    .bind(bob_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    .map(|r| r.get("config_json"));

    let totp_secret = if let Some(json) = existing_totp {
        let config: FactorConfig = serde_json::from_str(&json)?;
        if let FactorConfig::Totp(ref tc) = config {
            tc.secret.to_string()
        } else {
            axess_factors::generate_totp_secret()
        }
    } else {
        let secret = axess_factors::generate_totp_secret();
        let bob_totp_config = FactorConfig::Totp(TotpConfig {
            secret: ZeroizedString::new(secret.clone()),
            ..TotpConfig::default()
        });
        let bob_totp_json = serde_json::to_string(&bob_totp_config)?;
        let bob_totp_fc_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled)
             VALUES (?1, ?2, ?3, 'totp', ?4, 1)
             ON CONFLICT(user_id, tenant_id, kind) DO NOTHING",
        )
        .bind(&bob_totp_fc_id)
        .bind(bob_id)
        .bind(tenant_id)
        .bind(&bob_totp_json)
        .execute(pool)
        .await?;
        secret
    };

    // Bob: auth_method "password+totp" at user scope.
    let bob_method_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO auth_methods (id, name, factors_json, user_id, tenant_id, enabled)
         VALUES (?1, 'password+totp', '[\"Password\",\"Totp\"]', ?2, ?3, 1)
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(&bob_method_id)
    .bind(bob_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    Ok(totp_secret)
}
