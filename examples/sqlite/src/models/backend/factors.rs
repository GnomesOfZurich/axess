//! `FactorStore` trait impl.
//!
//! Storage encoding: `factor_configs.tenant_id` and `auth_methods.tenant_id`
//! are NOT NULL and reference `tenants(id)`. System-scope rows live under
//! [`TenantId::SYSTEM`] — there is no NULL-tenant encoding for
//! configuration scope. See `docs/authentication/scope.md`.

use axess::authn::{
    AuthMethod, AuthnScope, FactorConfig, FactorKind, FactorStep, FactorStore, ResolvedFactor,
    TenantId, UserId,
};
use sqlx::{AssertSqlSafe, Row};
use tracing::warn;
use uuid::Uuid;

use super::{BackendError, OurBackend};

impl FactorStore for OurBackend {
    type Error = BackendError;

    /// Runtime resolution in ONE query. Walks the User → Tenant → System
    /// chain via an ordered `SELECT` that ranks rows narrowest-first and
    /// takes the top hit. Also returns the scope the config was resolved
    /// from so callers can CAS at the correct tier.
    async fn resolve_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<ResolvedFactor>, Self::Error> {
        let kind_str = kind.as_str();
        let cols = scope.as_columns();
        let tenant_str = cols.tenant_id.to_string();
        let system_str = TenantId::SYSTEM.to_string();

        // Query shape depends on scope narrowness:
        //   User    → try user@tenant, then anyone@tenant, then anyone@SYSTEM
        //   Tenant  → try anyone@tenant, then anyone@SYSTEM
        //   System  → try anyone@SYSTEM
        // Each `SELECT ... UNION ALL ... ORDER BY rank LIMIT 1` collapses
        // to a single round trip.
        let row = match &cols.user_id {
            Some(user_id) => {
                let user_str = user_id.to_string();
                sqlx::query(
                    "SELECT config_json, user_id, tenant_id, 0 AS rank
                       FROM factor_configs
                      WHERE kind = ?1 AND enabled = 1
                        AND user_id = ?2 AND tenant_id = ?3
                     UNION ALL
                     SELECT config_json, user_id, tenant_id, 1 AS rank
                       FROM factor_configs
                      WHERE kind = ?1 AND enabled = 1
                        AND user_id IS NULL AND tenant_id = ?3
                     UNION ALL
                     SELECT config_json, user_id, tenant_id, 2 AS rank
                       FROM factor_configs
                      WHERE kind = ?1 AND enabled = 1
                        AND user_id IS NULL AND tenant_id = ?4
                     ORDER BY rank
                     LIMIT 1",
                )
                .bind(kind_str)
                .bind(&user_str)
                .bind(&tenant_str)
                .bind(&system_str)
                .fetch_optional(self.pool())
                .await?
            }
            None if tenant_str != system_str => {
                sqlx::query(
                    "SELECT config_json, user_id, tenant_id, 0 AS rank
                   FROM factor_configs
                  WHERE kind = ?1 AND enabled = 1
                    AND user_id IS NULL AND tenant_id = ?2
                 UNION ALL
                 SELECT config_json, user_id, tenant_id, 1 AS rank
                   FROM factor_configs
                  WHERE kind = ?1 AND enabled = 1
                    AND user_id IS NULL AND tenant_id = ?3
                 ORDER BY rank
                 LIMIT 1",
                )
                .bind(kind_str)
                .bind(&tenant_str)
                .bind(&system_str)
                .fetch_optional(self.pool())
                .await?
            }
            None => {
                sqlx::query(
                    "SELECT config_json, user_id, tenant_id
                       FROM factor_configs
                      WHERE kind = ?1 AND enabled = 1
                        AND user_id IS NULL AND tenant_id = ?2
                      LIMIT 1",
                )
                .bind(kind_str)
                .bind(&system_str)
                .fetch_optional(self.pool())
                .await?
            }
        };

        let Some(r) = row else { return Ok(None) };
        let json: String = r.get("config_json");
        let row_user: Option<String> = r.get("user_id");
        let row_tenant: String = r.get("tenant_id");
        let resolved_from = decode_scope(&row_tenant, row_user.as_deref())?;
        let config: FactorConfig = serde_json::from_str(&json)?;
        Ok(Some(ResolvedFactor {
            config,
            resolved_from,
        }))
    }

    /// Exact-scope lookup with no fallback. Admin / display path.
    async fn load_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<FactorConfig>, Self::Error> {
        let cols = scope.as_columns();
        let tenant_str = cols.tenant_id.to_string();
        let user_str = cols.user_id.map(|u| u.to_string());

        let (user_clause, bind_offset) = if user_str.is_some() {
            ("user_id = ?3", true)
        } else {
            ("user_id IS NULL", false)
        };

        let sql = format!(
            "SELECT config_json FROM factor_configs
              WHERE kind = ?1 AND {user_clause} AND tenant_id = ?2 AND enabled = 1
              LIMIT 1"
        );

        let mut q = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(kind.as_str())
            .bind(&tenant_str);
        if bind_offset {
            q = q.bind(user_str.as_deref().unwrap());
        }
        match q.fetch_optional(self.pool()).await? {
            None => Ok(None),
            Some(r) => {
                let json: String = r.get("config_json");
                Ok(Some(serde_json::from_str(&json)?))
            }
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

        let cols = scope.as_columns();
        let tenant_str = cols.tenant_id.to_string();
        let user_str = cols.user_id.map(|u| u.to_string());

        sqlx::query(
            "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, datetime('now'))
             ON CONFLICT(user_id, tenant_id, kind) DO UPDATE SET
                 config_json = excluded.config_json,
                 updated_at  = excluded.updated_at",
        )
        .bind(&id)
        .bind(&user_str)
        .bind(&tenant_str)
        .bind(&kind_str)
        .bind(&config_json)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn compare_and_save_factor(
        &self,
        scope: &AuthnScope,
        prior: &FactorConfig,
        updated: FactorConfig,
    ) -> Result<bool, Self::Error> {
        // CAS via a single UPDATE … WHERE config_json = (prior canonical
        // JSON). When `rows_affected()` is 0 the prior value didn't match:
        // either a concurrent writer beat us to it (TOTP/HOTP credential
        // already spent) or the row was deleted out from under us. The
        // example uses `serde_json::to_string`; a production backend would
        // canonicalise to defeat key-ordering drift.
        let kind_str = prior.kind().as_str().to_string();
        let prior_json = serde_json::to_string(prior)?;
        let updated_json = serde_json::to_string(&updated)?;

        let cols = scope.as_columns();
        let tenant_str = cols.tenant_id.to_string();
        let user_str = cols.user_id.map(|u| u.to_string());

        // tenant_id is always populated; only user_id needs the NULL branch.
        let (user_clause, prior_placeholder) = if user_str.is_some() {
            ("user_id = ?3", 5_usize)
        } else {
            ("user_id IS NULL", 4_usize)
        };
        let sql = format!(
            "UPDATE factor_configs
                SET config_json = ?1,
                    updated_at  = datetime('now')
              WHERE kind = ?2
                AND {user_clause}
                AND tenant_id = ?{tenant_placeholder}
                AND config_json = ?{prior_placeholder}",
            tenant_placeholder = if user_str.is_some() { 4 } else { 3 },
        );

        let mut q = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(&updated_json)
            .bind(&kind_str);
        if let Some(uid) = &user_str {
            q = q.bind(uid);
        }
        q = q.bind(&tenant_str).bind(&prior_json);

        let res = q.execute(self.pool()).await?;
        Ok(res.rows_affected() > 0)
    }

    async fn available_methods(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<Vec<AuthMethod>, Self::Error> {
        let rows = sqlx::query(
            "SELECT id, name, steps_json, user_id, tenant_id
             FROM auth_methods
             WHERE enabled = 1
               AND (user_id = ?1 OR (user_id IS NULL AND tenant_id = ?2))
             ORDER BY CASE WHEN user_id IS NOT NULL THEN 0 ELSE 1 END, rowid",
        )
        .bind(user_id.to_string())
        .bind(tenant_id.to_string())
        .fetch_all(self.pool())
        .await?;

        let mut methods = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: String = row.get("id");
            let name: String = row.get("name");
            let steps_json: String = row.get("steps_json");
            let row_user_id: Option<String> = row.get("user_id");

            let steps: Vec<FactorStep> = serde_json::from_str(&steps_json).unwrap_or_else(|err| {
                warn!(
                    method_id = %id,
                    error = %err,
                    "Failed to parse steps_json; treating as empty"
                );
                vec![]
            });

            let scope = if row_user_id.is_some() {
                AuthnScope::User {
                    tenant_id: *tenant_id,
                    user_id: *user_id,
                }
            } else {
                AuthnScope::Tenant(*tenant_id)
            };

            methods.push(AuthMethod {
                name: name.into(),
                steps,
                scope,
            });
        }

        Ok(methods)
    }

    async fn save_method(&self, scope: &AuthnScope, method: AuthMethod) -> Result<(), Self::Error> {
        let (user_id, tenant_id): (Option<String>, String) = match scope {
            AuthnScope::User { user_id, tenant_id } => {
                (Some(user_id.to_string()), tenant_id.to_string())
            }
            AuthnScope::Tenant(t) => (None, t.to_string()),
            AuthnScope::System => {
                // Runtime system auth methods are not supported in this
                // backend: methods must be materialised per tenant (see
                // `docs/tenancy.md`). Reject to surface the mistake.
                return Err(BackendError::InvalidSystemMethod);
            }
        };

        let steps_json = serde_json::to_string(&method.steps)?;
        let id = Uuid::new_v4().to_string();

        // Idempotent on (user_id, tenant_id, name): re-saving a method
        // with the same scope + name updates steps / re-enables the row.
        sqlx::query(
            "INSERT INTO auth_methods (id, name, steps_json, user_id, tenant_id, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)
             ON CONFLICT(user_id, tenant_id, name) DO UPDATE SET
                 steps_json = excluded.steps_json,
                 enabled    = 1",
        )
        .bind(&id)
        .bind(method.name.as_ref())
        .bind(&steps_json)
        .bind(&user_id)
        .bind(&tenant_id)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn remove_method(&self, scope: &AuthnScope, name: &str) -> Result<(), Self::Error> {
        let (user_clause, user_id, tenant_id) = match scope {
            AuthnScope::User { user_id, tenant_id } => (
                "user_id = ?2",
                Some(user_id.to_string()),
                tenant_id.to_string(),
            ),
            AuthnScope::Tenant(t) => ("user_id IS NULL", None, t.to_string()),
            AuthnScope::System => return Err(BackendError::InvalidSystemMethod),
        };
        let sql = format!(
            "DELETE FROM auth_methods WHERE name = ?1 AND {user_clause} AND tenant_id = ?{}",
            if user_id.is_some() { 3 } else { 2 }
        );

        let mut q = sqlx::query(AssertSqlSafe(sql.as_str())).bind(name);
        if let Some(uid) = &user_id {
            q = q.bind(uid);
        }
        q = q.bind(&tenant_id);
        q.execute(self.pool()).await?;
        Ok(())
    }

    async fn set_method_enabled(
        &self,
        scope: &AuthnScope,
        name: &str,
        enabled: bool,
    ) -> Result<bool, Self::Error> {
        let (user_clause, user_id, tenant_id) = match scope {
            AuthnScope::User { user_id, tenant_id } => (
                "user_id = ?3",
                Some(user_id.to_string()),
                tenant_id.to_string(),
            ),
            AuthnScope::Tenant(t) => ("user_id IS NULL", None, t.to_string()),
            AuthnScope::System => return Err(BackendError::InvalidSystemMethod),
        };
        let sql = format!(
            "UPDATE auth_methods SET enabled = ?1 WHERE name = ?2 AND {user_clause} AND tenant_id = ?{}",
            if user_id.is_some() { 4 } else { 3 }
        );

        let mut q = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(if enabled { 1 } else { 0 })
            .bind(name);
        if let Some(uid) = &user_id {
            q = q.bind(uid);
        }
        q = q.bind(&tenant_id);
        let res = q.execute(self.pool()).await?;
        Ok(res.rows_affected() > 0)
    }
}

/// Decode a (`tenant_id`, `user_id`) storage row back into an
/// [`AuthnScope`]. `tenant_id` is always populated;
/// [`TenantId::SYSTEM`] maps to [`AuthnScope::System`].
fn decode_scope(tenant_id: &str, user_id: Option<&str>) -> Result<AuthnScope, BackendError> {
    let tenant = TenantId::try_new(tenant_id)
        .map_err(|e| BackendError::Backend(format!("bad tenant_id in factor_configs: {e}")))?;
    match user_id {
        Some(uid) => {
            let user = UserId::try_new(uid).map_err(|e| {
                BackendError::Backend(format!("bad user_id in factor_configs: {e}"))
            })?;
            Ok(AuthnScope::User {
                tenant_id: tenant,
                user_id: user,
            })
        }
        None if tenant.is_system() => Ok(AuthnScope::System),
        None => Ok(AuthnScope::Tenant(tenant)),
    }
}
