//! `FactorStore` trait impl + scoped factor-config lookup helper.

use axess::authn::{
    AuthMethod, AuthnScope, FactorConfig, FactorKind, FactorStep, FactorStore, TenantId, UserId,
};
use sqlx::{AssertSqlSafe, Row, SqlitePool};
use tracing::warn;
use uuid::Uuid;

use super::{BackendError, OurBackend};

impl FactorStore for OurBackend {
    type Error = BackendError;

    async fn load_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<FactorConfig>, Self::Error> {
        let kind_str = kind.as_str();

        // Resolution contract (see `docs/tenancy.md`):
        //   User  → user row, then tenant row, then None.
        //   Tenant → tenant row, then None.
        //   Global → None (platform-wide defaults are expressed via
        //            `FactorTemplate` catalog entries at provisioning time,
        //            not as a runtime fallback row).
        match scope {
            AuthnScope::User { tenant_id, user_id } => {
                let user_str = user_id.to_string();
                let tenant_str = tenant_id.to_string();
                if let Some(cfg) =
                    fetch_factor_config(self.pool(), kind_str, Some(&user_str), Some(&tenant_str))
                        .await?
                {
                    return Ok(Some(cfg));
                }
                fetch_factor_config(self.pool(), kind_str, None, Some(&tenant_str)).await
            }
            AuthnScope::Tenant(tenant_id) => {
                let tenant_str = tenant_id.to_string();
                fetch_factor_config(self.pool(), kind_str, None, Some(&tenant_str)).await
            }
            AuthnScope::Global => Ok(None),
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

        let (user_id, tenant_id): (Option<String>, Option<String>) = match scope {
            AuthnScope::User { user_id, tenant_id } => {
                (Some(user_id.to_string()), Some(tenant_id.to_string()))
            }
            AuthnScope::Tenant(tid) => (None, Some(tid.to_string())),
            AuthnScope::Global => (None, None),
        };

        // SQLite NULL doesn't compare equal in `column = ?`, so route
        // through `IS` for the NULL legs to keep the WHERE clause
        // tenant/global-scope correct.
        let (user_clause, tenant_clause) = match (user_id.as_deref(), tenant_id.as_deref()) {
            (Some(_), Some(_)) => ("user_id = ?3", "tenant_id = ?4"),
            (None, Some(_)) => ("user_id IS NULL", "tenant_id = ?3"),
            (None, None) => ("user_id IS NULL", "tenant_id IS NULL"),
            (Some(_), None) => ("user_id = ?3", "tenant_id IS NULL"),
        };
        let sql = format!(
            "UPDATE factor_configs
                SET config_json = ?1,
                    updated_at  = datetime('now')
              WHERE kind = ?2
                AND {user_clause}
                AND {tenant_clause}
                AND config_json = ?{}",
            match (user_id.as_deref(), tenant_id.as_deref()) {
                (Some(_), Some(_)) => 5,
                (None, Some(_)) | (Some(_), None) => 4,
                (None, None) => 3,
            }
        );

        let mut q = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(&updated_json)
            .bind(&kind_str);
        if let Some(uid) = &user_id {
            q = q.bind(uid);
        }
        if let Some(tid) = &tenant_id {
            q = q.bind(tid);
        }
        q = q.bind(&prior_json);

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
        let (user_id, tenant_id): (Option<String>, Option<String>) = match scope {
            AuthnScope::User { user_id, tenant_id } => {
                (Some(user_id.to_string()), Some(tenant_id.to_string()))
            }
            AuthnScope::Tenant(t) => (None, Some(t.to_string())),
            AuthnScope::Global => {
                // Runtime global auth methods are not supported in this
                // backend: methods must be materialised per tenant (see
                // `docs/tenancy.md`). Reject to surface the mistake.
                return Err(BackendError::InvalidGlobalMethod);
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
        // Bind scope → (clauses + ids) in one pass so the inner match
        // remains exhaustive (no impossible-tuple arm).
        let (user_clause, tenant_clause, user_id, tenant_id) = match scope {
            AuthnScope::User { user_id, tenant_id } => (
                "user_id = ?2",
                "tenant_id = ?3",
                Some(user_id.to_string()),
                tenant_id.to_string(),
            ),
            AuthnScope::Tenant(t) => ("user_id IS NULL", "tenant_id = ?2", None, t.to_string()),
            AuthnScope::Global => return Err(BackendError::InvalidGlobalMethod),
        };
        let sql = format!(
            "DELETE FROM auth_methods WHERE name = ?1 AND {user_clause} AND {tenant_clause}"
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
        let (user_clause, tenant_clause, user_id, tenant_id) = match scope {
            AuthnScope::User { user_id, tenant_id } => (
                "user_id = ?3",
                "tenant_id = ?4",
                Some(user_id.to_string()),
                tenant_id.to_string(),
            ),
            AuthnScope::Tenant(t) => ("user_id IS NULL", "tenant_id = ?3", None, t.to_string()),
            AuthnScope::Global => return Err(BackendError::InvalidGlobalMethod),
        };
        let sql = format!(
            "UPDATE auth_methods SET enabled = ?1 WHERE name = ?2 AND {user_clause} AND {tenant_clause}"
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

/// Fetch a single `FactorConfig` from `factor_configs` for the given exact scope.
///
/// Pass `None` for `user_id` / `tenant_id` to query for the global / tenant scope.
async fn fetch_factor_config(
    pool: &SqlitePool,
    kind: &str,
    user_id: Option<&str>,
    tenant_id: Option<&str>,
) -> Result<Option<FactorConfig>, BackendError> {
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

    let mut q = sqlx::query(AssertSqlSafe(sql.as_str())).bind(kind);
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
