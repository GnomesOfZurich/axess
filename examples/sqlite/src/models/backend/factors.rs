//! `FactorStore` trait impl.
//!
//! Storage encoding: `factor_configs.tenant_id` and `auth_methods.tenant_id`
//! are NOT NULL and reference `tenants(id)`. System-scope rows live under
//! [`TenantId::SYSTEM`]: there is no NULL-tenant encoding for
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

        sqlx::query(AssertSqlSafe(format!(
            "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, datetime('now'))
             ON CONFLICT {} DO UPDATE SET
                 config_json = excluded.config_json,
                 updated_at  = excluded.updated_at",
            factor_conflict_target(user_str.is_some())
        )))
        .bind(&id)
        .bind(&user_str)
        .bind(&tenant_str)
        .bind(&kind_str)
        .bind(&config_json)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    /// Two statements, and the second decides.
    ///
    /// The first reads the row: its id, its version and its configuration.
    /// The configuration is compared with `prior` as a value, read into a
    /// `FactorConfig` by this build, and not as text. A row written by an
    /// earlier release, or by hand, can lack a field that has a default
    /// since (an HOTP row without `attempt_count`, a recovery-code set
    /// without `under_previous_pepper`); its text differs from what `prior`
    /// serialises to although nothing was spent, and a comparison of text
    /// would answer "replay" for it on every login until the row is
    /// rewritten.
    ///
    /// The second is one `UPDATE` guarded by the id and the version just
    /// read, and its affected-row count is the answer. A trigger moves the
    /// version on every write of `config_json` (see the migration that adds
    /// the column), so a row that another request replaced between the two
    /// statements is not written, and that request's swap is the one that
    /// won. The id is in the guard because a deleted and re-created row
    /// starts at version 0 again under a new id.
    ///
    /// The guard also names `enabled`. `load_factor` and `resolve_factor`
    /// hand out enabled rows only, and disabling a row does not move its
    /// version, so without it a factor disabled between a caller's load and
    /// its swap would still be swapped. With it the swap answers `false` for
    /// a row the store would no longer load, and writes nothing.
    ///
    /// No transaction spans the two statements, so there is no read lock to
    /// upgrade and a request that loses the race is answered `false`, never
    /// "database is locked".
    async fn compare_and_save_factor(
        &self,
        scope: &AuthnScope,
        prior: &FactorConfig,
        updated: FactorConfig,
    ) -> Result<bool, Self::Error> {
        let cols = scope.as_columns();
        let tenant_str = cols.tenant_id.to_string();
        let user_str = cols.user_id.map(|u| u.to_string());

        // tenant_id is always populated; only user_id needs the NULL branch.
        let user_clause = if user_str.is_some() {
            "user_id = ?3"
        } else {
            "user_id IS NULL"
        };
        let select = format!(
            "SELECT id, version, config_json FROM factor_configs
              WHERE kind = ?1 AND tenant_id = ?2 AND {user_clause}
              LIMIT 1"
        );
        let mut q = sqlx::query(AssertSqlSafe(select.as_str()))
            .bind(prior.kind().as_str().to_string())
            .bind(&tenant_str);
        if let Some(uid) = &user_str {
            q = q.bind(uid);
        }
        let Some(row) = q.fetch_optional(self.pool()).await? else {
            // No row: nothing to swap, and nothing is created.
            return Ok(false);
        };
        let id: String = row.get("id");
        let version: i64 = row.get("version");
        let stored: FactorConfig = serde_json::from_str(&row.get::<String, _>("config_json"))?;
        if serde_json::to_value(&stored)? != serde_json::to_value(prior)? {
            return Ok(false);
        }

        let res = sqlx::query(
            "UPDATE factor_configs
                SET config_json = ?1,
                    updated_at  = datetime('now')
              WHERE id = ?2 AND version = ?3 AND enabled = 1",
        )
        .bind(serde_json::to_string(&updated)?)
        .bind(&id)
        .bind(version)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn insert_factor_if_absent(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> Result<bool, Self::Error> {
        let kind_str = config.kind().as_str().to_string();
        let config_json = serde_json::to_string(&config)?;
        let id = Uuid::new_v4().to_string();

        let cols = scope.as_columns();
        let tenant_str = cols.tenant_id.to_string();
        let user_str = cols.user_id.map(|u| u.to_string());

        // One statement, atomic: the unique index for the scope
        // decides the winner of two concurrent first writes.
        let res = sqlx::query(AssertSqlSafe(format!(
            "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, datetime('now'))
             ON CONFLICT {} DO NOTHING",
            factor_conflict_target(user_str.is_some())
        )))
        .bind(&id)
        .bind(&user_str)
        .bind(&tenant_str)
        .bind(&kind_str)
        .bind(&config_json)
        .execute(self.pool())
        .await?;

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
               AND tenant_id = ?2
               AND (user_id = ?1 OR user_id IS NULL)
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

            // Steps that cannot be read are an error: a method read as having
            // no steps would ask for nothing.
            let steps: Vec<FactorStep> = serde_json::from_str(&steps_json).map_err(|err| {
                warn!(method_id = %id, error = %err, "failed to parse steps_json");
                BackendError::Backend(format!(
                    "auth_methods.steps_json of {id} is not valid: {err}"
                ))
            })?;

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
        let target = if user_id.is_some() {
            "(user_id, tenant_id, name)"
        } else {
            "(tenant_id, name) WHERE user_id IS NULL"
        };
        sqlx::query(AssertSqlSafe(format!(
            "INSERT INTO auth_methods (id, name, steps_json, user_id, tenant_id, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)
             ON CONFLICT {target} DO UPDATE SET
                 steps_json = excluded.steps_json,
                 enabled    = 1"
        )))
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

    /// Claim the id in `fido2_credential_claims`, whose primary key is
    /// `(tenant_id, credential_id)`, with one statement: the row is inserted
    /// when the id is free, and on a conflict the row already there is
    /// returned. Of two registrations racing for one id exactly one inserts,
    /// and the other is told the holder by the statement that refused it, so
    /// no release or claim in between can change the answer. A passkey
    /// stored before the table existed holds its id too, which the look
    /// through the stored rows finds first.
    async fn claim_fido2_credential(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> Result<axess::authn::Fido2CredentialClaim, Self::Error> {
        use axess::authn::Fido2CredentialClaim;
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let encoded = URL_SAFE_NO_PAD.encode(credential_id);
        if let Some(holder) = self.stored_fido2_holder(tenant_id, &encoded).await?
            && &holder != user_id
        {
            return Ok(Fido2CredentialClaim::HeldBy(holder));
        }
        // The update on a conflict changes nothing: it is what makes the
        // statement return the row that was already there.
        let holder: String = sqlx::query_scalar(
            "INSERT INTO fido2_credential_claims (tenant_id, credential_id, user_id)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (tenant_id, credential_id) DO UPDATE SET user_id = user_id
             RETURNING user_id",
        )
        .bind(tenant_id.to_string())
        .bind(&encoded)
        .bind(user_id.to_string())
        .fetch_one(self.pool())
        .await?;
        if holder == user_id.to_string() {
            return Ok(Fido2CredentialClaim::Claimed);
        }
        UserId::try_new(&holder)
            .map(Fido2CredentialClaim::HeldBy)
            .map_err(|e| {
                BackendError::Backend(format!("bad user_id in fido2_credential_claims: {e}"))
            })
    }

    /// Delete the user's own claim on the id; another user's claim stays.
    async fn release_fido2_credential(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> Result<(), Self::Error> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        sqlx::query(
            "DELETE FROM fido2_credential_claims
              WHERE tenant_id = ?1 AND credential_id = ?2 AND user_id = ?3",
        )
        .bind(tenant_id.to_string())
        .bind(URL_SAFE_NO_PAD.encode(credential_id))
        .bind(user_id.to_string())
        .execute(self.pool())
        .await?;
        Ok(())
    }
}

/// Whether any `cred_id` member anywhere in `value` equals `encoded`.
fn holds_credential_id(value: &serde_json::Value, encoded: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, inner)| {
            (key == "cred_id" && inner.as_str() == Some(encoded))
                || holds_credential_id(inner, encoded)
        }),
        serde_json::Value::Array(items) => items.iter().any(|v| holds_credential_id(v, encoded)),
        _ => false,
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

impl OurBackend {
    /// The user of the tenant whose stored passkey carries the base64url id
    /// `encoded`. The passkey ids live inside `factor_configs.config_json`,
    /// so the look narrows the tenant's `fido2` rows with a substring match
    /// on the id and confirms each candidate by parsing it.
    async fn stored_fido2_holder(
        &self,
        tenant_id: &TenantId,
        encoded: &str,
    ) -> Result<Option<UserId>, BackendError> {
        let rows = sqlx::query(
            "SELECT user_id, config_json FROM factor_configs
              WHERE kind = 'fido2' AND tenant_id = ?1 AND user_id IS NOT NULL
                AND instr(config_json, ?2) > 0",
        )
        .bind(tenant_id.to_string())
        .bind(encoded)
        .fetch_all(self.pool())
        .await?;
        for row in rows {
            let json: String = row.get("config_json");
            let value: serde_json::Value = serde_json::from_str(&json)?;
            if holds_credential_id(&value, encoded) {
                let user: String = row.get("user_id");
                return UserId::try_new(&user).map(Some).map_err(|e| {
                    BackendError::Backend(format!("bad user_id in factor_configs: {e}"))
                });
            }
        }
        Ok(None)
    }

    /// Stores a first TOTP factor, the recovery codes and the upgraded
    /// `password+totp` method for a user as one transaction.
    ///
    /// Returns `Ok(false)` when a TOTP factor is already stored (nothing is
    /// written). Any other failure, including a method upgrade that does not
    /// change exactly one row, rolls everything back and is an error, so a
    /// stored second factor is never paired with a method that does not ask
    /// for it.
    pub async fn enrol_totp(
        &self,
        scope: &AuthnScope,
        totp: FactorConfig,
        recovery_codes: FactorConfig,
        steps: &[FactorStep],
    ) -> Result<bool, BackendError> {
        let cols = scope.as_columns();
        let tenant_str = cols.tenant_id.to_string();
        let user_str = cols
            .user_id
            .map(|u| u.to_string())
            .ok_or_else(|| BackendError::Backend("enrolment needs a user scope".into()))?;
        let steps_json = serde_json::to_string(steps)?;

        let mut tx = self.pool().begin().await?;
        for (config, first_write) in [(&totp, true), (&recovery_codes, false)] {
            let conflict = if first_write {
                "DO NOTHING"
            } else {
                "DO UPDATE SET config_json = excluded.config_json,
                               updated_at = excluded.updated_at"
            };
            let res = sqlx::query(AssertSqlSafe(format!(
                "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, datetime('now'))
                 ON CONFLICT {} {conflict}",
                factor_conflict_target(true)
            )))
            .bind(Uuid::new_v4().to_string())
            .bind(&user_str)
            .bind(&tenant_str)
            .bind(config.kind().as_str())
            .bind(serde_json::to_string(config)?)
            .execute(&mut *tx)
            .await?;
            if first_write && res.rows_affected() == 0 {
                return Ok(false);
            }
        }
        let upgraded = sqlx::query(
            "UPDATE auth_methods SET name = 'password+totp', steps_json = ?3
             WHERE user_id = ?1 AND tenant_id = ?2",
        )
        .bind(&user_str)
        .bind(&tenant_str)
        .bind(steps_json)
        .execute(&mut *tx)
        .await?;
        if upgraded.rows_affected() != 1 {
            return Err(BackendError::Backend(format!(
                "the method upgrade changed {} rows, expected 1",
                upgraded.rows_affected()
            )));
        }
        tx.commit().await?;
        Ok(true)
    }
}

/// The `ON CONFLICT` target that names the unique index covering `scope`.
/// Tenant and system rows store `user_id` NULL, which the table-level
/// `UNIQUE(user_id, tenant_id, kind)` never matches (SQLite treats NULLs as
/// distinct), so they conflict on a partial index instead.
fn factor_conflict_target(has_user: bool) -> &'static str {
    if has_user {
        "(user_id, tenant_id, kind)"
    } else {
        "(tenant_id, kind) WHERE user_id IS NULL"
    }
}
