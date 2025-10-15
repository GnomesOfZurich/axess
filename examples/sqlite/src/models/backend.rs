use async_trait::async_trait;
use chrono::Utc;
// use chrono::{DateTime, Utc};
use password_auth::verify_password;
// use serde::{Deserialize, Serialize};
use serde_json;
use sqlx::{FromRow, Row, SqlitePool};
// use std::str::FromStr;
// use tracing_subscriber::filter;
// use tokio::task;
use uuid::Uuid;

// Import verify_totp from your utils or totp module
use axess::{
    authn::methods::{factor::FactorStateChange, method::MethodStateChange},
    verify_totp,
};

use crate::models::{
    authn::{OurAuthFactor, OurAuthFactorState, OurAuthMethod, OurAuthMethodState},
    entities::{OurTenant, OurUser},
};
use axess::{
    AuthEventRecord, AuthEventStatus, AuthEventType, AuthFactor, AuthFactorKind, AuthFactorState,
    AuthMethod, AuthMethodState, AuthnAdminBackend, AuthnBackend, EnablementState, EntityState,
    FactorForm, PermissionScope,
};

const DEFAULT_TENANT_NAME: &str = "Default Tenant";
const SYSTEM_SUPER_USER_NAME: &str = "system";
const TENANT_SUPER_USER_NAME: &str = "tenant";

pub type DataId = String;

/// Trait for extracting password from a factor form.
pub trait PasswordProvider {
    fn password(&self) -> &str;
}

/// Trait for extracting username from a factor form.
pub trait UsernameProvider {
    fn username(&self) -> &str;
}

/// Example backend implementation.
#[derive(Debug, Clone)]
pub struct OurBackend {
    pub db: SqlitePool,
}

impl OurBackend {
    pub fn new(db: SqlitePool) -> Self {
        Self { db }
    }
}

impl PartialEq for OurBackend {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

// Implement the AuthnBackend trait for OurBackend to define the associated types.
#[async_trait]
impl AuthnBackend for OurBackend {
    type User = OurUser;
    type UserId = Uuid;
    type Tenant = OurTenant;
    type TenantId = Uuid;
    type Error = sqlx::Error;
    type MethodId = Uuid;
    type FactorId = Uuid;
    type DataId = DataId;

    async fn get_default_protected_route(
        &self,
        _tid: Self::TenantId,
        _uid: Self::UserId,
    ) -> Result<String, Self::Error> {
        Ok("/main".to_string())
    }

    /// Gets the tenant by provided ID from the backend.
    async fn get_tenant(&self, tenant_id: &Self::TenantId) -> Result<Self::Tenant, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query("SELECT id, name, description FROM tenants WHERE id = ?")
            .bind(tenant_id.to_string())
            .fetch_one(&mut *conn)
            .await?;
        let tenant = OurTenant::from_row(&row)?;
        Ok(tenant)
    }

    /// Gets the tenant by provided name from the backend.
    async fn get_tenant_by_name(&self, name: &str) -> Result<Self::Tenant, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query("SELECT id, name, description FROM tenants WHERE name = ?")
            .bind(name)
            .fetch_one(&mut *conn)
            .await?;

        OurTenant::from_row(&row).map_err(|e| sqlx::Error::ColumnDecode {
            index: "tenant".into(),
            source: Box::new(e),
        })
    }

    async fn get_default_tenant_id(&self) -> Result<Self::TenantId, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query("SELECT tenant_id FROM tenants WHERE name = ?")
            .bind(DEFAULT_TENANT_NAME)
            .fetch_one(&mut *conn)
            .await?;

        Uuid::parse_str(row.try_get::<String, _>("tenant_id")?.as_str()).map_err(|e| {
            sqlx::Error::ColumnDecode {
                index: "tenant_id".into(),
                source: Box::new(e),
            }
        })
    }

    /// Gets the user by provided ID from the backend.
    async fn get_user(&self, user_id: &Self::UserId) -> Result<Self::User, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query("SELECT * FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .fetch_one(&mut *conn)
            .await?;

        OurUser::from_row(&row)
    }

    /// Gets the user by provided username from the backend.
    async fn get_user_by_name(
        &self,
        tenant_id: &Self::TenantId,
        username: &str,
    ) -> Result<Self::User, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query("SELECT * FROM users WHERE tenant_id = ? AND username = ?")
            .bind(tenant_id.to_string())
            .bind(username)
            .fetch_one(&mut *conn)
            .await?;

        OurUser::from_row(&row).map_err(|e| sqlx::Error::ColumnDecode {
            index: "user".into(),
            source: Box::new(e),
        })
    }

    /// Gets the super user for the given tenant, or the super user for the global system if none is provided.
    async fn get_system_user_id(
        &self,
        tenant_id: Option<&Self::TenantId>,
    ) -> Result<Self::UserId, Self::Error> {
        let (tenant_id, username) = match tenant_id {
            Some(tid) => (*tid, TENANT_SUPER_USER_NAME.to_string()),
            None => {
                let tid = self.get_default_tenant_id().await?;
                (tid, SYSTEM_SUPER_USER_NAME.to_string())
            }
        };

        let super_user = self.get_user_by_name(&tenant_id, &username).await?;
        Ok(super_user.id)
    }

    /// Gets the super user for the given tenant, or the super user for the global system if none is provided.
    async fn set_user_state(
        &self,
        user_id: &Self::UserId,
        new_state: EntityState,
    ) -> Result<Self::User, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query(
            "UPDATE users SET user_state = ? WHERE id = ? RETURNING id, username, password, tenant_id, user_state, factors, methods"
        )
            .bind(format!("{new_state:?}"))
            .bind(user_id.to_string())
            .fetch_one(&mut *conn)
            .await?;

        let user = OurUser::from_row(&row)?;
        Ok(user)
    }

    /// Create a new guest user in the backend.
    /// If `tenant_id` is `None`, a new tenant ID will be generated for the user.
    /// The `creator_id` is set to `Uuid::nil()` by default.
    async fn get_new_guest_user(
        &self,
        tenant_id: Option<&Self::TenantId>,
    ) -> Result<Self::User, Self::Error> {
        let default_tenant_id = Uuid::new_v4();

        let tenant_id = tenant_id.unwrap_or(&default_tenant_id);
        // Use Uuid::nil() as the creator_id for guest users by default
        Ok(OurUser::new_guest_user(*tenant_id, Uuid::nil()))
    }

    /// Get the authentication method by its ID.
    async fn get_auth_method(
        &self,
        method_id: &<OurBackend as AuthnBackend>::MethodId,
    ) -> Result<AuthMethod<OurBackend>, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query("SELECT * FROM methods WHERE id = ?")
            .bind(method_id.to_string())
            .fetch_one(&mut *conn)
            .await?;

        let method = OurAuthMethod::from_row(&row)?;
        let method = AuthMethod::<OurBackend>::from(method);
        Ok(method)
    }

    /// Get all authentication methods for a given scope (global/user/tenant), disregarding activation state.
    async fn get_all_auth_methods(&self) -> Result<Vec<AuthMethod<Self>>, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let rows: Vec<OurAuthMethod> = sqlx::query_as(
            r#"
            SELECT * FROM auth_methods
            "#,
        )
        .fetch_all(&mut *conn)
        .await?;

        let methods: Vec<AuthMethod<OurBackend>> = rows
            .into_iter()
            .map(|row: OurAuthMethod| AuthMethod::<OurBackend>::from(row))
            .collect();

        Ok(methods)
    }

    /// Get all active Authentication methods for a given scope (global/user/tenant) and filtered by the enablement state.
    async fn get_scoped_auth_methods(
        &self,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
        state: EnablementState,
    ) -> Result<Vec<AuthMethod<Self>>, Self::Error> {
        let state_str = format!("{:?}", state);

        let (query, binds): (&str, Vec<Option<String>>) = match scope {
            PermissionScope::Global => (
                r#"
                SELECT m.*
                FROM auth_methods m
                WHERE EXISTS (
                    SELECT * FROM method_states s
                    WHERE s.method_id = m.id
                    AND s.tenant_id IS NULL
                    AND s.user_id IS NULL
                    AND s.state = ?1
                )
                "#,
                vec![Some(state_str.clone())],
            ),
            PermissionScope::Any => (
                r#"
                SELECT m.*
                FROM auth_methods m
                WHERE EXISTS (
                    SELECT * FROM method_states s
                    WHERE s.method_id = m.id
                    AND s.state = ?1
                )
                "#,
                vec![Some(state_str.clone())],
            ),
            PermissionScope::Tenant(tid) => (
                r#"
                SELECT m.*
                FROM auth_methods m
                WHERE EXISTS (
                    SELECT * FROM method_states s
                    WHERE s.method_id = m.id
                    AND s.tenant_id = ?1
                    AND s.user_id IS NULL
                    AND s.state = ?2
                )
                "#,
                vec![Some(tid.to_string()), Some(state_str.clone())],
            ),
            PermissionScope::User(tid, uid) => (
                r#"
                SELECT m.*
                FROM auth_methods m
                WHERE EXISTS (
                    SELECT * FROM method_states s
                    WHERE s.method_id = m.id
                    AND s.tenant_id = ?1
                    AND s.user_id = ?2
                    AND s.state = ?3
                )
                "#,
                vec![
                    Some(tid.to_string()),
                    Some(uid.to_string()),
                    Some(state_str.clone()),
                ],
            ),
        };

        let mut sql = sqlx::query_as::<_, OurAuthMethod>(query);
        for bind in binds {
            match bind {
                Some(val) => sql = sql.bind(val),
                None => sql = sql.bind(None::<String>),
            }
        }

        let mut conn = self.db.acquire().await?;
        let rows: Vec<OurAuthMethod> = sql.fetch_all(&mut *conn).await?;
        let methods: Vec<AuthMethod<OurBackend>> = rows
            .into_iter()
            .map(AuthMethod::<OurBackend>::from)
            .collect();

        Ok(methods)
    }

    /// Get all states of an authentication method for a given scope (global/user/tenant).
    async fn get_method_states(
        &self,
        method_id: &Self::MethodId,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthMethodState<Self>>, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let (query, binds): (&str, Vec<Option<String>>) = match scope {
            PermissionScope::Global => (
                r#"
                SELECT * FROM method_states
                WHERE method_id = ?1
                AND tenant_id IS NULL
                AND user_id IS NULL
                "#,
                vec![Some(method_id.to_string())],
            ),
            PermissionScope::Any => (
                r#"
                SELECT * FROM method_states
                WHERE method_id = ?1
                "#,
                vec![Some(method_id.to_string())],
            ),
            PermissionScope::Tenant(tid) => (
                r#"
                SELECT * FROM method_states
                WHERE method_id = ?1
                AND tenant_id = ?2
                AND user_id IS NULL
                "#,
                vec![Some(method_id.to_string()), Some(tid.to_string())],
            ),
            PermissionScope::User(tid, uid) => (
                r#"
                SELECT * FROM method_states
                WHERE method_id = ?1
                AND tenant_id = ?2
                AND user_id = ?3
                "#,
                vec![
                    Some(method_id.to_string()),
                    Some(tid.to_string()),
                    Some(uid.to_string()),
                ],
            ),
        };

        let mut sql = sqlx::query_as::<_, OurAuthMethodState>(query);
        for bind in binds {
            match bind {
                Some(val) => sql = sql.bind(val),
                None => sql = sql.bind(None::<String>),
            }
        }

        let rows: Vec<OurAuthMethodState> = sql.fetch_all(&mut *conn).await?;
        let states: Vec<AuthMethodState<OurBackend>> = rows
            .into_iter()
            .map(AuthMethodState::<OurBackend>::from)
            .collect();

        Ok(states)
    }

    /// Upsert (insert or update) the state of an authentication method.
    ///
    /// The backend determines if this is an insert or update based on the
    /// composite key (method_id, tenant_id, user_id).
    ///
    /// For inserts: Generates new UUID for `id`, uses `created_at`, `created_by`, `updated_at`, and `updated_by` from input.
    /// For updates: Preserves existing `id`, `created_at`, and `created_by` from database, uses `updated_at` and `updated_by` from input.
    async fn upsert_method_state(
        &self,
        change: MethodStateChange<Self::MethodId, Self::TenantId, Self::UserId>,
    ) -> Result<AuthMethodState<Self>, Self::Error> {
        let tenant_id = change.tenant_id.map(|t| t.to_string());
        let user_id = change.user_id.map(|u| u.to_string());
        let now = Utc::now();

        let mut conn = self.db.acquire().await?;
        let row = sqlx::query(
            r#"
            INSERT INTO method_states (id, method_id, tenant_id, user_id, state, created_at, created_by, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(method_id, tenant_id, user_id) DO UPDATE SET 
                state = excluded.state,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            RETURNING id, method_id, tenant_id, user_id, state, created_at, created_by, updated_at, updated_by
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(change.method_id.to_string())
        .bind(tenant_id)
        .bind(user_id)
        .bind(format!("{:?}", change.state))
        .bind(now.to_rfc3339())
        .bind(change.updated_by.to_string())
        .bind(now.to_rfc3339())
        .bind(change.updated_by.to_string())
        .fetch_one(&mut *conn)
        .await?;

        let our_method_state =
            OurAuthMethodState::from_row(&row).map_err(|e| sqlx::Error::ColumnDecode {
                index: "method_state".into(),
                source: Box::new(e),
            })?;
        Ok(AuthMethodState::<OurBackend>::from(our_method_state))
    }

    // Get the authentication factor by its ID.
    async fn get_auth_factor(
        &self,
        factor_id: &Self::FactorId,
    ) -> Result<AuthFactor<Self>, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query("SELECT * FROM auth_factors WHERE id = ?")
            .bind(factor_id.to_string())
            .fetch_one(&mut *conn)
            .await?;

        let factor = OurAuthFactor::from_row(&row)?;
        Ok(AuthFactor::<OurBackend>::from(factor))
    }

    /// Get all authentication factors for a given scope (global/user/tenant), disregarding activation state.
    async fn get_all_auth_factors(&self) -> Result<Vec<AuthFactor<Self>>, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let rows: Vec<OurAuthFactor> = sqlx::query_as(
            r#"
            SELECT * FROM auth_factors
            "#,
        )
        .fetch_all(&mut *conn)
        .await?;

        let factors: Vec<AuthFactor<OurBackend>> = rows
            .into_iter()
            .map(|row: OurAuthFactor| AuthFactor::<OurBackend>::from(row))
            .collect();

        Ok(factors)
    }

    /// Get all authentication factors for a given scope (global/user/tenant).
    async fn get_scoped_auth_factors(
        &self,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
        state: EnablementState,
    ) -> Result<Vec<AuthFactor<Self>>, Self::Error> {
        let state_str = format!("{state:?}");

        let (query, binds): (&str, Vec<Option<String>>) = match scope {
            PermissionScope::Global => (
                r#"
            SELECT f.*
            FROM auth_factors f
            WHERE EXISTS (
                SELECT * FROM factor_states s
                WHERE s.factor_id = f.id
                AND s.tenant_id IS NULL
                AND s.user_id IS NULL
                AND s.state = ?1
            )
            "#,
                vec![Some(state_str.clone())],
            ),
            PermissionScope::Any => (
                r#"
            SELECT f.*
            FROM auth_factors f
            WHERE EXISTS (
                SELECT * FROM factor_states s
                WHERE s.factor_id = f.id
                AND s.state = ?1
            )
            "#,
                vec![Some(state_str.clone())],
            ),
            PermissionScope::Tenant(tid) => (
                r#"
            SELECT f.*
            FROM auth_factors f
            WHERE EXISTS (
                SELECT * FROM factor_states s
                WHERE s.factor_id = f.id
                AND s.tenant_id = ?1
                AND s.user_id IS NULL
                AND s.state = ?2
            )
            "#,
                vec![Some(tid.to_string()), Some(state_str)],
            ),
            PermissionScope::User(tid, uid) => (
                r#"
            SELECT f.*
            FROM auth_factors f
            WHERE EXISTS (
                SELECT * FROM factor_states s
                WHERE s.factor_id = f.id
                AND s.tenant_id = ?1
                AND s.user_id = ?2
                AND s.state = ?3
            )
            "#,
                vec![
                    Some(tid.to_string()),
                    Some(uid.to_string()),
                    Some(state_str),
                ],
            ),
        };

        let mut sql = sqlx::query_as::<_, OurAuthFactor>(query);
        for bind in binds {
            match bind {
                Some(val) => sql = sql.bind(val),
                None => sql = sql.bind(None::<String>),
            }
        }

        let mut conn = self.db.acquire().await?;
        let rows: Vec<OurAuthFactor> = sql.fetch_all(&mut *conn).await?;
        let factors: Vec<AuthFactor<OurBackend>> = rows
            .into_iter()
            .map(AuthFactor::<OurBackend>::from)
            .collect();

        Ok(factors)
    }

    /// Get all states of an authentication factor for a given scope (global/user/tenant).
    async fn get_factor_states(
        &self,
        factor_id: &Self::FactorId,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthFactorState<Self>>, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let (query, binds): (&str, Vec<Option<String>>) = match scope {
            PermissionScope::Global => (
                r#"
                SELECT * FROM factor_states
                WHERE factor_id = ?1
                AND tenant_id IS NULL
                AND user_id IS NULL
                "#,
                vec![Some(factor_id.to_string())],
            ),
            PermissionScope::Any => (
                r#"
                SELECT * FROM factor_states
                WHERE factor_id = ?1
                "#,
                vec![Some(factor_id.to_string())],
            ),
            PermissionScope::Tenant(tid) => (
                r#"
                SELECT * FROM factor_states
                WHERE factor_id = ?1
                AND tenant_id = ?2
                AND user_id IS NULL
                "#,
                vec![Some(factor_id.to_string()), Some(tid.to_string())],
            ),
            PermissionScope::User(tid, uid) => (
                r#"
                SELECT * FROM factor_states
                WHERE factor_id = ?1
                AND tenant_id = ?2
                AND user_id = ?3
                "#,
                vec![
                    Some(factor_id.to_string()),
                    Some(tid.to_string()),
                    Some(uid.to_string()),
                ],
            ),
        };

        let mut sql = sqlx::query_as::<_, OurAuthFactorState>(query);
        for bind in binds {
            match bind {
                Some(val) => sql = sql.bind(val),
                None => sql = sql.bind(None::<String>),
            }
        }

        let rows: Vec<OurAuthFactorState> = sql.fetch_all(&mut *conn).await?;
        let factor_states: Vec<AuthFactorState<OurBackend>> = rows
            .into_iter()
            .map(AuthFactorState::<OurBackend>::from)
            .collect();

        Ok(factor_states)
    }

    /// Upsert (insert or update) the state of an authentication factor.
    ///
    /// The backend determines if this is an insert or update based on the
    /// composite key (factor_id, tenant_id, user_id).
    ///
    /// For inserts: Generates new UUID for `id`, preserves `created_at` and `created_by` from input.
    /// For updates: Preserves existing `id`, `created_at`, and `created_by` from database.
    /// In both cases: Uses `updated_at` and `updated_by` from input.
    async fn upsert_factor_state(
        &self,
        change: FactorStateChange<Self::FactorId, Self::TenantId, Self::UserId>,
    ) -> Result<AuthFactorState<Self>, Self::Error> {
        let mut conn = self.db.acquire().await?;

        // Serialize config
        let config_json =
            serde_json::to_string(&change.config).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;

        let now = Utc::now();

        // Upsert using natural key - database handles ID generation
        let row = sqlx::query(
            r#"
            INSERT INTO factor_states (
                id, factor_id, tenant_id, user_id, state, config,
                created_at, created_by, updated_at, updated_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(factor_id, tenant_id, user_id) DO UPDATE SET
                state = excluded.state,
                config = excluded.config,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            RETURNING *
            "#,
        )
        .bind(Uuid::new_v4().to_string()) // Generate new ID (unused if updating)
        .bind(change.factor_id.to_string())
        .bind(change.tenant_id.map(|t| t.to_string()))
        .bind(change.user_id.map(|u| u.to_string()))
        .bind(format!("{:?}", change.state))
        .bind(&config_json)
        .bind(now.to_rfc3339())
        .bind(change.updated_by.to_string())
        .bind(now.to_rfc3339())
        .bind(change.updated_by.to_string())
        .fetch_one(&mut *conn)
        .await?;

        let factor_state = OurAuthFactorState::from_row(&row)
            .map(AuthFactorState::<OurBackend>::from)
            .map_err(|e| sqlx::Error::ColumnDecode {
                index: "factor_state".into(),
                source: Box::new(e),
            })?;
        Ok(factor_state)
    }

    async fn get_auth_history(
        &self,
        user_id: &Self::UserId,
        event_type: Option<AuthEventType>,
        event_status: Option<AuthEventStatus>,
        limit: Option<usize>,
    ) -> Result<Vec<axess::AuthEvent<Self>>, Self::Error> {
        let mut conn = self.db.acquire().await?;

        let mut query = String::from("SELECT * FROM auth_events WHERE user_id = ?");
        let mut binds: Vec<String> = vec![user_id.to_string()];

        if let Some(event_type) = event_type {
            query.push_str(" AND event_type = ?");
            binds.push(format!("{:?}", event_type));
        }

        if let Some(event_status) = event_status {
            query.push_str(" AND event_status = ?");
            binds.push(format!("{:?}", event_status));
        }

        query.push_str(" ORDER BY event_time DESC");

        if let Some(limit) = limit {
            query.push_str(" LIMIT ?");
            binds.push(limit.to_string());
        }

        let mut sql = sqlx::query(&query);
        for bind in binds {
            sql = sql.bind(bind);
        }

        let rows = sql.fetch_all(&mut *conn).await?;
        let events: Vec<axess::AuthEvent<OurBackend>> = rows
            .into_iter()
            .map(|row| {
                // Map the row fields to AuthEvent struct
                // You'll need to adjust these field names based on your actual schema
                axess::AuthEvent {
                    id: row.try_get::<String, _>("id").unwrap_or_default(),
                    user_id: Uuid::parse_str(
                        row.try_get::<String, _>("user_id").as_deref().unwrap_or(""),
                    )
                    .unwrap_or(Uuid::nil()),
                    tenant_id: Uuid::parse_str(
                        row.try_get::<String, _>("tenant_id")
                            .as_deref()
                            .unwrap_or(""),
                    )
                    .unwrap_or(Uuid::nil()),
                    session_id: row
                        .try_get::<Option<String>, _>("session_id")
                        .ok()
                        .flatten(),
                    event_type: row
                        .try_get::<String, _>("event_type")
                        .ok()
                        .and_then(|et| serde_json::from_str(&format!("\"{}\"", et)).ok())
                        .unwrap_or(AuthEventType::Authenticated),
                    event_status: row
                        .try_get::<String, _>("event_status")
                        .ok()
                        .and_then(|es| serde_json::from_str(&format!("\"{}\"", es)).ok())
                        .unwrap_or(AuthEventStatus::Success),
                    event_time: row
                        .try_get::<String, _>("event_time")
                        .ok()
                        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(&ts).ok())
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or(Utc::now()),
                    method_id: row
                        .try_get::<Option<String>, _>("method_id")
                        .ok()
                        .flatten()
                        .and_then(|mid| Uuid::parse_str(&mid).ok()),
                    factor_id: row
                        .try_get::<Option<String>, _>("factor_id")
                        .ok()
                        .flatten()
                        .and_then(|fid| Uuid::parse_str(&fid).ok()),
                    factor_kind: row
                        .try_get::<Option<String>, _>("factor_kind")
                        .ok()
                        .flatten()
                        .and_then(|fk| serde_json::from_str(&format!("\"{}\"", fk)).ok()),
                    ip_address: row
                        .try_get::<Option<String>, _>("ip_address")
                        .ok()
                        .flatten(),
                    user_agent: row
                        .try_get::<Option<String>, _>("user_agent")
                        .ok()
                        .flatten(),
                    error_message: row
                        .try_get::<Option<String>, _>("error_message")
                        .ok()
                        .flatten(),
                }
            })
            .collect();
        Ok(events)
    }

    async fn get_last_login(
        &self,
        user_id: &Self::UserId,
    ) -> Result<Option<chrono::DateTime<Utc>>, Self::Error> {
        // Reuse get_auth_history to keep filtering/sorting logic in one place.
        let events = self
            .get_auth_history(
                user_id,
                Some(AuthEventType::LoginAttempt),
                Some(AuthEventStatus::Success),
                Some(1),
            )
            .await?;
        Ok(events.into_iter().next().map(|e| e.event_time))
    }

    async fn record_auth_event(&self, event: AuthEventRecord<'_, Self>) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        let now = Utc::now();

        sqlx::query(
            r#"
                INSERT INTO auth_events (
                    id, user_id, tenant_id, session_id, event_type, event_status,
                    event_time, method_id, factor_id, factor_kind, ip_address,
                    user_agent, error_message
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(event.user_id.to_string())
        .bind(event.tenant_id.to_string())
        .bind(event.session_id)
        .bind(format!("{:?}", event.event_type))
        .bind(format!("{:?}", event.event_status))
        .bind(now.to_rfc3339())
        .bind(event.method_id.map(|m| m.to_string()))
        .bind(event.factor_id.map(|f| f.to_string()))
        .bind(event.factor_kind.map(|fk| format!("{:?}", fk)))
        .bind(event.ip_address)
        .bind(event.user_agent)
        .bind(event.error_message)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Authenticates a user using the provided credentials form.
    async fn authenticate<'a, F>(&self, creds: &'a F) -> Result<Self::User, Self::Error>
    where
        F: FactorForm + Send + Sync,
    {
        let fields = creds.fields_map();
        let factor_kind = creds.factor_kind();

        // 1. Resolve tenant and username from form fields
        let tenant_id = fields
            .get("tenant")
            .and_then(|tid| Uuid::parse_str(tid).ok())
            .unwrap_or(Uuid::nil());
        let username = fields.get("username").map(|s| s.as_str()).unwrap_or("");

        // 2. Lookup user by tenant and username
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query("SELECT * FROM users WHERE tenant_id = ? AND username = ?")
            .bind(tenant_id.to_string())
            .bind(username)
            .fetch_one(&mut *conn)
            .await?;

        let user = OurUser::from_row(&row)?;

        // 3. Check user state
        if user.state != EntityState::Active {
            // TODO: improve error handling in the example app backend !!!
            return Err(sqlx::Error::RowNotFound);
        }

        // 4. Lookup factors for this user using the backend's scoped factor lookup
        let scope = PermissionScope::User(tenant_id, user.id);
        let factors = self
            .get_scoped_auth_factors(scope, EnablementState::Active)
            .await?;

        // 5. Find the factor matching the submitted kind
        let factor = factors
            .iter()
            .find(|f| f.kind == factor_kind)
            .ok_or_else(|| sqlx::Error::ColumnDecode {
                index: "factors".into(),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Missing active factor for kind: {factor_kind}"),
                )),
            })?;

        // 6. Lookup factor state for this factor
        let factor_state_row = sqlx::query("SELECT * FROM factor_states WHERE factor_id = ? AND tenant_id = ? AND user_id = ? AND state = ?")
            .bind(factor.id.to_string())
            .bind(tenant_id.to_string())
            .bind(user.id.to_string())
            .bind("Active")
            .fetch_one(&mut *conn)
            .await?;

        let factor_state = OurAuthFactorState::from_row(&factor_state_row)?;

        // 7. Verify credentials according to factor kind
        match factor_kind {
            AuthFactorKind::Password => {
                let password_hash = factor_state
                    .0
                    .config
                    .get("password_hash")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| sqlx::Error::ColumnDecode {
                        index: "factor_state".into(),
                        source: Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Missing password hash in factor state",
                        )),
                    })?;
                let password = fields.get("password").map(|s| s.as_str()).unwrap_or("");
                verify_password(password, password_hash)
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                Ok(user)
            }
            AuthFactorKind::Totp => {
                let totp_secret = factor_state
                    .0
                    .config
                    .get("totp_secret")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| sqlx::Error::ColumnDecode {
                        index: "factor_state".into(),
                        source: Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Missing TOTP secret in factor state",
                        )),
                    })?;
                let totp_code = fields.get("totp_code").map(|s| s.as_str()).unwrap_or("");
                if !verify_totp(totp_secret, totp_code) {
                    return Err(sqlx::Error::Protocol("Invalid TOTP code".to_string()));
                }
                Ok(user)
            }
            AuthFactorKind::Oauth => {
                // Handle OAuth factor authentication
                // This is a placeholder, actual implementation will depend on your OAuth setup
                Err(sqlx::Error::Protocol(
                    "OAuth factor authentication not implemented".to_string(),
                ))
            }
        }
    }
}

#[async_trait]
impl AuthnAdminBackend for OurBackend {
    /// Upserts (inserts or updates) a user in the database.
    ///
    /// If the user already exists (matched by `id`), updates all fields.
    /// Otherwise, inserts a new user record.
    ///
    /// Returns the upserted user as loaded from the database.
    async fn upsert_user(&self, user: Self::User) -> Result<Self::User, Self::Error> {
        let mut conn = self.db.acquire().await?;

        // Upsert user record using only the fields present in OurUser
        let row = sqlx::query(
            r#"
            INSERT INTO users (
            id,
            username,
            tenant_id,
            user_state,
            created_at,
            created_by,
            updated_at,
            updated_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
            username = excluded.username,
            tenant_id = excluded.tenant_id,
            user_state = excluded.user_state,
            created_at = excluded.created_at,
            created_by = excluded.created_by,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by
            RETURNING
            id,
            username,
            tenant_id,
            user_state,
            created_at,
            created_by,
            updated_at,
            updated_by
            "#,
        )
        .bind(user.id.to_string())
        .bind(&user.username)
        .bind(user.tenant_id.to_string())
        .bind(format!("{:?}", user.state))
        .bind(user.created_at.to_rfc3339())
        .bind(user.created_by.to_string())
        .bind(user.updated_at.to_rfc3339())
        .bind(user.updated_by.to_string())
        .fetch_one(&mut *conn)
        .await?;

        OurUser::from_row(&row)
    }

    async fn delete_user(&self, user_id: &Self::UserId) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    /// Upserts (inserts or updates) a tenant in the database.
    ///
    /// If the tenant already exists (matched by `id`), updates all fields.
    /// Otherwise, inserts a new tenant record.
    ///
    /// Returns the upserted tenant as loaded from the database.
    async fn upsert_tenant(&self, tenant: Self::Tenant) -> Result<Self::Tenant, Self::Error> {
        let mut conn = self.db.acquire().await?;

        let row = sqlx::query(
            r#"
            INSERT INTO tenants (id, name, description, state, created_at, created_by, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                state = excluded.state,
                created_at = excluded.created_at,
                created_by = excluded.created_by,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            RETURNING id, name, description, state, created_at, created_by, updated_at, updated_by
            "#
        )
        .bind(tenant.id.to_string())
        .bind(&tenant.name)
        .bind(&tenant.description)
        .bind(format!("{:?}", tenant.state))
        .bind(tenant.created_at.to_rfc3339())
        .bind(tenant.created_by.to_string())
        .bind(tenant.updated_at.to_rfc3339())
        .bind(tenant.updated_by.to_string())
        .fetch_one(&mut *conn)
        .await?;

        OurTenant::from_row(&row)
    }

    async fn delete_tenant(&self, tenant_id: &Self::TenantId) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        sqlx::query("DELETE FROM tenants WHERE id = ?")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    /// Deletes a method state from the database by its composite key (method_id, tenant_id, user_id).
    ///
    /// The `method_state_id` parameter should be a string encoding the composite key, e.g. "method_id:tenant_id:user_id".
    /// If tenant_id or user_id is missing, use "null" in their place.
    async fn delete_method_state(&self, method_state_id: &Self::DataId) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        sqlx::query(
            r#"
            DELETE FROM method_states
            WHERE id = ?
            "#,
        )
        .bind(method_state_id)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    async fn upsert_auth_method(
        &self,
        method: AuthMethod<Self>,
    ) -> Result<AuthMethod<Self>, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query(
            r#"
            INSERT INTO auth_methods (id, name, description, factors, created_at, created_by, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                factors = excluded.factors,
                created_at = excluded.created_at,
                created_by = excluded.created_by,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            RETURNING id, name, description, factors, created_at, created_by, updated_at, updated_by
            "#
        )
        .bind(method.id.to_string())
        .bind(&method.name)
        .bind(&method.description)
        .bind(serde_json::to_string(&method.factors).unwrap())
        .bind(method.created_at.to_rfc3339())
        .bind(method.created_by.to_string())
        .bind(method.updated_at.to_rfc3339())
        .bind(method.updated_by.to_string())
        .fetch_one(&mut *conn)
        .await?;

        let our_method = OurAuthMethod::from_row(&row)?;
        Ok(AuthMethod::<OurBackend>::from(our_method))
    }

    async fn delete_auth_method(&self, method_id: &Self::MethodId) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        sqlx::query("DELETE FROM auth_methods WHERE id = ?")
            .bind(method_id.to_string())
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    async fn delete_factor_state(&self, factor_state_id: &Self::DataId) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        sqlx::query(
            r#"
            DELETE FROM factor_states
            WHERE factor_id = ?
            AND (tenant_id IS ? OR tenant_id = ?)
            AND (user_id IS ? OR user_id = ?)
            "#,
        )
        .bind(factor_state_id.to_string())
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    async fn upsert_auth_factor(
        &self,
        factor: AuthFactor<Self>,
    ) -> Result<AuthFactor<Self>, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let row = sqlx::query(
            r#"
            INSERT INTO auth_factors (id, kind, name, description, created_at, created_by, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                kind = excluded.kind,
                name = excluded.name,
                description = excluded.description,
                created_at = excluded.created_at,
                created_by = excluded.created_by,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            RETURNING id, kind, name, description, created_at, created_by, updated_at, updated_by
            "#
        )
        .bind(factor.id.to_string())
        .bind(factor.kind.as_str())
        .bind(&factor.name)
        .bind(&factor.description)
        .bind(factor.created_at.to_rfc3339())
        .bind(factor.created_by.to_string())
        .bind(factor.updated_at.to_rfc3339())
        .bind(factor.updated_by.to_string())
        .fetch_one(&mut *conn)
        .await?;

        let our_factor = OurAuthFactor::from_row(&row)?;
        Ok(AuthFactor::<OurBackend>::from(our_factor))
    }

    async fn delete_auth_factor(&self, factor_id: &Self::FactorId) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        sqlx::query("DELETE FROM auth_factors WHERE id = ?")
            .bind(factor_id.to_string())
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
}
