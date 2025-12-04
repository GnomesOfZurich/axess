use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json;
use sqlx::{Error as SqlxError, FromRow, Row, SqlitePool};
use std::time::SystemTime;
use tracing::{error, info, warn};
use uuid::Uuid;

use axess::{
    AuthEvent, AuthEventRecord, AuthEventStatus, AuthEventType, AuthFactor, AuthFactorKind,
    AuthFactorState, AuthMethod, AuthMethodState, AuthnAdminBackend, AuthnBackend, EnablementState,
    EntityState, FactorForm, FactorFormExt, FactorStateChange, FormField, MethodStateChange,
    PermissionScope, TOTP_LENGTH, TOTP_PERIOD,
    // WorkflowState, WorkflowStep, WorkflowStepKind,
    verify_password, verify_totp,
};

use crate::models::{
    authn::{OurAuthFactor, OurAuthFactorState, OurAuthMethod, OurAuthMethodState},
    entities::{OurTenant, OurUser},
};

const DEFAULT_TENANT_NAME: &str = "Default Tenant";
const SYSTEM_SUPER_USER_NAME: &str = "system";
const TENANT_SUPER_USER_NAME: &str = "tenant";

pub type DataId = String;

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

// /// Helper to build the signup workflow
// pub fn build_signup_workflow() -> WorkflowState {
//     WorkflowState {
//         steps: vec![
//             WorkflowStep {
//                 kind: WorkflowStepKind::FactorVerify(AuthFactorKind::Otp), // Email verification
//                 description: "Verify your email".to_string(),
//                 completed: false,
//                 completed_at: None,
//                 metadata: None,
//             },
//             WorkflowStep {
//                 kind: WorkflowStepKind::FactorSetup(AuthFactorKind::Otp), // TOTP setup
//                 description: "Setup TOTP".to_string(),
//                 completed: false,
//                 completed_at: None,
//                 metadata: None,
//             },
//         ],
//         current_step: 0,
//         started_at: Utc::now(),
//         last_updated: Utc::now(),
//         blocking: true,
//     }
// }

// Small parsing helpers used when reading enum values stored as text in the DB.
fn parse_enum_or_default<T>(s: Option<String>) -> T
where
    T: std::str::FromStr,
{
    match s {
        Some(st) => st.parse::<T>().unwrap_or_else(|_| {
            // prefer a graceful fallback: log and use Default if T: Default
            // If T doesn't implement Default, fallback to panic (explicit)
            error!("Failed to parse enum from database text: {}", st);
            panic!("Failed to parse enum from database text: {}", st)
        }),
        None => {
            warn!("Missing enum text value in database row; using default if available");
            // If T implements Default, return that; otherwise explicit panic to surface mismatch
            // try to return Default via trait bound - cast fails if not implemented, so panic
            panic!("Missing enum text value in database row")
        }
    }
}

fn parse_enum_option<T>(s: Option<String>) -> Option<T>
where
    T: std::str::FromStr,
{
    s.and_then(|st| st.parse::<T>().ok())
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
        let row = sqlx::query("SELECT id FROM tenants WHERE name = ?")
            .bind(DEFAULT_TENANT_NAME)
            .fetch_one(&mut *conn)
            .await?;

        let id_str: String = row.try_get("id")?;
        Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::ColumnDecode {
            index: "tenant".into(),
            source: Box::new(e),
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
            "UPDATE users SET state = ? WHERE id = ? RETURNING id, username, password, tenant_id, state, factors, methods"
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
        let row = sqlx::query("SELECT * FROM auth_methods WHERE id = ?")
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

        eprintln!("get_scoped_auth_methods returned rows: {}", rows.len());

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
    /// For inserts: Generates new UUID for `id`, sets `created_by` to the given `actor`.
    /// For updates: Preserves existing `created_by` value from the database, sets `updated_by` to the given actor.
    /// In both cases: Uses `updated_at` and `updated_by` from input.
    ///
    /// Returns the upserted method state as loaded from the database.
    async fn upsert_method_state(
        &self,
        change: MethodStateChange<Self::MethodId, Self::TenantId, Self::UserId>,
        actor: Self::UserId,
    ) -> Result<AuthMethodState<Self>, Self::Error> {
        let tenant_id = change.tenant_id.map(|t| t.to_string());
        let user_id = change.user_id.map(|u| u.to_string());

        let mut conn = self.db.acquire().await?;
        let now = Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO method_states (id, method_id, tenant_id, user_id, state, created_at, created_by, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(method_id, tenant_id, user_id) DO UPDATE SET 
                created_at = method_states.created_at, -- preserve existing value
                created_by = method_states.created_by  -- preserve existing value
            RETURNING id, method_id, tenant_id, user_id, state, created_at, created_by, updated_at, updated_by
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(change.method_id.to_string())
        .bind(tenant_id)
        .bind(user_id)
        .bind(format!("{:?}", change.state))
        .bind(now.to_rfc3339())
        .bind(actor.to_string()) // only used for insert
        .bind(now.to_rfc3339())
        .bind(actor.to_string()) // always set updated_by to actor
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
    /// Filters by the provided enablement states.
    /// Returns factors that have at least one matching state in the specified scope.
    /// For example, if scope is Tenant(tid) and states are [Active, Inactive],
    /// it returns factors that are Active or Inactive for that tenant,
    /// as well as any global factors with those states.
    /// If `states` is empty, all factors in the scope are returned, regardless of state.
    async fn get_scoped_auth_factors(
        &self,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
        states: Vec<EnablementState>,
    ) -> Result<Vec<AuthFactor<Self>>, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let state_strs: Vec<String> = states.iter().map(|s| format!("{:?}", s)).collect();

        // Build scope filter and binds
        let (scope_filter, mut binds): (String, Vec<Option<String>>) = match scope {
            PermissionScope::Global => (
                "s.tenant_id IS NULL AND s.user_id IS NULL".to_string(),
                vec![],
            ),
            PermissionScope::Any => (
                "1=1".to_string(), // No scope filter
                vec![],
            ),
            PermissionScope::Tenant(tid) => (
                // Match both tenant-level and global factor states
                "(s.tenant_id IS NULL AND s.user_id IS NULL) OR (s.tenant_id = ?1 AND s.user_id IS NULL)".to_string(),
                vec![Some(tid.to_string())],
            ),
            PermissionScope::User(tid, uid) => (
                "(s.tenant_id IS NULL AND s.user_id IS NULL) \
                  OR (s.tenant_id = ?1 AND s.user_id IS NULL) \
                  OR (s.tenant_id = ?2 AND s.user_id = ?3)".to_string(),
                vec![Some(tid.to_string()), Some(tid.to_string()), Some(uid.to_string())],
            ),
        };

        // Build state filter and placeholders
        let (state_filter, state_binds) = if state_strs.is_empty() {
            ("".to_string(), vec![])
        } else {
            let offset = binds.len();
            let state_placeholders = (0..state_strs.len())
                .map(|i| format!("?{}", i + offset + 1))
                .collect::<Vec<_>>()
                .join(", ");
            (
                format!("AND s.state IN ({})", state_placeholders),
                state_strs.iter().map(|s| Some(s.clone())).collect(),
            )
        };

        binds.extend(state_binds);

        // Compose final query
        let query = format!(
            r#"
            SELECT f.*
            FROM auth_factors f
            WHERE EXISTS (
                SELECT 1 FROM factor_states s
                WHERE s.factor_id = f.id
                AND ({})
                {}
            )
            "#,
            scope_filter, state_filter
        );

        let mut sql = sqlx::query_as::<_, OurAuthFactor>(&query);
        for bind in binds {
            match bind {
                Some(val) => sql = sql.bind(val),
                None => sql = sql.bind(None::<String>),
            }
        }

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
    /// For inserts: Generates new UUID for `id`, sets `created_by` to the given `updated_by` (actor).
    /// For updates: Preserves existing `id`, `created_at`, and `created_by` from database, sets `updated_by` to the given actor.
    /// In both cases: Uses `updated_at` and `updated_by` from input.
    ///
    /// Returns the upserted factor state as loaded from the database.
    async fn upsert_factor_state(
        &self,
        change: FactorStateChange<Self::FactorId, Self::TenantId, Self::UserId>,
        actor: Self::UserId,
    ) -> Result<AuthFactorState<Self>, Self::Error> {
        let mut conn = self.db.acquire().await?;

        let config_json =
            serde_json::to_string(&change.config).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
        let now = Utc::now();

        let row = sqlx::query(
            r#"
            INSERT INTO factor_states (
                id, factor_id, tenant_id, user_id, state, config,
                created_at, created_by, updated_at, updated_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(factor_id, tenant_id, user_id) DO UPDATE SET
                created_at = factor_states.created_at, -- preserve existing value
                created_by = factor_states.created_by  -- preserve existing value
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
        .bind(actor.to_string()) // only used for insert
        .bind(now.to_rfc3339())
        .bind(actor.to_string())
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
    ) -> Result<Vec<AuthEvent<OurBackend>>, Self::Error> {
        let mut conn = self.db.acquire().await?;

        // Base query selects events for the given user
        let mut query = String::from("SELECT * FROM authn_hist WHERE user_id = ?");
        let mut binds: Vec<String> = vec![user_id.to_string()];

        if let Some(event_type) = event_type {
            query.push_str(" AND event_type = ?");
            binds.push(event_type.as_str().to_string());
        }

        if let Some(event_status) = event_status {
            query.push_str(" AND event_status = ?");
            binds.push(event_status.as_str().to_string());
        }

        // Order results by event_time descending so the newest events come first
        query.push_str(" ORDER BY event_time DESC");

        // Apply optional limit if provided
        if let Some(l) = limit {
            query.push_str(" LIMIT ?");
            binds.push(l.to_string());
        }

        // Prepare and execute the query, binding the collected parameters to produce `rows`
        let mut sql = sqlx::query(&query);
        for b in binds {
            sql = sql.bind(b);
        }
        let rows = sql.fetch_all(&mut *conn).await?;

        let events: Vec<AuthEvent<OurBackend>> = rows
            .into_iter()
            .map(|row| {
                // Safely extract optional text fields and parse defensively.
                let event_type_txt = row
                    .try_get::<Option<String>, _>("event_type")
                    .ok()
                    .flatten();
                let event_status_txt = row
                    .try_get::<Option<String>, _>("event_status")
                    .ok()
                    .flatten();
                let method_id_txt = row.try_get::<Option<String>, _>("method_id").ok().flatten();
                let factor_id_txt = row.try_get::<Option<String>, _>("factor_id").ok().flatten();
                let factor_kind_txt = row
                    .try_get::<Option<String>, _>("factor_kind")
                    .ok()
                    .flatten();
                let event_time_txt = row
                    .try_get::<Option<String>, _>("event_time")
                    .ok()
                    .flatten();

                AuthEvent {
                    id: row
                        .try_get::<Option<String>, _>("id")
                        .ok()
                        .flatten()
                        .unwrap_or_default(),
                    user_id: Uuid::parse_str(
                        row.try_get::<Option<String>, _>("user_id")
                            .ok()
                            .flatten()
                            .as_deref()
                            .unwrap_or(""),
                    )
                    .unwrap_or(Uuid::nil()),
                    tenant_id: Uuid::parse_str(
                        row.try_get::<Option<String>, _>("tenant_id")
                            .ok()
                            .flatten()
                            .as_deref()
                            .unwrap_or(""),
                    )
                    .unwrap_or(Uuid::nil()),
                    session_id: row
                        .try_get::<Option<String>, _>("session_id")
                        .ok()
                        .flatten(),
                    // use parsing helpers to tolerate empty/null text and parse enums via FromStr
                    event_type: parse_enum_or_default::<AuthEventType>(event_type_txt.clone()),
                    event_status: parse_enum_or_default::<AuthEventStatus>(
                        event_status_txt.clone(),
                    ),
                    event_time: event_time_txt
                        .as_deref()
                        .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or(Utc::now()),
                    method_id: method_id_txt.and_then(|mid| Uuid::parse_str(&mid).ok()),
                    factor_id: factor_id_txt.and_then(|fid| Uuid::parse_str(&fid).ok()),
                    factor_kind: parse_enum_option::<AuthFactorKind>(factor_kind_txt),
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
    ) -> Result<Option<DateTime<Utc>>, Self::Error> {
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

        // omit `id` so SQLite will use AUTOINCREMENT integer key
        sqlx::query(
            r#"
            INSERT INTO authn_hist (
                user_id, tenant_id, session_id, event_type, event_status,
                event_time, method_id, factor_id, factor_kind, ip_address,
                user_agent, error_message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.user_id.to_string())
        .bind(event.tenant_id.to_string())
        .bind(event.session_id)
        .bind(event.event_type.as_str())
        .bind(event.event_status.as_str())
        .bind(now.to_rfc3339())
        .bind(event.method_id.map(|m| m.to_string()))
        .bind(event.factor_id.map(|f| f.to_string()))
        .bind(event.factor_kind.map(|fk| fk.to_string()))
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
        let factor_kind = creds.factor_kind();

        // 1. Resolve tenant and username from the typed helpers
        let tenant_id = if let Some(t) = creds.get_string_field(FormField::Tenant) {
            Uuid::parse_str(&t).map_err(|e| sqlx::Error::ColumnDecode {
                index: "tenant".into(),
                source: Box::new(e),
            })?
        } else {
            // prefer explicit backend default rather than Uuid::nil()
            self.get_default_tenant_id().await?
        };
        let username = creds
            .get_string_field(FormField::Username)
            .unwrap_or_default();

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
            return Err(sqlx::Error::Decode(
                format!("User account is not active (state: {:?})", user.state).into(),
            ));
        }

        // 4. Lookup factors for this user using the backend's scoped factor lookup
        let scope = PermissionScope::User(tenant_id, user.id);
        let factors = self
            .get_scoped_auth_factors(scope, vec![EnablementState::Active])
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
                // prefer the generic credential() accessor for primary auth values
                let password = creds.credential().unwrap_or("");
                verify_password(password, password_hash)
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                Ok(user)
            }
            AuthFactorKind::Otp => {
                let factor_config = &factor_state.0.config;

                let otp_type = factor_config
                    .get("otp_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                match otp_type {
                    "totp" => {
                        let totp_code = creds.credential().unwrap_or("");

                        let totp_secret = factor_config
                            .get("secret")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| sqlx::Error::ColumnDecode {
                                index: "factor_state".into(),
                                source: Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "Missing TOTP secret in factor state",
                                )),
                            })?;
                        let totp_length = factor_config
                            .get("otp_length")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(TOTP_LENGTH as u64)
                            as usize;
                        let totp_period = factor_config
                            .get("period")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(TOTP_PERIOD);
                        let past_window = factor_config
                            .get("past_window")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(1u64);
                        let future_window = factor_config
                            .get("future_window")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0u64);

                        match verify_totp(
                            totp_secret,
                            totp_code,
                            SystemTime::now(),
                            Some(totp_length),
                            Some(totp_period),
                            Some(past_window),
                            Some(future_window),
                        ) {
                            Some(_) => Ok(user),
                            None => Err(SqlxError::Protocol("Invalid TOTP code".to_string())),
                        }
                    }
                    _ => Err(SqlxError::Protocol(format!(
                        "Unsupported OTP type: {}",
                        otp_type
                    ))),
                }
            }
            AuthFactorKind::Oauth => {
                // Handle OAuth factor authentication
                // This is a placeholder, actual implementation will depend on your OAuth setup
                Err(SqlxError::Protocol(
                    "OAuth factor authentication not implemented".to_string(),
                ))
            }
            AuthFactorKind::Custom(name) => {
                // Custom factor kinds are not handled by this backend example.
                // Return a protocol error indicating the custom kind is unsupported.
                Err(SqlxError::Protocol(format!(
                    "Custom factor authentication not implemented for kind: {}",
                    name
                )))
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
    async fn upsert_user(
        &self,
        user: Self::User,
        actor: Self::UserId,
    ) -> Result<Self::User, Self::Error> {
        let mut conn = self.db.acquire().await?;

        let now = Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO users (
                id, tenant_id, username, fullname, email, state,
                created_at, created_by, updated_at, updated_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                created_at = users.created_at, -- preserve existing value
                created_by = users.created_by  -- preserve existing value
            RETURNING
                id, tenant_id, username, fullname, email, state,
                created_at, created_by, updated_at, updated_by
            "#,
        )
        .bind(user.id.to_string())
        .bind(user.tenant_id.to_string())
        .bind(&user.username)
        .bind(&user.fullname)
        .bind(&user.email)
        .bind(format!("{:?}", user.state))
        .bind(now.to_rfc3339()) // only used for insert
        .bind(actor.to_string()) // only used for insert
        .bind(now.to_rfc3339())
        .bind(actor.to_string())
        .fetch_one(&mut *conn)
        .await?;

        OurUser::from_row(&row)
    }

    async fn delete_user(
        &self,
        user_id: &Self::UserId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .execute(&mut *conn)
            .await?;
        info!("User with ID {} deleted from 'users' by {}", user_id, actor);
        Ok(())
    }

    /// Upserts (inserts or updates) a tenant in the database.
    ///
    /// If the tenant already exists (matched by `id`), updates all fields except `created_by`.
    /// For inserts, sets `created_by` to the given `actor`.
    /// For updates, preserves the existing `created_by` value from the database.
    ///
    /// Returns the upserted tenant as loaded from the database.
    async fn upsert_tenant(
        &self,
        tenant: Self::Tenant,
        actor: Self::UserId,
    ) -> Result<Self::Tenant, Self::Error> {
        let mut conn = self.db.acquire().await?;

        let now = Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO tenants (id, name, description, state, created_at, created_by, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                created_at = tenants.created_at, -- preserve existing value on update
                created_by = tenants.created_by  -- preserve existing value on update
            RETURNING id, name, description, state, created_at, created_by, updated_at, updated_by
            "#
        )
        .bind(tenant.id.to_string())
        .bind(&tenant.name)
        .bind(&tenant.description)
        .bind(format!("{:?}", tenant.state))
        .bind(now.to_rfc3339()) // only used for insert
        .bind(actor.to_string()) // only used for insert
        .bind(now.to_rfc3339())
        .bind(actor.to_string())
        .fetch_one(&mut *conn)
        .await?;

        OurTenant::from_row(&row)
    }

    async fn delete_tenant(
        &self,
        tenant_id: &Self::TenantId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        sqlx::query("DELETE FROM tenants WHERE id = ?")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;
        info!(
            "Tenant with ID {} deleted from 'tenants' by user {}",
            tenant_id, actor
        );
        Ok(())
    }

    /// Deletes a method state from the database by its composite key (method_id, tenant_id, user_id).
    ///
    /// The `method_state_id` parameter should be a string encoding the composite key, e.g. "method_id:tenant_id:user_id".
    /// If tenant_id or user_id is missing, use "null" in their place.
    async fn delete_method_state(
        &self,
        method_state_id: &Self::DataId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error> {
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
        info!(
            "MethodState with ID {} deleted from 'method_states' by {}",
            method_state_id, actor
        );
        Ok(())
    }

    /// Upserts (inserts or updates) an authentication method in the database.
    ///
    /// If the method already exists (matched by `id`), updates all fields except `created_by`.
    /// For inserts, sets `created_by` to the given `created_by` field from the input.
    /// For updates, preserves the existing `created_by` value from the database.
    ///
    /// Returns the upserted method as loaded from the database.
    async fn upsert_auth_method(
        &self,
        method: AuthMethod<Self>,
        actor: Self::UserId,
    ) -> Result<AuthMethod<Self>, Self::Error> {
        let mut conn = self.db.acquire().await?;

        let factors_json =
            serde_json::to_string(&method.factors).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;

        let now = Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO auth_methods (id, name, description, factors, created_at, created_by, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                created_at = auth_methods.created_at,      -- preserve original
                created_by = auth_methods.created_by       -- preserve original
            RETURNING id, name, description, factors, created_at, created_by, updated_at, updated_by
            "#
        )
        .bind(method.id.to_string())
        .bind(&method.name)
        .bind(&method.description)
        .bind(factors_json)
        .bind(now.to_rfc3339()) // only used for insert
        .bind(actor.to_string()) // only used for insert
        .bind(now.to_rfc3339())
        .bind(actor.to_string())
        .fetch_one(&mut *conn)
        .await?;

        let our_method = OurAuthMethod::from_row(&row)?;
        Ok(AuthMethod::<OurBackend>::from(our_method))
    }

    async fn delete_auth_method(
        &self,
        method_id: &Self::MethodId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        sqlx::query("DELETE FROM auth_methods WHERE id = ?")
            .bind(method_id.to_string())
            .execute(&mut *conn)
            .await?;
        info!(
            "Authentication method with ID {} deleted from 'auth_methods' by {}",
            method_id, actor
        );
        Ok(())
    }

    async fn delete_factor_state(
        &self,
        factor_state_id: &Self::DataId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error> {
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
        info!(
            "Authentication factor state with ID {} deleted from 'factor_states'by {}",
            factor_state_id, actor
        );
        Ok(())
    }

    /// Upserts (inserts or updates) an authentication factor in the database.
    ///
    /// If the factor already exists (matched by `id`), updates all fields except `created_by`.
    /// For inserts, sets `created_by` to the given `created_by` field from the input.
    /// For updates, preserves the existing `created_by` value from the database.
    ///
    /// Returns the upserted factor as loaded from the database.
    async fn upsert_auth_factor(
        &self,
        factor: AuthFactor<Self>,
        actor: Self::UserId,
    ) -> Result<AuthFactor<Self>, Self::Error> {
        let mut conn = self.db.acquire().await?;
        let now = Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO auth_factors (id, kind, name, description, created_at, created_by, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                created_at = auth_factors.created_at, -- preserve existing value
                created_by = auth_factors.created_by  -- preserve existing value
            RETURNING id, kind, name, description, created_at, created_by, updated_at, updated_by
            "#
        )
        .bind(factor.id.to_string())
        .bind(factor.kind.as_str())
        .bind(&factor.name)
        .bind(&factor.description)
        .bind(now.to_rfc3339()) // only used for insert
        .bind(actor.to_string()) // only used for insert
        .bind(now.to_rfc3339())
        .bind(actor.to_string())
        .fetch_one(&mut *conn)
        .await?;

        let our_factor = OurAuthFactor::from_row(&row)?;
        Ok(AuthFactor::<OurBackend>::from(our_factor))
    }

    async fn delete_auth_factor(
        &self,
        factor_id: &Self::FactorId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        let mut conn = self.db.acquire().await?;
        sqlx::query("DELETE FROM auth_factors WHERE id = ?")
            .bind(factor_id.to_string())
            .execute(&mut *conn)
            .await?;
        info!(
            "Authentication factor with ID {} deleted from 'auth_factors' by {}",
            factor_id, actor
        );
        Ok(())
    }
}
