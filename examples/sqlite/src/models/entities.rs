use axess::{AuthTenant, AuthUser, EntityState, StatusDetail, utils::time as time_utils};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Error as SqlxError, FromRow, Row, sqlite::SqliteRow};
use uuid::Uuid; // add near other use imports

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct OurTenant {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub state: EntityState,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Uuid,
}

impl AuthTenant for OurTenant {
    type Id = Uuid;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn get_tenant_state(&self) -> EntityState {
        self.state.clone()
    }
}

fn parse_state(s: &str) -> EntityState {
    match s {
        "Active" => EntityState::Active,
        "Guest" => EntityState::Guest,
        other => {
            // preserve original guard behavior by treating unknown as Suspended with detail
            EntityState::Suspended(StatusDetail {
                reason: format!("Unknown state: {}", other),
                timestamp: Utc::now(),
                until: None,
                metadata: None,
            })
        }
    }
}

impl<'r> FromRow<'r, SqliteRow> for OurTenant {
    fn from_row(row: &'r SqliteRow) -> Result<Self, SqlxError> {
        // parse id with proper error mapping
        let id_str: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id_str).map_err(|e| SqlxError::ColumnDecode {
            index: "id".into(),
            source: Box::new(e),
        })?;

        // name/description
        let name: String = row.try_get("name")?;
        let description: String = row.try_get("description")?;

        // state: prefer tolerant parsing using parse_state, fall back to Guest if absent
        let state_txt: Option<String> = row.try_get::<Option<String>, _>("state").ok().flatten();
        let state = state_txt
            .as_deref()
            .map(parse_state)
            .unwrap_or(EntityState::Guest);

        // created_at / updated_at using shared flexible parser
        let created_at = parse_datetime_flexible_row(row, "created_at")?.unwrap_or_else(Utc::now);
        let updated_at = parse_datetime_flexible_row(row, "updated_at")?.unwrap_or_else(Utc::now);

        // created_by / updated_by with UUID error mapping
        let created_by =
            Uuid::parse_str(&row.try_get::<String, _>("created_by")?).map_err(|e| {
                SqlxError::ColumnDecode {
                    index: "created_by".into(),
                    source: Box::new(e),
                }
            })?;
        let updated_by =
            Uuid::parse_str(&row.try_get::<String, _>("updated_by")?).map_err(|e| {
                SqlxError::ColumnDecode {
                    index: "updated_by".into(),
                    source: Box::new(e),
                }
            })?;

        Ok(Self {
            id,
            name,
            description,
            state,
            created_at,
            created_by,
            updated_at,
            updated_by,
        })
    }
}

/// User model for the example app.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct OurUser {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub fullname: String,
    pub email: String,
    pub state: EntityState,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Uuid,
}

impl OurUser {
    pub fn new(
        id: Uuid,
        tenant_id: Uuid,
        username: String,
        fullname: String,
        email: String,
        creator: Uuid,
    ) -> Self {
        Self {
            id,
            tenant_id,
            username,
            fullname,
            email,
            state: EntityState::Active,
            created_at: Utc::now(),
            created_by: creator,
            updated_at: Utc::now(),
            updated_by: creator,
        }
    }

    pub fn new_guest_user(tenant_id: Uuid, creator_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            username: "guest".to_string(),
            fullname: "Guest User".to_string(),
            email: "".to_string(),
            state: EntityState::Guest,
            created_at: Utc::now(),
            created_by: creator_id,
            updated_at: Utc::now(),
            updated_by: creator_id,
        }
    }
}

impl AuthUser for OurUser {
    type Id = Uuid;
    type TenantId = Uuid;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn tenant_id(&self) -> &Self::TenantId {
        &self.tenant_id
    }

    fn get_user_state(&self) -> EntityState {
        self.state.clone()
    }
}

impl<'r> FromRow<'r, SqliteRow> for OurUser {
    fn from_row(row: &'r SqliteRow) -> Result<Self, SqlxError> {
        // read string columns defensively
        let id_str: String = row.try_get("id")?;
        let tenant_str: String = row.try_get("tenant_id")?;
        let id = Uuid::parse_str(&id_str).map_err(|e| SqlxError::ColumnDecode {
            index: "id".into(),
            source: Box::new(e),
        })?;
        let tenant_id = Uuid::parse_str(&tenant_str).map_err(|e| SqlxError::ColumnDecode {
            index: "tenant_id".into(),
            source: Box::new(e),
        })?;

        // Prefer user_state then state, fallback to Guest
        let state_txt: Option<String> = row
            .try_get::<Option<String>, _>("user_state")
            .ok()
            .flatten()
            .or_else(|| row.try_get::<Option<String>, _>("state").ok().flatten());
        let state = state_txt
            .as_deref()
            .map(parse_state)
            .unwrap_or(EntityState::Guest);

        // created_at/updated_at tolerant parsing
        let created_at = parse_datetime_flexible_row(row, "created_at")?.unwrap_or_else(Utc::now);
        let updated_at = parse_datetime_flexible_row(row, "updated_at")?.unwrap_or(created_at);

        // created_by/updated_by UUID parsing with error mapping
        let created_by =
            Uuid::parse_str(&row.try_get::<String, _>("created_by")?).map_err(|e| {
                SqlxError::ColumnDecode {
                    index: "created_by".into(),
                    source: Box::new(e),
                }
            })?;
        let updated_by =
            Uuid::parse_str(&row.try_get::<String, _>("updated_by")?).map_err(|e| {
                SqlxError::ColumnDecode {
                    index: "updated_by".into(),
                    source: Box::new(e),
                }
            })?;

        Ok(OurUser {
            id,
            tenant_id,
            username: row.try_get("username")?,
            fullname: row
                .try_get::<Option<String>, _>("fullname")?
                .unwrap_or_default(),
            email: row.try_get("email")?,
            state,
            created_at,
            created_by,
            updated_at,
            updated_by,
        })
    }
}

fn parse_datetime_flexible_row(
    row: &SqliteRow,
    col: &str,
) -> Result<Option<DateTime<Utc>>, SqlxError> {
    // Extract possible TEXT and INTEGER representations and delegate to shared helper.
    let txt_opt = row.try_get::<Option<String>, _>(col).ok().flatten();
    let int_opt = row.try_get::<Option<i64>, _>(col).ok().flatten();
    Ok(time_utils::parse_datetime_flexible(
        txt_opt.as_deref(),
        int_opt,
    ))
}
