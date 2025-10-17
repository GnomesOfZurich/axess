use axess::utils::time as time_utils;
use axess::{AuthTenant, AuthUser, EntityState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, sqlite::SqliteRow};
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

fn parse_state(s: &str) -> axess::EntityState {
    match s {
        "Active" => axess::EntityState::Active,
        "Guest" => axess::EntityState::Guest,
        other => {
            // preserve original guard behavior by treating unknown as Suspended with detail
            axess::EntityState::Suspended(axess::StatusDetail {
                reason: format!("Unknown state: {}", other),
                timestamp: Utc::now(),
                until: None,
                metadata: None,
            })
        }
    }
}

impl<'r> FromRow<'r, SqliteRow> for OurTenant {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: Uuid::parse_str(row.try_get::<String, _>("id")?.as_str()).unwrap(),
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            state: match row.try_get::<String, _>("state")?.as_str() {
                "Active" => EntityState::Active,
                "Guest" => EntityState::Guest,
                other => {
                    return Err(sqlx::Error::ColumnDecode {
                        index: "state".into(),
                        source: Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Unknown tenant state: {other}"),
                        )),
                    });
                }
            },
            created_at: row
                .try_get::<Option<String>, _>("created_at")?
                .as_deref()
                .map(|s| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            created_by: Uuid::parse_str(row.try_get::<String, _>("created_by")?.as_str()).unwrap(),
            updated_at: row
                .try_get::<Option<String>, _>("updated_at")?
                .as_deref()
                .map(|s| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            updated_by: Uuid::parse_str(row.try_get::<String, _>("updated_by")?.as_str()).unwrap(),
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

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for OurUser {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        // read string columns
        let id_str: String = row.try_get("id")?;
        let tenant_id_str: String = row.try_get("tenant_id")?;
        let username: String = row.try_get("username")?;
        let fullname: Option<String> = row.try_get("fullname")?;
        let email: String = row.try_get("email")?;

        // parse UUIDs
        let id = Uuid::parse_str(id_str.as_str()).map_err(|e| sqlx::Error::ColumnDecode {
            index: "id".into(),
            source: Box::new(e),
        })?;
        let tenant_id =
            Uuid::parse_str(tenant_id_str.as_str()).map_err(|e| sqlx::Error::ColumnDecode {
                index: "tenant_id".into(),
                source: Box::new(e),
            })?;

        // state: try "user_state" then fallback to "state"
        let state_txt_opt: Option<String> = match row.try_get("user_state") {
            Ok(v) => v,
            Err(_) => row.try_get("state").unwrap_or(None),
        };
        let state = state_txt_opt
            .as_deref()
            .map(parse_state)
            .unwrap_or(axess::EntityState::Guest);

        // created_at / updated_at: accept either RFC3339 TEXT or INTEGER epoch
        let created_at = parse_datetime_flexible_row(row, "created_at")?.unwrap_or_else(Utc::now);
        let updated_at = parse_datetime_flexible_row(row, "updated_at")?.unwrap_or(created_at);

        let created_by_str: String = row.try_get("created_by")?;
        let updated_by_str: String = row.try_get("updated_by")?;

        let created_by =
            Uuid::parse_str(created_by_str.as_str()).map_err(|e| sqlx::Error::ColumnDecode {
                index: "created_by".into(),
                source: Box::new(e),
            })?;
        let updated_by =
            Uuid::parse_str(updated_by_str.as_str()).map_err(|e| sqlx::Error::ColumnDecode {
                index: "updated_by".into(),
                source: Box::new(e),
            })?;

        Ok(OurUser {
            id,
            tenant_id,
            username,
            fullname: fullname.unwrap_or_default(),
            email,
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
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    // Extract possible TEXT and INTEGER representations and delegate to shared helper.
    let txt_opt = row.try_get::<Option<String>, _>(col).ok().flatten();
    let int_opt = row.try_get::<Option<i64>, _>(col).ok().flatten();
    Ok(time_utils::parse_datetime_flexible(
        txt_opt.as_deref(),
        int_opt,
    ))
}
