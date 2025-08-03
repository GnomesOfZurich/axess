use axess::{AuthTenant, AuthUser, EntityState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, sqlite::SqliteRow};
use uuid::Uuid;

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
    pub auth_hash: String,
    pub username: String,
    pub fullname: String,
    pub email: String,
    pub state: EntityState,
    pub last_login_at: Option<DateTime<Utc>>,
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
            auth_hash: String::new(),
            username,
            fullname,
            email,
            state: EntityState::Active,
            last_login_at: None,
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
            auth_hash: String::new(),
            username: "guest".to_string(),
            fullname: "Guest User".to_string(),
            email: "".to_string(),
            state: EntityState::Guest,
            last_login_at: None,
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
        // Assuming UserState is an enum, you can implement the logic to determine the state.
        // For simplicity, we return the user's state here.
        self.state.clone()
    }

    fn auth_session_hash(&self) -> Option<&str> {
        if self.auth_hash.is_empty() {
            None
        } else {
            Some(self.auth_hash.as_str())
        }
    }

    fn set_auth_session_hash(&mut self, hash: Option<String>) {
        match hash {
            Some(h) => self.auth_hash = h,
            None => self.auth_hash.clear(),
        }
    }
}

impl<'r> FromRow<'r, SqliteRow> for OurUser {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: Uuid::parse_str(row.try_get::<String, _>("id")?.as_str()).unwrap(),
            tenant_id: Uuid::parse_str(row.try_get::<String, _>("tenant_id")?.as_str()).unwrap(),
            auth_hash: row.try_get("auth_hash")?,
            username: row.try_get("username")?,
            fullname: row.try_get("fullname")?,
            email: row.try_get("email")?,
            state: match row.try_get::<String, _>("state")?.as_str() {
                "Active" => EntityState::Active,
                "Guest" => EntityState::Guest,
                other => {
                    return Err(sqlx::Error::ColumnDecode {
                        index: "state".into(),
                        source: Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Unknown user_state: {other}"),
                        )),
                    });
                }
            },
            last_login_at: row
                .try_get::<Option<String>, _>("last_login_at")?
                .as_deref()
                .map(|s| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)),
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
