use chrono::{DateTime, Utc};
use sqlx::{FromRow, Row, sqlite::SqliteRow};
use uuid::Uuid;

use crate::models::backend::OurBackend;
use axess::{AuthMethod, AuthMethodState, EnablementState};

pub struct OurAuthMethod(pub AuthMethod<OurBackend>);

impl From<OurAuthMethod> for AuthMethod<OurBackend> {
    fn from(value: OurAuthMethod) -> Self {
        value.0
    }
}

impl<'r> FromRow<'r, SqliteRow> for OurAuthMethod {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(OurAuthMethod(AuthMethod::<OurBackend> {
            id: Uuid::parse_str(row.try_get::<String, _>("id")?.as_str()).unwrap(),
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            factors: serde_json::from_str(&row.try_get::<String, _>("factors")?).unwrap(),
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
        }))
    }
}

pub struct OurAuthMethodState(pub AuthMethodState<OurBackend>);

impl From<OurAuthMethodState> for AuthMethodState<OurBackend> {
    fn from(value: OurAuthMethodState) -> Self {
        value.0
    }
}

impl<'r> FromRow<'r, SqliteRow> for OurAuthMethodState {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(OurAuthMethodState(AuthMethodState::<OurBackend> {
            id: Uuid::parse_str(row.try_get::<String, _>("id")?.as_str()).unwrap(),
            method_id: Uuid::parse_str(row.try_get::<String, _>("method_id")?.as_str()).unwrap(),
            tenant_id: Some(
                Uuid::parse_str(row.try_get::<String, _>("tenant_id")?.as_str()).unwrap(),
            ),
            user_id: Some(Uuid::parse_str(row.try_get::<String, _>("user_id")?.as_str()).unwrap()),
            state: match row.try_get::<String, _>("state")?.as_str() {
                "Active" => EnablementState::Active,
                "Inactive" => EnablementState::Inactive,
                other => {
                    return Err(sqlx::Error::ColumnDecode {
                        index: "state".into(),
                        source: Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Unknown factor state: {other}"),
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
        }))
    }
}
