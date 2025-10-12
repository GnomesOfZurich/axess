use chrono::{DateTime, Utc};
use sqlx::{FromRow, Row, sqlite::SqliteRow};
use uuid::Uuid;

use crate::models::backend::OurBackend;
use axess::{AuthFactor, AuthFactorState, EnablementState};

pub struct OurAuthFactor(pub AuthFactor<OurBackend>);

impl From<OurAuthFactor> for AuthFactor<OurBackend> {
    fn from(value: OurAuthFactor) -> Self {
        value.0
    }
}

impl<'r> FromRow<'r, SqliteRow> for OurAuthFactor {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(OurAuthFactor(AuthFactor::<OurBackend> {
            id: Uuid::parse_str(row.try_get::<String, _>("id")?.as_str()).unwrap(),
            kind: serde_json::from_str(&row.try_get::<String, _>("kind")?).unwrap(),
            name: row.try_get("name")?,
            description: row.try_get("description")?,
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

pub struct OurAuthFactorState(pub AuthFactorState<OurBackend>);

impl From<OurAuthFactorState> for AuthFactorState<OurBackend> {
    fn from(value: OurAuthFactorState) -> Self {
        value.0
    }
}

impl<'r> FromRow<'r, SqliteRow> for OurAuthFactorState {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(OurAuthFactorState(AuthFactorState::<OurBackend> {
            id: row.try_get::<String, _>("id")?,
            factor_id: Uuid::parse_str(row.try_get::<String, _>("factor_id")?.as_str()).unwrap(),
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
            config: serde_json::from_str(&row.try_get::<String, _>("config")?).unwrap(),
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
