use crate::models::backend::OurBackend;
use axess::{
    AuthFactor, AuthFactorState, AuthMethod, AuthMethodState, AuthSession, EnablementState,
    StoreSessionRegistry,
};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, Row, sqlite::SqliteRow};
use tower_sessions_sqlx_store::SqliteStore;
use uuid::Uuid;

#[allow(dead_code)]
pub type OurAuthSession = AuthSession<OurBackend, StoreSessionRegistry<SqliteStore>>;

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
            // DB stores enum as plain text (e.g. Password). Wrap in quotes so serde_json can deserialize.
            kind: {
                let kind_txt: String = row.try_get("kind")?;
                serde_json::from_str(&format!("\"{}\"", kind_txt))
                    .unwrap_or(axess::AuthFactorKind::Custom(kind_txt))
            },
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
            // tolerate NULL/empty config and invalid JSON by defaulting to empty object
            config: {
                match row.try_get::<Option<String>, _>("config")? {
                    Some(s) => serde_json::from_str::<
                        std::collections::HashMap<String, serde_json::Value>,
                    >(&s)
                    .unwrap_or_else(|_| std::collections::HashMap::new()),
                    None => std::collections::HashMap::new(),
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
            // tolerate NULL/empty factors JSON by defaulting to empty vec
            factors: match row.try_get::<Option<String>, _>("factors")? {
                Some(s) => serde_json::from_str(&s).unwrap_or_default(),
                None => Vec::new(),
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
