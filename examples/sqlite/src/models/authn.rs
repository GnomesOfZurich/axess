use crate::models::backend::OurBackend;
use axess::{
    AuthFactor, AuthFactorState, AuthMethod, AuthMethodState, AuthSession, EnablementState,
    SessionRegistryStore, SystemRng,
};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, Row, sqlite::SqliteRow};
use std::collections::HashMap;
use tower_sessions_sqlx_store::SqliteStore;
use uuid::Uuid;

#[allow(dead_code)]
pub type OurAuthSession = AuthSession<OurBackend, SessionRegistryStore<SqliteStore>, SystemRng>;

pub struct OurAuthFactor(pub AuthFactor<OurBackend>);

impl From<OurAuthFactor> for AuthFactor<OurBackend> {
    fn from(value: OurAuthFactor) -> Self {
        value.0
    }
}

impl<'r> FromRow<'r, SqliteRow> for OurAuthFactor {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let id_str: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::ColumnDecode {
            index: "id".into(),
            source: Box::new(e),
        })?;

        let kind_txt: String = row.try_get("kind")?;
        let kind = serde_json::from_str::<axess::AuthFactorKind>(&format!("\"{}\"", kind_txt))
            .unwrap_or(axess::AuthFactorKind::Custom(kind_txt.clone()));

        let name: String = row.try_get("name")?;
        let description: String = row.try_get("description")?;

        let created_at = row
            .try_get::<Option<String>, _>("created_at")?
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let created_by_str: String = row.try_get("created_by")?;
        let created_by =
            Uuid::parse_str(&created_by_str).map_err(|e| sqlx::Error::ColumnDecode {
                index: "created_by".into(),
                source: Box::new(e),
            })?;

        let updated_at = row
            .try_get::<Option<String>, _>("updated_at")?
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let updated_by_str: String = row.try_get("updated_by")?;
        let updated_by =
            Uuid::parse_str(&updated_by_str).map_err(|e| sqlx::Error::ColumnDecode {
                index: "updated_by".into(),
                source: Box::new(e),
            })?;

        Ok(OurAuthFactor(AuthFactor::<OurBackend> {
            id,
            kind,
            name,
            description,
            created_at,
            created_by,
            updated_at,
            updated_by,
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
        let factor_id_str: String = row.try_get("factor_id")?;
        let factor_id =
            uuid::Uuid::parse_str(&factor_id_str).map_err(|e| sqlx::Error::ColumnDecode {
                index: "factor_id".into(),
                source: Box::new(e),
            })?;

        // Optional tenant/user ids
        let tenant_id = row
            .try_get::<Option<String>, _>("tenant_id")?
            .and_then(|s| uuid::Uuid::parse_str(&s).ok());
        let user_id = row
            .try_get::<Option<String>, _>("user_id")?
            .and_then(|s| uuid::Uuid::parse_str(&s).ok());

        // tolerant config JSON
        let config: HashMap<String, serde_json::Value> =
            match row.try_get::<Option<String>, _>("config")? {
                Some(s) => serde_json::from_str::<HashMap<String, serde_json::Value>>(&s)
                    .unwrap_or_default(),
                None => HashMap::new(),
            };

        let state_txt: String = row.try_get("state")?;
        let state = match state_txt.as_str() {
            "Active" => axess::EnablementState::Active,
            "Inactive" => axess::EnablementState::Inactive,
            other => {
                return Err(sqlx::Error::ColumnDecode {
                    index: "state".into(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Unknown state: {}", other),
                    )),
                });
            }
        };

        let created_at = row
            .try_get::<Option<String>, _>("created_at")?
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let created_by =
            Uuid::parse_str(&row.try_get::<String, _>("created_by")?).map_err(|e| {
                sqlx::Error::ColumnDecode {
                    index: "created_by".into(),
                    source: Box::new(e),
                }
            })?;

        let updated_at = row
            .try_get::<Option<String>, _>("updated_at")?
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let updated_by =
            Uuid::parse_str(&row.try_get::<String, _>("updated_by")?).map_err(|e| {
                sqlx::Error::ColumnDecode {
                    index: "updated_by".into(),
                    source: Box::new(e),
                }
            })?;

        Ok(OurAuthFactorState(AuthFactorState::<OurBackend> {
            id: row.try_get::<String, _>("id")?,
            factor_id,
            tenant_id,
            user_id,
            state,
            config,
            created_at,
            created_by,
            updated_at,
            updated_by,
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
        // parse id with mapped error
        let id_str: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::ColumnDecode {
            index: "id".into(),
            source: Box::new(e),
        })?;

        // parse factors JSON defensively and map serde errors
        let factors: Vec<_> = match row.try_get::<Option<String>, _>("factors")? {
            Some(s) if !s.trim().is_empty() => {
                serde_json::from_str(&s).map_err(|e| sqlx::Error::ColumnDecode {
                    index: "factors".into(),
                    source: Box::new(e),
                })?
            }
            _ => Vec::new(),
        };

        let created_at = row
            .try_get::<Option<String>, _>("created_at")?
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let created_by_str: String = row.try_get("created_by")?;
        let created_by =
            Uuid::parse_str(&created_by_str).map_err(|e| sqlx::Error::ColumnDecode {
                index: "created_by".into(),
                source: Box::new(e),
            })?;

        let updated_at = row
            .try_get::<Option<String>, _>("updated_at")?
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let updated_by_str: String = row.try_get("updated_by")?;
        let updated_by =
            Uuid::parse_str(&updated_by_str).map_err(|e| sqlx::Error::ColumnDecode {
                index: "updated_by".into(),
                source: Box::new(e),
            })?;

        Ok(OurAuthMethod(AuthMethod::<OurBackend> {
            id,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            factors,
            created_at,
            created_by,
            updated_at,
            updated_by,
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
        let id_str: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::ColumnDecode {
            index: "id".into(),
            source: Box::new(e),
        })?;

        let method_id_str: String = row.try_get("method_id")?;
        let method_id = Uuid::parse_str(&method_id_str).map_err(|e| sqlx::Error::ColumnDecode {
            index: "method_id".into(),
            source: Box::new(e),
        })?;

        let tenant_id = row
            .try_get::<Option<String>, _>("tenant_id")?
            .and_then(|s| Uuid::parse_str(&s).ok());

        let user_id = row
            .try_get::<Option<String>, _>("user_id")?
            .and_then(|s| Uuid::parse_str(&s).ok());

        let state_txt: String = row.try_get("state")?;
        let state = match state_txt.as_str() {
            "Active" => EnablementState::Active,
            "Inactive" => EnablementState::Inactive,
            other => {
                return Err(sqlx::Error::ColumnDecode {
                    index: "state".into(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Unknown method state: {}", other),
                    )),
                });
            }
        };

        let created_at = row
            .try_get::<Option<String>, _>("created_at")?
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let created_by_str: String = row.try_get("created_by")?;
        let created_by =
            Uuid::parse_str(&created_by_str).map_err(|e| sqlx::Error::ColumnDecode {
                index: "created_by".into(),
                source: Box::new(e),
            })?;

        let updated_at = row
            .try_get::<Option<String>, _>("updated_at")?
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let updated_by_str: String = row.try_get("updated_by")?;
        let updated_by =
            Uuid::parse_str(&updated_by_str).map_err(|e| sqlx::Error::ColumnDecode {
                index: "updated_by".into(),
                source: Box::new(e),
            })?;

        Ok(OurAuthMethodState(AuthMethodState::<OurBackend> {
            id,
            method_id,
            tenant_id,
            user_id,
            state,
            created_at,
            created_by,
            updated_at,
            updated_by,
        }))
    }
}
