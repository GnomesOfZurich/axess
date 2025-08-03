use crate::{
    authn::{
        backend::{DataId, FactorId, TenantId, UserId},
        errors::FactorKindError,
        methods::scope::{EnablementState, PermissionScope},
    },
    tracing::error,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    str::FromStr,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthFactorKind {
    Password,
    Totp,
    Oauth,
}

impl AuthFactorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthFactorKind::Password => "Password",
            AuthFactorKind::Totp => "Totp",
            AuthFactorKind::Oauth => "oauth",
        }
    }
}

impl FromStr for AuthFactorKind {
    type Err = FactorKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "password" => Ok(AuthFactorKind::Password),
            "totp" => Ok(AuthFactorKind::Totp),
            "oauth" => Ok(AuthFactorKind::Oauth),
            _ => Err(FactorKindError::UnexpectedValue(s.to_string())),
        }
    }
}

impl Display for AuthFactorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthFactorKind::Password => write!(f, "password"),
            AuthFactorKind::Totp => write!(f, "totp"),
            AuthFactorKind::Oauth => write!(f, "oauth"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound(
    serialize = "D: Serialize, F: Serialize, T: Serialize, U: Serialize",
    deserialize = "D: DeserializeOwned, F: DeserializeOwned, T: DeserializeOwned, U: DeserializeOwned"
))]
pub struct FactorState<D, F, T, U>
where
    D: DataId,
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    pub id: D,
    pub factor_id: F,
    pub tenant_id: Option<T>,
    pub user_id: Option<U>,
    pub state: EnablementState, // Represents the current state of the factor (e.g., "pending", "active", etc.)
    pub config: HashMap<String, Value>, // Configuration specific to the factor
    pub created_at: DateTime<Utc>, // Timestamp of creation
    pub created_by: U,          // Who created this factor
    pub updated_at: DateTime<Utc>,
    pub updated_by: U,
}

impl<D, F, T, U> FactorState<D, F, T, U>
where
    D: DataId,
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    pub fn new(id: D, factor_id: F, created_by: U) -> Self {
        let time_now = Utc::now();
        Self {
            id,
            factor_id,
            tenant_id: None,
            user_id: None,
            state: EnablementState::Pending,
            config: HashMap::new(), // Default empty config
            created_at: time_now,
            created_by: created_by.clone(),
            updated_at: time_now,
            updated_by: created_by,
        }
    }

    pub fn with_config(mut self, config: HashMap<String, Value>) -> Self {
        self.config = config;
        self
    }

    pub fn with_state(mut self, state: EnablementState) -> Self {
        self.state = state;
        self
    }

    pub fn get_config_value(&self, key: &str) -> Option<&Value> {
        self.config.get(key)
    }

    pub fn scope(&self) -> PermissionScope<T, U> {
        match (&self.tenant_id, &self.user_id) {
            (None, None) => PermissionScope::Global,
            (Some(tid), None) => PermissionScope::Tenant(tid.clone()),
            (Some(tid), Some(uid)) => PermissionScope::User(tid.clone(), uid.clone()),
            (None, Some(_)) => {
                error!("user_id without tenant_id should not occur");
                // TODO: Handle this case more gracefully in case of corrupt data.
                unreachable!("user_id without tenant_id should not occur")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound(
    serialize = "F: Serialize, U: Serialize",
    deserialize = "F: DeserializeOwned, U: DeserializeOwned"
))]
pub struct FactorInstance<F, U>
where
    F: FactorId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
{
    pub id: F,
    pub kind: AuthFactorKind, // The kind of factor (e.g., Password, Totp, etc.)
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>, // Timestamp of creation
    pub created_by: U,             // Who created this factor
    pub updated_at: DateTime<Utc>, // Timestamp of last update
    pub updated_by: U,             // Who last updated this factor
}

impl<F, U> FactorInstance<F, U>
where
    F: FactorId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
{
    pub fn new(id: F, kind: AuthFactorKind, name: &str, description: &str, created_by: U) -> Self {
        let time_now = Utc::now();
        Self {
            id,
            kind,
            name: name.to_string(),
            description: description.to_string(), // Default empty description
            created_at: time_now,
            created_by: created_by.clone(),
            updated_at: time_now,
            updated_by: created_by,
        }
    }
}
