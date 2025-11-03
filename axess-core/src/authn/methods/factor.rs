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
#[serde(rename_all = "lowercase")]
pub enum AuthFactorKind {
    Password,
    Otp,
    Oauth,
    Custom(String),
}

impl AuthFactorKind {
    pub fn as_str(&self) -> &str {
        match self {
            AuthFactorKind::Password => "password",
            AuthFactorKind::Otp => "otp",
            AuthFactorKind::Oauth => "oauth",
            AuthFactorKind::Custom(s) => s.as_str(),
        }
    }
}

impl FromStr for AuthFactorKind {
    type Err = FactorKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "password" => Ok(AuthFactorKind::Password),
            "otp" => Ok(AuthFactorKind::Otp),
            "oauth" => Ok(AuthFactorKind::Oauth),
            custom => Ok(AuthFactorKind::Custom(custom.to_string())),
        }
    }
}

impl Display for AuthFactorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// This type doesn't include an ID because the backend generates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "F: Serialize, T: Serialize, U: Serialize",
    deserialize = "F: DeserializeOwned, T: DeserializeOwned, U: DeserializeOwned"
))]
pub struct FactorStateChange<F, T, U>
where
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    pub factor_id: F,
    pub tenant_id: Option<T>,
    pub user_id: Option<U>,
    pub state: EnablementState,
    pub config: HashMap<String, Value>,
    pub updated_by: U,
}

impl<F, T, U> FactorStateChange<F, T, U>
where
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    pub fn new(factor_id: F, updated_by: U) -> Self {
        Self {
            factor_id,
            tenant_id: None,
            user_id: None,
            state: EnablementState::Active,
            config: HashMap::new(),
            updated_by,
        }
    }

    pub fn with_scope(mut self, scope: PermissionScope<T, U>) -> Self {
        self.tenant_id = scope.tenant_id().cloned();
        self.user_id = scope.user_id().cloned();
        self
    }

    pub fn with_state(mut self, state: EnablementState) -> Self {
        self.state = state;
        self
    }

    pub fn with_config(mut self, config: HashMap<String, Value>) -> Self {
        self.config = config;
        self
    }

    pub fn add_config(mut self, key: String, value: Value) -> Self {
        self.config.insert(key, value);
        self
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
