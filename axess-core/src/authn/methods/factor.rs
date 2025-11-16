//! Factor definitions, state transitions, and configuration helpers.
//!
//! This module centralizes factor-related types used across Axess:
//! - [`AuthFactorKind`] enumerates supported factor kinds.
//! - [`FactorInstance`] represents provisioned factors stored by backends.
//! - [`FactorState`] and [`FactorStateChange`] capture per-scope enablement metadata.
//! - [`FactorConfigBuilder`] and [`FactorStateChangeBuilder`] provide ergonomic helpers
//!   for constructing strongly typed factor configurations (password, OTP, OAuth, etc.).
//!
//! Higher-level flows (e.g. `AuthSession`) rely on these structures to provision,
//! activate, and verify authentication factors in a consistent, replay-safe way.

use crate::{
    authn::{
        backend::{DataId, FactorId, TenantId, UserId},
        errors::FactorKindError,
        methods::{
            policy::{FactorConfig, FactorConfigBuilder},
            scope::{EnablementState, PermissionScope},
        },
    },
    tracing::error,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    str::FromStr,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
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
#[derive(Debug, Clone)]
pub struct FactorStateChangeBuilder<F, T, U>
where
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    change: FactorStateChange<F, T, U>,
}

impl<F, T, U> FactorStateChangeBuilder<F, T, U>
where
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    pub fn new(factor_id: F, updated_by: U) -> Self {
        Self {
            change: FactorStateChange::new(factor_id, updated_by),
        }
    }

    fn with_factor_config(mut self, config: FactorConfig) -> Self {
        self.change.config.extend(config.into_inner());
        self
    }

    pub fn with_scope(mut self, scope: PermissionScope<T, U>) -> Self {
        self.change.tenant_id = scope.tenant_id().cloned();
        self.change.user_id = scope.user_id().cloned();
        self
    }

    pub fn with_state(mut self, state: EnablementState) -> Self {
        self.change.state = state;
        self
    }

    pub fn with_config_map(mut self, map: Map<String, Value>) -> Self {
        // Directly extend the internal config map from the serde_json::Map
        self.change.config.extend(map);
        self
    }

    pub fn insert(mut self, key: impl Into<String>, value: Value) -> Self {
        self.change.config.insert(key.into(), value);
        self
    }

    pub fn set_password_hash(self, hash: impl Into<String>) -> Self {
        self.with_factor_config(FactorConfigBuilder::password(hash).build())
    }

    pub fn set_otp_config(self, builder: FactorConfigBuilder) -> Self {
        self.with_factor_config(builder.build())
    }

    pub fn set_totp_config(self, builder: FactorConfigBuilder) -> Self {
        self.set_otp_config(builder)
    }

    pub fn build(self) -> FactorStateChange<F, T, U> {
        self.change
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authn::methods::{policy::FactorConfigBuilder, scope::PermissionScope};
    use serde_json::json;

    #[test]
    /// Ensures the convenience constructor sets kind/name/description correctly.
    fn factor_instance_password_helper_sets_kind() {
        let factor = FactorInstance::new(1_u64, AuthFactorKind::Password, "pwd", "desc", 7_u64);
        assert_eq!(factor.kind, AuthFactorKind::Password);
        assert_eq!(factor.name, "pwd");
        assert_eq!(factor.description, "desc");
    }

    #[test]
    /// Confirms password state changes carry scope and the hash field.
    fn factor_state_change_builder_sets_password_hash() {
        let builder = FactorStateChangeBuilder::new(10_u64, 99_u64)
            .with_scope(PermissionScope::User(1_u64, 2_u64))
            .with_state(EnablementState::Active)
            .set_password_hash("hash123");
        let change = builder.build();
        assert_eq!(change.state, EnablementState::Active);
        assert_eq!(change.config.get("password_hash"), Some(&json!("hash123")));
        assert_eq!(change.tenant_id, Some(1_u64));
        assert_eq!(change.user_id, Some(2_u64));
    }

    #[test]
    /// Verifies TOTP settings are serialized into the config map.
    fn factor_state_change_builder_sets_totp_config() {
        let params = FactorConfigBuilder::totp("BASE32SECRET")
            .with_length(8)
            .with_period(60)
            .with_windows(2, 1)
            .with_last_totp_step(42);
        let change = FactorStateChangeBuilder::<u64, u64, u64>::new(10_u64, 7_u64)
            .with_state(EnablementState::Pending)
            .set_otp_config(params)
            .build();

        assert_eq!(change.state, EnablementState::Pending);
        assert_eq!(change.config.get("otp_type"), Some(&json!("totp")));
        assert_eq!(
            change.config.get("otp_secret"),
            Some(&json!("BASE32SECRET"))
        );
        assert_eq!(change.config.get("length"), Some(&json!(8)));
        assert_eq!(change.config.get("period"), Some(&json!(60)));
        assert_eq!(change.config.get("past_window"), Some(&json!(2)));
        assert_eq!(change.config.get("future_window"), Some(&json!(1)));
        assert_eq!(change.config.get("last_totp_step"), Some(&json!(42)));
    }

    #[test]
    /// Verifies HOTP defaults carry counter/window fields.
    fn factor_state_change_builder_sets_hotp_config() {
        let builder = FactorConfigBuilder::hotp("HOTSECRET")
            .with_length(7)
            .with_field("counter", json!(3))
            .with_field("window", json!(12));
        let change = FactorStateChangeBuilder::<u64, u64, u64>::new(11_u64, 8_u64)
            .with_state(EnablementState::Active)
            .set_otp_config(builder)
            .build();

        assert_eq!(change.state, EnablementState::Active);
        assert_eq!(change.config.get("otp_type"), Some(&json!("hotp")));
        assert_eq!(change.config.get("otp_secret"), Some(&json!("HOTSECRET")));
        assert_eq!(change.config.get("length"), Some(&json!(7)));
        assert_eq!(change.config.get("counter"), Some(&json!(3)));
        assert_eq!(change.config.get("window"), Some(&json!(12)));
        assert!(change.config.get("period").is_none());
    }
}
