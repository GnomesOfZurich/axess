//! Factor definitions, state transitions, and configuration helpers.
//!
//! This module centralizes factor-related types used across Axess:
//! - [`AuthFactorKind`] enumerates supported factor kinds.
//! - [`FactorInstance`] represents provisioned factors stored by backends.
//! - [`FactorState`] and [`FactorStateChange`] capture per-scope enablement metadata,
//!   with the latter providing ergonomic helpers for constructing strongly typed
//!   factor configurations (password, OTP, OAuth, etc.).
//!
//! Higher-level flows (e.g. `AuthSession`) rely on these structures to provision,
//! activate, and verify authentication factors in a consistent, replay-safe way.

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
use serde_json::Value as JsonValue;
use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    str::FromStr,
};

/// Enumerates the supported kinds of authentication factors in Axess.
///
/// This enum is used to distinguish between different factor types in authentication flows,
/// configuration, and backend logic. Each variant corresponds to a distinct credential or
/// verification mechanism.
///
/// # Variants
/// - `Password`: Standard password-based authentication.
/// - `Otp`: One-time password (TOTP/HOTP) authentication.
/// - `Oauth`: OAuth/OpenID Connect or similar federated authentication.
/// - `Custom(String)`: Custom or vendor-specific factor kind, identified by a string.
///
/// # Usage
/// Use `AuthFactorKind` to select, provision, and verify factors in session flows,
/// backend queries, and configuration builders. The `Custom` variant allows for
/// extensibility and integration with non-standard or external factor types.
///
/// # Examples
/// ```rust
/// use axess_core::authn::methods::factor::AuthFactorKind;
///
/// let kind = AuthFactorKind::Password;
/// assert_eq!(kind.as_str(), "password");
///
/// let custom_kind = AuthFactorKind::Custom("webauthn".to_string());
/// assert_eq!(custom_kind.as_str(), "webauthn");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AuthFactorKind {
    /// Standard password-based authentication.
    Password,
    /// One-time password (TOTP/HOTP) authentication.
    Otp,
    /// OAuth/OpenID Connect or similar federated authentication.
    Oauth,
    /// Custom or vendor-specific factor kind, identified by a string.
    Custom(String),
}

impl AuthFactorKind {
    /// Returns the canonical string representation of the factor kind.
    ///
    /// This is used for serialization, logging, and backend queries.
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

/// Represents the persisted state of an authentication factor for a specific scope.
///
/// This struct is stored in the backend and tracks the enablement state, configuration,
/// and audit metadata for a factor instance. Each factor state is uniquely identified
/// by its composite key (factor_id, tenant_id, user_id).
///
/// # Fields
/// - `id`: Unique identifier for this factor state (usually a UUID or database key).
/// - `factor_id`: The ID of the factor this state belongs to.
/// - `tenant_id`: Optional tenant scope; `None` for global factors.
/// - `user_id`: Optional user scope; `None` for tenant/global factors.
/// - `state`: The enablement state (e.g., Pending, Active, Inactive).
/// - `config`: Configuration map for factor-specific settings (e.g., password hash, OTP secret).
/// - `created_at`: Timestamp when this state was created.
/// - `created_by`: Who created this state.
/// - `updated_at`: Timestamp of last update.
/// - `updated_by`: Who last updated this state.
///
/// # Usage
/// Use `FactorState` to query, audit, and update factor enablement and configuration.
/// For upserts, use [`FactorStateChange`] to describe the desired change, then persist
/// as a new or updated `FactorState`.
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
    /// Unique identifier for this factor state (e.g., UUID or database key).
    pub id: D,
    /// The ID of the factor this state belongs to.
    pub factor_id: F,
    /// Optional tenant scope; `None` for global factors.
    pub tenant_id: Option<T>,
    /// Optional user scope; `None` for tenant/global factors.
    pub user_id: Option<U>,
    /// The enablement state (Pending, Active, Inactive, etc.).
    pub state: EnablementState,
    /// Configuration map for factor-specific settings (password hash, OTP secret, etc.).
    pub config: HashMap<String, JsonValue>,
    /// Timestamp when this state was created.
    pub created_at: DateTime<Utc>,
    /// Who created this state.
    pub created_by: U,
    /// Timestamp of last update.
    pub updated_at: DateTime<Utc>,
    /// Who last updated this state.
    pub updated_by: U,
}

impl<D, F, T, U> FactorState<D, F, T, U>
where
    D: DataId,
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    /// Creates a new `FactorState` with default values.
    ///
    /// Sets `state` to `Pending` and initializes timestamps.
    pub fn new(id: D, factor_id: F, created_by: U) -> Self {
        let time_now = Utc::now();
        Self {
            id,
            factor_id,
            tenant_id: None,
            user_id: None,
            state: EnablementState::Pending,
            config: HashMap::new(),
            created_at: time_now,
            created_by: created_by.clone(),
            updated_at: time_now,
            updated_by: created_by,
        }
    }

    /// Sets the configuration map for this factor state.
    pub fn with_config(mut self, config: HashMap<String, JsonValue>) -> Self {
        self.config = config;
        self
    }

    /// Sets the enablement state for this factor state.
    pub fn with_state(mut self, state: EnablementState) -> Self {
        self.state = state;
        self
    }

    /// Returns a reference to the value for the given config key, if present.
    pub fn get_config_value(&self, key: &str) -> Option<&JsonValue> {
        self.config.get(key)
    }

    /// Returns the [`PermissionScope`] for this factor state (global, tenant, or user).
    pub fn scope(&self) -> PermissionScope<T, U> {
        match (&self.tenant_id, &self.user_id) {
            (None, None) => PermissionScope::Global,
            (Some(tid), None) => PermissionScope::Tenant(tid.clone()),
            (Some(tid), Some(uid)) => PermissionScope::User(tid.clone(), uid.clone()),
            (None, Some(_)) => {
                error!("user_id without tenant_id should not occur");
                unreachable!("user_id without tenant_id should not occur")
            }
        }
    }
}

/// Represents a desired change to a factor's state and configuration.
///
/// This struct is used to describe updates or insertions of factor states in the backend.
/// Unlike [`FactorState`], it does not include an ID or audit fields, as those are managed by the backend.
/// It is typically constructed when provisioning, enabling, disabling, or updating a factor for a user or tenant.
///
/// # Fields
/// - `factor_id`: The ID of the factor to change.
/// - `tenant_id`: Optional tenant scope; `None` for global factors.
/// - `user_id`: Optional user scope; `None` for tenant/global factors.
/// - `state`: The new enablement state (e.g., Pending, Active, Inactive).
/// - `config`: Configuration map for factor-specific settings (e.g., password hash, OTP secret).
///
/// # Usage
/// Use `FactorStateChange` when you want to upsert (insert or update) a factor state in the backend.
/// Construct it using the builder-style methods (`with_scope`, `with_state`, `with_config`, etc.)
/// and pass it to your backend's `upsert_factor_state` method.
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::{factor::FactorStateChange, policy::FactorConfigBuilder, scope::{EnablementState, PermissionScope}};
///
/// let factor_id = 42_u64;
/// let tenant_id = 1_u64;
/// let user_id = 2_u64;
///
/// let change = FactorStateChange::new(factor_id)
///     .with_scope(PermissionScope::User(tenant_id, user_id))
///     .with_state(EnablementState::Active)
///     .with_config(FactorConfigBuilder::password("hash123").into());
/// ```
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
    /// The ID of the factor to change.
    pub factor_id: F,
    /// Optional tenant scope; `None` for global factors.
    pub tenant_id: Option<T>,
    /// Optional user scope; `None` for tenant/global factors.
    pub user_id: Option<U>,
    /// The new enablement state (Pending, Active, Inactive, etc.).
    pub state: EnablementState,
    /// Configuration map for factor-specific settings (password hash, OTP secret, etc.).
    pub config: HashMap<String, JsonValue>,
}

impl<F, T, U> FactorStateChange<F, T, U>
where
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    /// Creates a new `FactorStateChange` for the given factor.
    ///
    /// By default, sets the state to `Active` and leaves scope/config empty.
    pub fn new(factor_id: F) -> Self {
        Self {
            factor_id,
            tenant_id: None,
            user_id: None,
            state: EnablementState::Active,
            config: HashMap::new(),
        }
    }

    /// Sets the scope (global, tenant, or user) for this change.
    ///
    /// This will populate `tenant_id` and `user_id` according to the provided [`PermissionScope`].
    pub fn with_scope(mut self, scope: PermissionScope<T, U>) -> Self {
        self.tenant_id = scope.tenant_id().cloned();
        self.user_id = scope.user_id().cloned();
        self
    }

    /// Sets the enablement state for this change.
    ///
    /// Use this to activate, deactivate, or suspend a factor.
    pub fn with_state(mut self, state: EnablementState) -> Self {
        self.state = state;
        self
    }

    /// Sets the configuration map for this change.
    ///
    /// Use this to provide factor-specific settings, such as password hashes or OTP secrets.
    pub fn with_config(mut self, config: HashMap<String, JsonValue>) -> Self {
        self.config = config;
        self
    }

    /// Adds or updates a single config JsonValue for this change.
    ///
    /// This is useful for incremental construction or mutation of the config.
    pub fn add_config_value(mut self, key: String, value: JsonValue) -> Self {
        self.config.insert(key, value);
        self
    }
}

impl<D, F, T, U> From<&FactorState<D, F, T, U>> for FactorStateChange<F, T, U>
where
    D: DataId,
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    /// Converts a persisted [`FactorState`] into a change intent.
    ///
    /// This is useful for updating or cloning an existing factor state.
    fn from(state: &FactorState<D, F, T, U>) -> Self {
        FactorStateChange {
            factor_id: state.factor_id.clone(),
            tenant_id: state.tenant_id.clone(),
            user_id: state.user_id.clone(),
            state: state.state.clone(),
            config: state.config.clone(),
        }
    }
}

/// Represents a provisioned authentication factor for a user or tenant.
///
/// This struct is persisted in the backend and describes the metadata for an authentication factor,
/// such as its kind (password, OTP, OAuth, etc.), display name, description, and audit fields.
/// Each `FactorInstance` is uniquely identified by its `id` and is associated with a specific user or tenant.
///
/// # Fields
/// - `id`: Unique identifier for this factor instance (usually a UUID or database key).
/// - `kind`: The kind of factor (e.g., Password, Otp, Oauth, Custom).
/// - `name`: Human-readable name for the factor (e.g., "Password", "Authenticator App").
/// - `description`: Optional description or display text for the factor.
/// - `created_at`: Timestamp when this factor was created.
/// - `created_by`: Who created this factor.
/// - `updated_at`: Timestamp of last update.
/// - `updated_by`: Who last updated this factor.
///
/// # Usage
/// Use `FactorInstance` to enumerate available authentication factors for a user or tenant,
/// display factor options in setup/verification flows, and manage factor metadata in the backend.
/// The associated state and configuration for a factor are tracked separately via [`FactorState`] and [`FactorStateChange`].
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::factor::{AuthFactorKind, FactorInstance};
///
/// let factor = FactorInstance::new(
///     1_u64,
///     AuthFactorKind::Password,
///     "Password",
///     "Primary login password",
///     42_u64,
/// );
/// assert_eq!(factor.kind, AuthFactorKind::Password);
/// assert_eq!(factor.name, "Password");
/// assert_eq!(factor.description, "Primary login password");
/// ```
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
    /// Unique identifier for this factor instance (e.g., UUID or database key).
    pub id: F,
    /// The kind of factor (e.g., Password, Otp, Oauth, Custom).
    pub kind: AuthFactorKind,
    /// Human-readable name for the factor (e.g., "Password", "Authenticator App").
    pub name: String,
    /// Optional description or display text for the factor.
    pub description: String,
    /// Timestamp when this factor was created.
    pub created_at: DateTime<Utc>,
    /// Who created this factor.
    pub created_by: U,
    /// Timestamp of last update.
    pub updated_at: DateTime<Utc>,
    /// Who last updated this factor.
    pub updated_by: U,
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
    fn factor_state_change_with_password_hash() {
        let change = FactorStateChange::new(10_u64)
            .with_scope(PermissionScope::User(1_u64, 2_u64))
            .with_state(EnablementState::Active)
            .with_config(FactorConfigBuilder::password("hash123").into());
        assert_eq!(change.state, EnablementState::Active);
        assert_eq!(change.config.get("password_hash"), Some(&json!("hash123")));
        assert_eq!(change.tenant_id, Some(1_u64));
        assert_eq!(change.user_id, Some(2_u64));
    }

    #[test]
    /// Verifies TOTP settings are serialized into the config map.
    fn factor_state_change_with_totp_config() {
        let config: HashMap<String, JsonValue> = FactorConfigBuilder::totp("BASE32SECRET")
            .with_length(8)
            .with_period(60)
            .with_windows(2, 1)
            .with_last_totp_step(42)
            .into();
        let change = FactorStateChange::<u64, u64, u64>::new(10_u64)
            .with_state(EnablementState::Pending)
            .with_config(config);

        assert_eq!(change.state, EnablementState::Pending);
        assert_eq!(change.config.get("otp_type"), Some(&json!("totp")));
        assert_eq!(change.config.get("secret"), Some(&json!("BASE32SECRET")));
        assert_eq!(change.config.get("length"), Some(&json!(8)));
        assert_eq!(change.config.get("period"), Some(&json!(60)));
        assert_eq!(change.config.get("past_window"), Some(&json!(2)));
        assert_eq!(change.config.get("future_window"), Some(&json!(1)));
        assert_eq!(change.config.get("last_totp_step"), Some(&json!(42)));
    }

    #[test]
    /// Verifies HOTP defaults carry counter/window fields.
    fn factor_state_change_with_hotp_config() {
        let config: HashMap<String, JsonValue> = FactorConfigBuilder::hotp("HOTSECRET")
            .with_length(7)
            .with_field("counter", json!(3))
            .with_field("window", json!(12))
            .into();
        let change = FactorStateChange::<u64, u64, u64>::new(11_u64)
            .with_state(EnablementState::Active)
            .with_config(config);

        assert_eq!(change.state, EnablementState::Active);
        assert_eq!(change.config.get("otp_type"), Some(&json!("hotp")));
        assert_eq!(change.config.get("secret"), Some(&json!("HOTSECRET")));
        assert_eq!(change.config.get("length"), Some(&json!(7)));
        assert_eq!(change.config.get("counter"), Some(&json!(3)));
        assert_eq!(change.config.get("window"), Some(&json!(12)));
        assert!(change.config.get("period").is_none());
    }
}
