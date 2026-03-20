//! Factor definitions, state transitions, and configuration helpers.
//!
//! This module centralizes factor-related types used across Axess:
//! - [`Kind`] enumerates supported factor kinds.
//! - [`FactorInstance`] represents provisioned factors stored by backends.
//! - [`FactorState`] and [`FactorStateChange`] capture per-scope enablement metadata,
//!   with the latter providing ergonomic helpers for constructing strongly typed
//!   factor configurations (password, OTP, OAuth, etc.).
//!
//! Higher-level flows (e.g. `AuthSession`) rely on these structures to provision,
//! activate, and verify authentication factors in a consistent, replay-safe way.

use crate::{
    authn::{
        backend::{AuthId, TenantId, UserId},
        errors::FactorKindError,
        methods::{
            form::{Action, Flow},
            scope::{AuthnScope, EnablementState},
        },
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum FederatedProtocol {
    OAuth2,
    OIDC,
    SAML,
}

// Manual implementation of Hash for FederatedProvider, since HashMap is not Hash.
// We only hash the name and protocol for Custom, ignoring config for Hash/PartialEq/Eq.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FederatedProvider {
    Github,
    Google,
    Facebook,
    AzureAD,
    Auth0,
    Custom {
        name: String,
        protocol: FederatedProtocol,
        config: HashMap<String, serde_json::Value>,
    },
}

impl std::hash::Hash for FederatedProvider {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        use FederatedProvider::*;
        match self {
            Github => "Github".hash(state),
            Google => "Google".hash(state),
            Facebook => "Facebook".hash(state),
            AzureAD => "AzureAD".hash(state),
            Auth0 => "Auth0".hash(state),
            Custom { name, protocol, .. } => {
                "Custom".hash(state);
                name.hash(state);
                protocol.hash(state);
                // config is intentionally not hashed (for now...)
            }
        }
    }
}

impl FederatedProvider {
    /// Returns the canonical string representation of the federated provider.
    pub fn as_str(&self) -> &str {
        match self {
            FederatedProvider::Github => "github",
            FederatedProvider::Google => "google",
            FederatedProvider::Facebook => "facebook",
            FederatedProvider::AzureAD => "azuread",
            FederatedProvider::Auth0 => "auth0",
            FederatedProvider::Custom { name, .. } => name.as_str(),
        }
    }
}

impl FromStr for FederatedProvider {
    type Err = FactorKindError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "github" => Ok(FederatedProvider::Github),
            "google" => Ok(FederatedProvider::Google),
            "facebook" => Ok(FederatedProvider::Facebook),
            "azuread" => Ok(FederatedProvider::AzureAD),
            "auth0" => Ok(FederatedProvider::Auth0),
            other => Ok(FederatedProvider::Custom {
                name: other.to_string(),
                protocol: FederatedProtocol::OIDC, // or OAuth2, or configurable
                config: HashMap::new(),
            }),
        }
    }
}

/// Enumerates the supported kinds of authentication factors in Axess.
///
/// This enum is used to distinguish between different factor types in authentication flows,
/// configuration, and backend logic. Each variant corresponds to a distinct credential or
/// verification mechanism.
///
/// # Variants
/// - `Password`: Standard password-based authentication.
/// - `Totp`: One-time password (TOTP) authentication.
/// - `Hotp`: HMAC-based one-time password (HOTP) authentication.
/// - `EmailOtp`: One-time password sent via email.
/// - `OauthProvider(String)`: OAuth-based federated authentication.
/// - `OidcProvider(String)`: OpenID Connect-based federated authentication.
///
/// # Usage
/// Use `Kind` to select, provision, and verify factors in session flows,
/// backend queries, and configuration builders.
///
/// # Examples
/// ```rust
/// use axess_core::authn::methods::factor::{FederatedProvider, Kind};
///
/// let password_factor_kind = Kind::Password;
/// assert_eq!(password_factor_kind.as_str(), "password");
///
/// let oauth_factor_kind = Kind::Federated(FederatedProvider::Github);
/// assert_eq!(oauth_factor_kind.as_str(), "github");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    // High-level flow type for this factor kind.
    Workflow,

    // // Knowledge based factors
    Password,
    // Pin,
    // FactorKind,

    //
    Totp,
    Hotp,
    EmailOtp,
    // SmsOtp,
    // MagicLink,
    // YubikeyOtp,

    // // Crypto
    // WebAuthn,
    // U2f,
    // Smartcard,

    // Federated (OAuth/OpenID Connect or similar federated authentication)
    Federated(FederatedProvider),
}

impl Kind {
    /// Returns the canonical string representation of the factor kind.
    pub fn as_str(&self) -> &str {
        match self {
            Kind::Workflow => "workflow",
            Kind::Password => "password",
            Kind::Totp => "totp",
            Kind::Hotp => "hotp",
            Kind::EmailOtp => "email_otp",
            Kind::Federated(provider) => provider.as_str(),
        }
    }

    /// Returns the high-level flow type for this factor kind.
    pub fn flow_type(&self) -> &Flow {
        match self {
            Kind::Workflow => &Flow::Workflow,
            Kind::Password => &Flow::Knowledge,
            Kind::Totp | Kind::Hotp | Kind::EmailOtp => &Flow::Otp,
            Kind::Federated(_) => &Flow::Federated,
        }
    }

    /// Convenience constructor for federated providers.
    pub fn from_provider_str(s: &str) -> Self {
        Kind::Federated(FederatedProvider::from_str(s).unwrap_or_else(|_| {
            FederatedProvider::Custom {
                name: s.to_string(),
                protocol: FederatedProtocol::OIDC,
                config: HashMap::new(),
            }
        }))
    }
}

impl FromStr for Kind {
    type Err = FactorKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "workflow" => Ok(Kind::Workflow),
            "password" => Ok(Kind::Password),
            "totp" => Ok(Kind::Totp),
            "hotp" => Ok(Kind::Hotp),
            "email_otp" => Ok(Kind::EmailOtp),
            provider => Ok(Kind::from_provider_str(provider)),
        }
    }
}

impl Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Operation {
    pub kind: Kind,
    pub action: Action,
}

impl Operation {
    pub fn new(kind: Kind, action: Action) -> Self {
        Self { kind, action }
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
    serialize = "A: Serialize, T: Serialize, U: Serialize",
    deserialize = "A: DeserializeOwned, T: DeserializeOwned, U: DeserializeOwned"
))]
pub struct FactorState<A, T, U>
where
    A: AuthId,
    T: TenantId,
    U: UserId,
{
    /// Unique identifier for this factor state (e.g., UUID or database key).
    pub id: A,
    /// The ID of the factor this state belongs to.
    pub factor_id: A,
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

impl<A, T, U> FactorState<A, T, U>
where
    A: AuthId,
    T: TenantId,
    U: UserId,
{
    /// Creates a new `FactorState` with default values.
    ///
    /// Sets `state` to `Pending` and initializes timestamps.
    pub fn new(id: A, factor_id: A, created_by: U) -> Self {
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

    /// Returns the [`AuthnScope`] for this factor state (global, tenant, or user).
    pub fn scope(&self) -> AuthnScope<T, U> {
        match (&self.tenant_id, &self.user_id) {
            (None, None) => AuthnScope::Global,
            (Some(tid), None) => AuthnScope::Tenant(tid.clone()),
            (Some(tid), Some(uid)) => AuthnScope::User(tid.clone(), uid.clone()),
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
/// use axess_core::authn::methods::{factor::FactorStateChange, policy::FactorConfigBuilder, scope::{EnablementState, AuthnScope}};
///
/// let factor_id = 42_u64;
/// let tenant_id = 1_u64;
/// let user_id = 2_u64;
///
/// let change = FactorStateChange::new(factor_id)
///     .with_scope(AuthnScope::User(tenant_id, user_id))
///     .with_state(EnablementState::Active)
///     .with_config(FactorConfigBuilder::password("hash123").into());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "A: Serialize, T: Serialize, U: Serialize",
    deserialize = "A: DeserializeOwned, T: DeserializeOwned, U: DeserializeOwned"
))]
pub struct FactorStateChange<A, T, U>
where
    A: AuthId,
    T: TenantId,
    U: UserId,
{
    /// The ID of the factor to change.
    pub factor_id: A,
    /// Optional tenant scope; `None` for global factors.
    pub tenant_id: Option<T>,
    /// Optional user scope; `None` for tenant/global factors.
    pub user_id: Option<U>,
    /// The new enablement state (Pending, Active, Inactive, etc.).
    pub state: EnablementState,
    /// Configuration map for factor-specific settings (password hash, OTP secret, etc.).
    pub config: HashMap<String, JsonValue>,
}

impl<A, T, U> FactorStateChange<A, T, U>
where
    A: AuthId,
    T: TenantId,
    U: UserId,
{
    /// Creates a new `FactorStateChange` for the given factor.
    ///
    /// By default, sets the state to `Active` and leaves scope/config empty.
    pub fn new(factor_id: A) -> Self {
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
    /// This will populate `tenant_id` and `user_id` according to the provided [`AuthnScope`].
    pub fn with_scope(mut self, scope: AuthnScope<T, U>) -> Self {
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

impl<A, T, U> From<&FactorState<A, T, U>> for FactorStateChange<A, T, U>
where
    A: AuthId,
    T: TenantId,
    U: UserId,
{
    /// Converts a persisted [`FactorState`] into a change intent.
    ///
    /// This is useful for updating or cloning an existing factor state.
    fn from(state: &FactorState<A, T, U>) -> Self {
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
/// use axess_core::authn::methods::factor::{Kind, FactorInstance};
///
/// let factor = FactorInstance::new(
///     1_u64,
///     Kind::Password,
///     "Password",
///     "Primary login password",
///     42_u64,
/// );
/// assert_eq!(factor.kind, Kind::Password);
/// assert_eq!(factor.name, "Password");
/// assert_eq!(factor.description, "Primary login password");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound(
    serialize = "A: Serialize, U: Serialize",
    deserialize = "A: DeserializeOwned, U: DeserializeOwned"
))]
pub struct FactorInstance<A, U>
where
    A: AuthId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
{
    /// Unique identifier for this factor instance (e.g., UUID or database key).
    pub id: A,
    /// The kind of factor (e.g., Password, Otp, Oauth, Custom).
    pub kind: Kind,
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

impl<A, U> FactorInstance<A, U>
where
    A: AuthId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
{
    pub fn new(id: A, kind: Kind, name: &str, description: &str, created_by: U) -> Self {
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

    // pub fn get_name(&self) -> &str {
    //     &self.name
    // }

    pub fn get_kind(&self) -> &Kind {
        &self.kind
    }

    pub fn get_flow(&self) -> &Flow {
        self.kind.flow_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authn::methods::{policy::FactorConfigBuilder, scope::AuthnScope};
    use serde_json::json;

    #[test]
    /// Ensures the convenience constructor sets kind/name/description correctly.
    fn factor_instance_password_helper_sets_kind() {
        let factor = FactorInstance::new(1_u64, Kind::Password, "pwd", "desc", 7_u64);
        assert_eq!(factor.kind, Kind::Password);
        assert_eq!(factor.name, "pwd");
        assert_eq!(factor.description, "desc");
    }

    #[test]
    /// Confirms password state changes carry scope and the hash field.
    fn factor_state_change_with_password_hash() {
        let change = FactorStateChange::new(10_u64)
            .with_scope(AuthnScope::User(1_u64, 2_u64))
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
        assert_eq!(change.config.get("kind"), Some(&json!("totp")));
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
        assert_eq!(change.config.get("kind"), Some(&json!("hotp")));
        assert_eq!(change.config.get("secret"), Some(&json!("HOTSECRET")));
        assert_eq!(change.config.get("length"), Some(&json!(7)));
        assert_eq!(change.config.get("counter"), Some(&json!(3)));
        assert_eq!(change.config.get("window"), Some(&json!(12)));
        assert!(change.config.get("period").is_none());
    }
}
