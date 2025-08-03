use crate::authn::{
    backend::{EntityState, FactorId, MethodId, TenantId, UserId},
    methods::{
        factor::{AuthFactorKind, FactorInstance},
        method::MethodInstance,
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "M: Serialize, F: Serialize, U: Serialize",
    deserialize = "M: DeserializeOwned, F: DeserializeOwned, U: DeserializeOwned"
))]
pub struct PartialAuthState<M, F, U>
where
    M: MethodId + serde::de::DeserializeOwned + serde::Serialize,
    F: FactorId + serde::de::DeserializeOwned + serde::Serialize,
    U: UserId + serde::de::DeserializeOwned + serde::Serialize,
{
    pub current_method: MethodInstance<M, F, U>,
    pub remaining_factors: Vec<FactorInstance<F, U>>,
    pub attempt_count: u32,
    pub last_attempt: Option<DateTime<Utc>>,
}

impl<M, F, U> PartialAuthState<M, F, U>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
{
    pub fn new(method: MethodInstance<M, F, U>) -> Self {
        Self {
            current_method: method,
            remaining_factors: Vec::new(),
            attempt_count: 0,
            last_attempt: None,
        }
    }

    pub fn apply_factor(&mut self, factor_id: &F) -> Self {
        self.remaining_factors.retain(|f| &f.id != factor_id);
        self.clone()
    }

    /// Returns the kind of the next required factor, if any.
    pub fn next_factor_kind(&self) -> Option<AuthFactorKind> {
        self.remaining_factors.first().map(|f| f.kind.clone())
    }

    /// Returns the id of the next required factor, if any.
    pub fn next_factor_id(&self) -> Option<&F> {
        self.remaining_factors.first().map(|f| &f.id)
    }

    pub fn is_complete(&self) -> bool {
        self.remaining_factors.is_empty()
    }

    pub fn increment_attempt(&mut self) -> Self {
        self.attempt_count += 1;
        self.last_attempt = Some(Utc::now());
        self.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "M: Serialize, F: Serialize, U: Serialize",
    deserialize = "M: DeserializeOwned, F: DeserializeOwned, U: DeserializeOwned"
))]
pub enum AuthState<M, F, U>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
{
    NotAuthenticated,
    PartialAuthn(PartialAuthState<M, F, U>),
    Authenticated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound(
    serialize = "M: Serialize, F: Serialize, U: Serialize, T: Serialize",
    deserialize = "M: DeserializeOwned, F: DeserializeOwned, U: DeserializeOwned, T: DeserializeOwned"
))]
pub struct Data<M, F, U, T>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
    T: TenantId,
{
    pub tenant_id: Option<T>,                    // Tenant ID if applicable
    pub user_id: Option<U>,                      // User ID if authenticated
    pub user_state: EntityState,                 // Current user state
    pub auth_state: AuthState<M, F, U>,          // Current authentication state
    pub auth_hash: Option<String>,               // Hash of the authentication state
    pub custom_data: HashMap<String, JsonValue>, // Additional custom session data
}

impl<M, F, U, T> Data<M, F, U, T>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
    T: TenantId,
{
    pub fn new(
        tenant_id: Option<T>,
        user_id: Option<U>,
        user_state: EntityState,
        auth_state: AuthState<M, F, U>,
        auth_hash: Option<String>,
        custom_data: HashMap<String, JsonValue>,
    ) -> Self {
        Self {
            tenant_id,
            user_id,
            user_state,
            auth_state,
            auth_hash,
            custom_data,
        }
    }
}

impl<M, F, U, T> Default for Data<M, F, U, T>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
    T: TenantId,
{
    fn default() -> Self {
        Self {
            tenant_id: None,                                    // Default tenant ID
            user_id: None,                                      // Default user ID
            user_state: EntityState::Guest,                     // Default user state
            auth_state: AuthState::<M, F, U>::NotAuthenticated, // Default authentication state
            auth_hash: None,
            custom_data: HashMap::new(), // Default empty custom data
        }
    }
}
