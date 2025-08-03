use crate::{
    authn::{
        backend::{DataId, FactorId, MethodId, TenantId, UserId},
        methods::scope::{EnablementState, PermissionScope},
    },
    tracing::error,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt::Debug;

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct MethodState<D, M, U, T>
where
    D: DataId,
    M: MethodId,
    U: UserId,
    T: TenantId,
{
    pub id: D,
    pub method_id: M,
    pub tenant_id: Option<T>,
    pub user_id: Option<U>,
    pub state: EnablementState, // Represents the current state of the method (e.g., "pending", "active", etc.)
    pub created_at: DateTime<Utc>, // Timestamp of creation
    pub created_by: U,          // Who created this factor
    pub updated_at: DateTime<Utc>, // Timestamp of last update
    pub updated_by: U,          // Who last updated this factor
}

impl<D, M, U, T> MethodState<D, M, U, T>
where
    D: DataId,
    M: MethodId,
    U: UserId,
    T: TenantId,
{
    pub fn new(id: D, method_id: M, created_by: U) -> Self {
        let time_now = Utc::now();
        Self {
            id,
            method_id,
            tenant_id: None,
            user_id: None,
            state: EnablementState::Pending,
            created_at: time_now,
            created_by: created_by.clone(),
            updated_at: time_now,
            updated_by: created_by,
        }
    }

    pub fn with_state(mut self, state: EnablementState) -> Self {
        self.state = state;
        self
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
    serialize = "M: Serialize, F: Serialize, U: Serialize",
    deserialize = "M: DeserializeOwned, F: DeserializeOwned, U: DeserializeOwned"
))]
pub struct MethodInstance<M, F, U>
where
    M: MethodId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
    F: FactorId + Serialize + DeserializeOwned,
{
    pub id: M,
    pub name: String,
    pub description: String,
    pub factors: Vec<F>,
    pub created_at: DateTime<Utc>,
    pub created_by: U,
    pub updated_at: DateTime<Utc>,
    pub updated_by: U,
}

impl<M, F, U> MethodInstance<M, F, U>
where
    M: MethodId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
    F: FactorId + Serialize + DeserializeOwned,
{
    pub fn new(id: M, name: &str, description: &str, factors: Vec<F>, created_by: U) -> Self {
        let time_now = Utc::now();
        Self {
            id,
            name: name.to_string(),
            description: description.to_string(),
            factors,
            created_at: time_now,
            created_by: created_by.clone(),
            updated_at: time_now,
            updated_by: created_by,
        }
    }
}
