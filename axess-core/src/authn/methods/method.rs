//! Authentication method primitives and builders.
//!
//! This module defines:
//! - [`MethodStateChange`] / [`MethodState`] for tracking per-scope method enablement.
//! - [`MethodInstance`] as the persisted representation of multi-factor flows.
//! - [`MethodBuilder`] to assemble methods ergonomically from their factor instances.

use crate::{
    authn::{
        backend::{DataId, FactorId, MethodId, TenantId, UserId},
        methods::{
            factor::FactorInstance,
            scope::{EnablementState, PermissionScope},
        },
    },
    tracing::error,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt::Debug;

pub struct MethodStateChange<M, T, U>
where
    M: MethodId,
    T: TenantId,
    U: UserId,
{
    pub method_id: M,
    pub tenant_id: Option<T>,
    pub user_id: Option<U>,
    pub state: EnablementState,
    pub updated_by: U,
}

impl<M, T, U> MethodStateChange<M, T, U>
where
    M: MethodId,
    T: TenantId,
    U: UserId,
{
    pub fn new(method_id: M, updated_by: U) -> Self {
        Self {
            method_id,
            tenant_id: None,
            user_id: None,
            state: EnablementState::Active,
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
}

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct MethodState<D, M, T, U>
where
    D: DataId,
    M: MethodId,
    T: TenantId,
    U: UserId,
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

impl<D, M, T, U> MethodState<D, M, T, U>
where
    D: DataId,
    M: MethodId,
    T: TenantId,
    U: UserId,
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
    pub factors: Vec<FactorInstance<F, U>>,
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
    pub fn new(
        id: M,
        name: &str,
        description: &str,
        factors: Vec<FactorInstance<F, U>>,
        created_by: U,
    ) -> Self {
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

    pub fn get_factor(&self, factor_id: &F) -> Option<&FactorInstance<F, U>> {
        self.factors.iter().find(|factor| &factor.id == factor_id)
    }

    pub fn get_factor_ids(&self) -> Vec<F>
    where
        F: Clone,
    {
        self.factors
            .iter()
            .map(|factor| factor.id.clone())
            .collect()
    }

    pub fn get_first_factor_id(&self) -> Option<F>
    where
        F: Clone,
    {
        self.factors.first().map(|factor| factor.id.clone())
    }

    pub fn has_factor_kind(&self, kind: &crate::authn::methods::AuthFactorKind) -> bool {
        self.factors.iter().any(|factor| &factor.kind == kind)
    }
}

pub struct MethodBuilder<M, F, U>
where
    M: MethodId + Serialize + DeserializeOwned,
    F: FactorId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
{
    id: M,
    name: String,
    description: String,
    factors: Vec<FactorInstance<F, U>>,
    created_by: U,
}

impl<M, F, U> MethodBuilder<M, F, U>
where
    M: MethodId + Serialize + DeserializeOwned,
    F: FactorId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
{
    pub fn new(
        id: M,
        name: impl Into<String>,
        description: impl Into<String>,
        created_by: U,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            description: description.into(),
            factors: Vec::new(),
            created_by,
        }
    }

    pub fn add_factor(mut self, factor: FactorInstance<F, U>) -> Self {
        self.factors.push(factor);
        self
    }

    pub fn add_factors<I>(mut self, factors: I) -> Self
    where
        I: IntoIterator<Item = FactorInstance<F, U>>,
    {
        self.factors.extend(factors);
        self
    }

    pub fn build(self) -> MethodInstance<M, F, U> {
        MethodInstance::new(
            self.id,
            &self.name,
            &self.description,
            self.factors,
            self.created_by,
        )
    }
}
