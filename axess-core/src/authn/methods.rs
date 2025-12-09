//! Authentication method primitives and builders.
//!
//! This module defines:
//! - [`MethodStateChange`] / [`MethodState`] for tracking per-scope method enablement.
//! - [`MethodInstance`] as the persisted representation of multi-factor flows.
//! - [`MethodBuilder`] to assemble methods ergonomically from their factor instances.
//!

pub mod factor;
pub mod form;
pub mod policy;
pub mod scope;

use crate::{
    authn::{
        backend::{AuthId, TenantId, UserId},
        methods::{
            factor::{FactorInstance, Kind},
            scope::{AuthnScope, EnablementState},
        },
    },
    tracing::error,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt::Debug;

/// Describes a desired change to an authentication method's enablement state for a given scope.
///
/// `MethodStateChange` is used to upsert (insert or update) the state of an authentication method
/// for a specific scope (global, tenant, or user) in the backend. It does not include an ID or audit
/// fields, as those are managed by the backend. This struct is typically constructed when provisioning,
/// enabling, disabling, or updating a method for a user or tenant.
///
/// # Fields
/// - `method_id`: The ID of the method to change.
/// - `tenant_id`: Optional tenant scope; `None` for global methods.
/// - `user_id`: Optional user scope; `None` for tenant/global methods.
/// - `state`: The new enablement state (e.g., Pending, Active, Inactive).
/// - `updated_by`: The user performing the change (for audit and authorization).
///
/// # Usage
/// Use `MethodStateChange` when you want to upsert a method state in the backend.
/// Construct it using the builder-style methods (`with_scope`, `with_state`) and pass it to your backend's
/// `upsert_method_state` method.
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::{MethodStateChange, scope::{EnablementState, AuthnScope}};
///
/// let method_id = 42_u64;
/// let tenant_id = 1_u64;
/// let user_id = 2_u64;
///
/// let change = MethodStateChange::new(method_id, user_id)
///     .with_scope(AuthnScope::User(tenant_id, user_id))
///     .with_state(EnablementState::Active);
/// ```
pub struct MethodStateChange<A, T, U>
where
    A: AuthId,
    T: TenantId,
    U: UserId,
{
    /// The ID of the method to change.
    pub method_id: A,
    /// Optional tenant scope; `None` for global methods.
    pub tenant_id: Option<T>,
    /// Optional user scope; `None` for tenant/global methods.
    pub user_id: Option<U>,
    /// The new enablement state (Pending, Active, Inactive, etc.).
    pub state: EnablementState,
    /// The user performing the change (for audit and authorization).
    pub updated_by: U,
}

impl<A, T, U> MethodStateChange<A, T, U>
where
    A: AuthId,
    T: TenantId,
    U: UserId,
{
    /// Creates a new `MethodStateChange` for the given method and actor.
    ///
    /// By default, sets the state to `Active` and leaves scope empty.
    pub fn new(method_id: A, updated_by: U) -> Self {
        Self {
            method_id,
            tenant_id: None,
            user_id: None,
            state: EnablementState::Active,
            updated_by,
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
    /// Use this to activate, deactivate, or suspend a method.
    pub fn with_state(mut self, state: EnablementState) -> Self {
        self.state = state;
        self
    }
}

/// Represents the enablement state of an authentication method for a given scope.
///
/// `MethodState` tracks whether a method is pending, active, inactive, suspended, or archived
/// for a specific scope (global, tenant, or user). It includes audit fields for creation and updates,
/// and is used to resolve which authentication flows are available to a user or tenant.
///
/// # Fields
/// - `id`: Unique identifier for this method state (usually a UUID or database key).
/// - `method_id`: The ID of the authentication method.
/// - `tenant_id`: Optional tenant scope; `None` for global methods.
/// - `user_id`: Optional user scope; `None` for tenant/global methods.
/// - `state`: The current enablement state (see [`EnablementState`]).
/// - `created_at`: Timestamp when this state was created.
/// - `created_by`: Who created this state.
/// - `updated_at`: Timestamp of last update.
/// - `updated_by`: Who last updated this state.
///
/// # Usage
/// - Used by backends to query, audit, and update method enablement.
/// - Supports multi-tenancy and per-user overrides.
/// - Use [`MethodStateChange`] to describe upserts or updates.
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::{MethodState, scope::{EnablementState, AuthnScope}};
///
/// type TenantId = u64;
///
/// let id = 1_u64;
/// let method_id = 42_u64;
/// let created_by = 2_u64;
///
/// let state: MethodState<u64, TenantId, u64> = MethodState::new(id, method_id, created_by)
///     .with_state(EnablementState::Active);
/// assert_eq!(state.state, EnablementState::Active);
/// assert_eq!(state.scope(), AuthnScope::Global);
/// ```
#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct MethodState<A, T, U>
where
    A: AuthId,
    T: TenantId,
    U: UserId,
{
    /// Unique identifier for this method state (usually a UUID or database key).
    pub id: A,
    /// The ID of the authentication method.
    pub method_id: A,
    /// Optional tenant scope; `None` for global methods.
    pub tenant_id: Option<T>,
    /// Optional user scope; `None` for tenant/global methods.
    pub user_id: Option<U>,
    /// The current enablement state (see [`EnablementState`]).
    pub state: EnablementState,
    /// Timestamp when this state was created.
    pub created_at: DateTime<Utc>,
    /// Who created this state.
    pub created_by: U,
    /// Timestamp of last update.
    pub updated_at: DateTime<Utc>,
    /// Who last updated this state.
    pub updated_by: U,
}

impl<A, T, U> MethodState<A, T, U>
where
    A: AuthId,
    T: TenantId,
    U: UserId,
{
    /// Creates a new `MethodState` with default values.
    ///
    /// Sets `state` to `Pending` and initializes timestamps.
    pub fn new(id: A, method_id: A, created_by: U) -> Self {
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

    /// Sets the enablement state for this method state.
    pub fn with_state(mut self, state: EnablementState) -> Self {
        self.state = state;
        self
    }

    /// Returns the [`AuthnScope`] for this method state (global, tenant, or user).
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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound(
    serialize = "A: Serialize, U: Serialize",
    deserialize = "A: DeserializeOwned, U: DeserializeOwned"
))]
pub struct MethodInstance<A, U>
where
    A: AuthId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
{
    /// Unique identifier for this method (e.g., UUID, string).
    pub id: A,
    /// Human-readable name for the method (e.g., "Password + TOTP").
    pub name: String,
    /// Optional description or display text for the method.
    pub description: String,
    /// List of factors that must be verified for this method.
    pub factors: Vec<FactorInstance<A, U>>,
    /// Timestamp when this method was created.
    pub created_at: DateTime<Utc>,
    /// Who created this method.
    pub created_by: U,
    /// Timestamp of last update.
    pub updated_at: DateTime<Utc>,
    /// Who last updated this method.
    pub updated_by: U,
}

impl<A, U> MethodInstance<A, U>
where
    A: AuthId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
{
    pub fn new(
        id: A,
        name: &str,
        description: &str,
        factors: Vec<FactorInstance<A, U>>,
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

    pub fn get_factor(&self, factor_id: &A) -> Option<&FactorInstance<A, U>> {
        self.factors.iter().find(|factor| &factor.id == factor_id)
    }

    pub fn get_factor_ids(&self) -> Vec<A>
    where
        A: Clone,
    {
        self.factors
            .iter()
            .map(|factor| factor.id.clone())
            .collect()
    }

    pub fn get_first_factor_id(&self) -> Option<A>
    where
        A: Clone,
    {
        self.factors.first().map(|factor| factor.id.clone())
    }

    pub fn has_factor_kind(&self, kind: &Kind) -> bool {
        self.factors.iter().any(|factor| &factor.kind == kind)
    }
}

/// Ergonomic builder for constructing multi-factor authentication methods.
///
/// `MethodBuilder` provides a fluent API for assembling [`MethodInstance`]s from their factor instances.
/// It is used throughout Axess to define authentication flows such as "Password Only", "Password + TOTP",
/// or custom multi-factor methods. The builder ensures all required fields are set and supports adding
/// factors incrementally.
///
/// # Fields
/// - `id`: Unique identifier for the method (e.g., UUID, string).
/// - `name`: Human-readable name for the method.
/// - `description`: Optional description or display text.
/// - `factors`: List of [`FactorInstance`]s to be verified for this method.
/// - `created_by`: User who created the method.
///
/// # Usage
/// - Use [`MethodBuilder::new`] to start a new method.
/// - Add factors with [`add_factor`] or [`add_factors`] (chained).
/// - Call [`build`] to produce a [`MethodInstance`] for persistence or provisioning.
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::{MethodBuilder, factor::{Kind, FactorInstance}};
///
/// let password_factor = FactorInstance::new(
///     "password-factor".to_string(),
///     Kind::Password,
///     "Password",
///     "Primary login password",
///     "user-id".to_string(),
/// );
///
/// let method = MethodBuilder::new(
///     "method-id".to_string(),
///     "Password Only",
///     "Password based authentication",
///     "user-id".to_string(),
/// )
/// .add_factor(password_factor)
/// .build();
/// assert_eq!(method.name, "Password Only");
/// assert_eq!(method.factors.len(), 1);
/// ```
pub struct MethodBuilder<A, U>
where
    A: AuthId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
{
    id: A,
    name: String,
    description: String,
    factors: Vec<FactorInstance<A, U>>,
    created_by: U,
}

impl<A, U> MethodBuilder<A, U>
where
    A: AuthId + Serialize + DeserializeOwned,
    U: UserId + Serialize + DeserializeOwned,
{
    /// Creates a new builder for an authentication method.
    ///
    /// Sets the method's ID, name, description, and creator.
    pub fn new(
        id: A,
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

    /// Adds a single factor to the method.
    ///
    /// Can be chained for ergonomic construction.
    pub fn add_factor(mut self, factor: FactorInstance<A, U>) -> Self {
        self.factors.push(factor);
        self
    }

    /// Adds multiple factors to the method.
    ///
    /// Accepts any iterator of [`FactorInstance`]s.
    pub fn add_factors<I>(mut self, factors: I) -> Self
    where
        I: IntoIterator<Item = FactorInstance<A, U>>,
    {
        self.factors.extend(factors);
        self
    }

    /// Builds and returns a [`MethodInstance`] from the builder.
    ///
    /// Consumes the builder and produces a fully constructed method.
    pub fn build(self) -> MethodInstance<A, U> {
        MethodInstance::new(
            self.id,
            &self.name,
            &self.description,
            self.factors,
            self.created_by,
        )
    }
}
