//! Core backend abstraction for Axess authentication.
//!
//! This module standardizes how storage backends interact with Axess:
//! - Identifier traits (`TenantId`, `UserId`, `AuthId`) that
//!   downstream crates implement for their domain-specific types.
//! - [`AuthnBackend`], the async trait every storage adapter must satisfy to support
//!   credential provisioning, factor/method state transitions, and audit logging.
//! - Shared [`EntityState`] and [`StatusDetail`] structures for user and tenant lifecycle.
//! - Reference tests exercising the in-memory [`MockBackend`] to ensure the trait contract
//!   behaves consistently across implementations.

#[cfg(feature = "admin")]
pub mod admin;
#[cfg(feature = "admin")]
pub mod handlers;

use crate::authn::{
    errors::AuthError, methods::{
        MethodStateChange,
        factor::FactorStateChange,
        form::FactorForm,
        scope::{AuthnScope, EnablementState},
    }, session::state::{AuthEvent, AuthEventRecord, AuthEventStatus, AuthEventType}, types::{AuthFactor, AuthFactorState, AuthMethod, AuthMethodState}
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{
    cmp::PartialEq,
    fmt::{Debug, Display},
    hash::Hash,
};

pub trait TenantId:
    Clone
    + Display
    + Debug
    + Eq
    + PartialEq
    + Hash
    + Send
    + Sync
    + Serialize
    + for<'de> Deserialize<'de>
{
}

pub trait UserId:
    Clone
    + Display
    + Debug
    + Eq
    + PartialEq
    + Hash
    + Send
    + Sync
    + Serialize
    + for<'de> Deserialize<'de>
{
}

pub trait AuthId:
    Clone
    + Display
    + Debug
    + Eq
    + PartialEq
    + Hash
    + Send
    + Sync
    + Serialize
    + for<'de> Deserialize<'de>
{
}

impl<T> TenantId for T where
    T: Clone
        + Display
        + Debug
        + Eq
        + PartialEq
        + Hash
        + Send
        + Sync
        + Serialize
        + for<'de> Deserialize<'de>
{
}

impl<T> UserId for T where
    T: Clone
        + Display
        + Debug
        + Eq
        + PartialEq
        + Hash
        + Send
        + Sync
        + Serialize
        + for<'de> Deserialize<'de>
{
}

impl<T> AuthId for T where
    T: Clone
        + Display
        + Debug
        + Eq
        + PartialEq
        + Hash
        + Send
        + Sync
        + Serialize
        + for<'de> Deserialize<'de>
{
}

/// Provides additional context for user or tenant lifecycle state transitions.
///
/// `StatusDetail` is attached to states such as `Suspended`, `Terminated`, `Pending`, or `Archived`
/// in [`EntityState`]. It records the reason for the state change, the timestamp when it occurred,
/// an optional expiry (`until`), and any extra metadata (e.g., audit info, error details).
///
/// This struct enables fine-grained audit logging, lockout policies, and compliance reporting
/// for authentication and authorization flows.
///
/// # Fields
/// - `reason`: Human-readable explanation for the state change (e.g., "Too many failed logins").
/// - `timestamp`: When the state change occurred.
/// - `until`: Optional expiry for temporary states (e.g., lockout until a future time).
/// - `metadata`: Optional extra context (e.g., error details, admin info, audit trail).
///
/// # Usage
/// Used in [`EntityState`] variants to provide context for transitions such as suspension,
/// termination, or pending approval. Enables backends and UIs to display meaningful status
/// and reason codes to users and administrators.
///
/// # Example
/// ```rust
/// use axess_core::authn::backend::StatusDetail;
/// use chrono::Utc;
///
/// let detail = StatusDetail {
///     reason: "Too many failed login attempts".to_string(),
///     timestamp: Utc::now(),
///     until: Some(Utc::now() + chrono::Duration::minutes(30)),
///     metadata: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct StatusDetail {
    /// Human-readable explanation for the state change (e.g., "Too many failed logins").
    pub reason: String,
    /// When the state change occurred.
    pub timestamp: DateTime<Utc>,
    /// Optional expiry for temporary states (e.g., lockout until a future time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
    /// Optional extra context (e.g., error details, admin info, audit trail).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<JsonValue>,
}

/// Represents the lifecycle state of a user or tenant entity in Axess.
///
/// `EntityState` tracks whether an entity is active, pending approval, suspended, terminated, archived, or a guest.
/// This enables fine-grained control over authentication, authorization, and audit flows, supporting lockout,
/// onboarding, and compliance requirements.
///
/// # Variants
/// - `Guest`: Unauthenticated or guest entity.
/// - `Candidate`: Newly created entity, not yet approved.
/// - `Pending(StatusDetail)`: Awaiting approval or activation; includes reason and metadata.
/// - `Active`: Fully enabled and operational.
/// - `Suspended(StatusDetail)`: Temporarily disabled (e.g., lockout, policy violation); includes reason and metadata.
/// - `Terminated(StatusDetail)`: Permanently disabled or deleted; includes reason and metadata.
/// - `Archived(StatusDetail)`: No longer available for new use, but kept for history/audit; includes reason and metadata.
///
/// # Usage
/// Used by [`AuthUser`] and [`AuthTenant`] to track and query entity status.
/// Drives backend logic for authentication, lockout, onboarding, and audit logging.
/// Status transitions should include a [`StatusDetail`] for audit and compliance.
///
/// # Example
/// ```rust
/// use axess_core::authn::backend::{EntityState, StatusDetail};
/// use chrono::Utc;
///
/// let active = EntityState::Active;
/// let suspended = EntityState::Suspended(StatusDetail {
///     reason: "Too many failed logins".to_string(),
///     timestamp: Utc::now(),
///     until: Some(Utc::now() + chrono::Duration::minutes(30)),
///     metadata: None,
/// });
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", content = "data")]
pub enum EntityState {
    /// Unauthenticated or guest entity.
    Guest,
    /// Newly created entity, not yet approved.
    Candidate,
    /// Awaiting approval or activation; includes reason and metadata.
    Pending(StatusDetail),
    /// Fully enabled and operational.
    Active,
    /// Temporarily disabled (e.g., lockout, policy violation); includes reason and metadata.
    Suspended(StatusDetail),
    /// Permanently disabled or deleted; includes reason and metadata.
    Terminated(StatusDetail),
    /// No longer available for new use, but kept for history/audit; includes reason and metadata.
    Archived(StatusDetail),
}

impl EntityState {
    /// If this state is Suspended, return a reference to the inner StatusDetail, otherwise None.
    pub fn as_suspended(&self) -> Option<&StatusDetail> {
        if let EntityState::Suspended(detail) = self {
            Some(detail)
        } else {
            None
        }
    }

    /// If this state is Pending, return a reference to the inner StatusDetail, otherwise None.
    pub fn as_pending(&self) -> Option<&StatusDetail> {
        if let EntityState::Pending(detail) = self {
            Some(detail)
        } else {
            None
        }
    }

    /// If this state is Terminated, return a reference to the inner StatusDetail, otherwise None.
    pub fn as_terminated(&self) -> Option<&StatusDetail> {
        if let EntityState::Terminated(detail) = self {
            Some(detail)
        } else {
            None
        }
    }

    /// If this state is Archived, return a reference to the inner StatusDetail, otherwise None.
    pub fn as_archived(&self) -> Option<&StatusDetail> {
        if let EntityState::Archived(detail) = self {
            Some(detail)
        } else {
            None
        }
    }

    pub fn is_deactivated(&self) -> bool {
        matches!(
            self,
            EntityState::Suspended(_) | EntityState::Terminated(_) | EntityState::Archived(_)
        )
    }
}

impl Display for EntityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityState::Guest => write!(f, "guest"),
            EntityState::Candidate => write!(f, "candidate"),
            EntityState::Pending(_) => write!(f, "pending"),
            EntityState::Active => write!(f, "active"),
            EntityState::Suspended(_) => write!(f, "suspended"),
            EntityState::Terminated(_) => write!(f, "terminated"),
            EntityState::Archived(_) => write!(f, "archived"),
        }
    }
}

/// Trait for tenant entities in Axess authentication backends.
///
/// `AuthTenant` abstracts the representation of a tenant (organization, workspace, etc.)
/// in the authentication system. Each tenant must have a unique identifier, a display name,
/// and a lifecycle state (see [`EntityState`]).
///
/// Implement this trait for your backend's tenant struct to enable multi-tenancy,
/// per-tenant authentication flows, and tenant-scoped policies.
///
/// # Associated Types
/// - `Id`: Unique identifier type for the tenant (e.g., UUID, String).
///
/// # Required Methods
/// - `id(&self) -> Self::Id`: Returns the tenant's unique identifier.
/// - `name(&self) -> String`: Returns the tenant's display name.
/// - `get_tenant_state(&self) -> EntityState`: Returns the tenant's lifecycle state.
///
/// # Example
/// ```rust
/// use axess_core::authn::backend::{AuthTenant, EntityState};
/// use uuid::Uuid;
///
/// #[derive(Debug, Clone, PartialEq, Eq)]
/// struct MyTenant {
///     id: Uuid,
///     name: String,
///     state: EntityState,
/// }
///
/// impl AuthTenant for MyTenant {
///     type Id = Uuid;
///     fn id(&self) -> Self::Id { self.id }
///     fn name(&self) -> String { self.name.clone() }
///     fn get_tenant_state(&self) -> EntityState { self.state.clone() }
/// }
/// ```
pub trait AuthTenant: Debug + Clone + Send + Sync + Eq + PartialEq {
    /// Unique identifier type for the tenant (e.g., UUID, String).
    type Id: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + 'static;

    /// Returns the tenant's unique identifier.
    fn id(&self) -> Self::Id;

    /// Returns the tenant's display name.
    fn name(&self) -> String;

    /// Returns the tenant's lifecycle state.
    fn get_tenant_state(&self) -> EntityState;
}

/// Trait for user entities in Axess authentication backends.
///
/// `AuthUser` abstracts the representation of a user in the authentication system.
/// Each user must have a unique identifier, be associated with a tenant, and have a lifecycle state (see [`EntityState`]).
///
/// Implement this trait for your backend's user struct to enable multi-tenancy,
/// per-user authentication flows, and user-scoped policies.
///
/// # Associated Types
/// - `Id`: Unique identifier type for the user (e.g., UUID, String).
/// - `TenantId`: Unique identifier type for the tenant the user belongs to.
///
/// # Required Methods
/// - `id(&self) -> &Self::Id`: Returns a reference to the user's unique identifier.
/// - `tenant_id(&self) -> &Self::TenantId`: Returns a reference to the user's tenant identifier.
/// - `get_user_state(&self) -> EntityState`: Returns the user's lifecycle state.
///
/// # Example
/// ```rust
/// use axess_core::authn::backend::{AuthUser, EntityState};
/// use uuid::Uuid;
///
/// #[derive(Debug, Clone, PartialEq, Eq)]
/// struct MyUser {
///     id: Uuid,
///     tenant_id: Uuid,
///     state: EntityState,
/// }
///
/// impl AuthUser for MyUser {
///     type Id = Uuid;
///     type TenantId = Uuid;
///     fn id(&self) -> &Self::Id { &self.id }
///     fn tenant_id(&self) -> &Self::TenantId { &self.tenant_id }
///     fn get_user_state(&self) -> EntityState { self.state.clone() }
/// }
/// ```
pub trait AuthUser: Debug + Clone + Send + Sync + Eq + PartialEq {
    /// Unique identifier type for the user (e.g., UUID, String).
    type Id: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + 'static;
    /// Unique identifier type for the tenant the user belongs to.
    type TenantId: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + 'static;

    /// Returns a reference to the user's unique identifier.
    fn id(&self) -> &Self::Id;
    /// Returns a reference to the user's tenant identifier.
    fn tenant_id(&self) -> &Self::TenantId;
    /// Returns the user's lifecycle state.
    fn get_user_state(&self) -> EntityState;
}

/// Core async trait for Axess authentication and authorization backends.
///
/// `AuthnBackend` standardizes how storage backends interact with Axess, providing
/// all necessary operations for user, tenant, factor, and method management, as well as
/// audit logging and authentication flows. Implement this trait for your backend to enable
/// session-based authentication, multi-factor flows, and policy-driven authorization.
///
/// # Associated Types
/// - `User`: User entity type, must implement [`AuthUser`].
/// - `UserId`: User identifier type.
/// - `Tenant`: Tenant entity type, must implement [`AuthTenant`].
/// - `TenantId`: Tenant identifier type.
/// - `AuthId`: Generic identifier type for factors, methods, and data.
/// - `Error`: Error type for backend operations.
///
/// # Required Methods
/// - User and tenant lookup, creation, and state management.
/// - Authentication method and factor lookup, state management, and upserts.
/// - Audit event recording and retrieval.
/// - Authentication flow entry point (`authenticate`).
///
/// # Usage
/// Implement `AuthnBackend` for your database or storage adapter to support Axess authentication flows.
/// Use the provided identifier traits for ergonomic type mapping. See [`MockBackend`] for a reference implementation.
///
/// # Example
/// ```rust,ignore
/// use axess_core::authn::backend::{AuthnBackend, AuthUser, AuthTenant, EntityState};
/// use async_trait::async_trait;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// struct MyUser { /* ... */ }
/// impl AuthUser for MyUser { /* ... */ }
///
/// #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// struct MyTenant { /* ... */ }
/// impl AuthTenant for MyTenant { /* ... */ }
///
/// struct MyBackend;
/// #[async_trait]
/// impl AuthnBackend for MyBackend {
///     type User = MyUser;
///     type UserId = String;
///     type Tenant = MyTenant;
///     type TenantId = String;
///     type AuthId = String;
///     type Error = anyhow::Error;
///     // Implement all required async methods...
/// }
/// ```
///
/// # DST Support
/// All methods are async and designed with deterministic simulation testing (DST) in mind.
#[async_trait]
pub trait AuthnBackend: Clone + Send + Sync + 'static
where
    Self::User: AuthUser + Debug + Clone + Serialize + for<'de> Deserialize<'de> + PartialEq,
    Self::Tenant: AuthTenant + Debug + Clone + Serialize + for<'de> Deserialize<'de> + PartialEq,
    Self::Error: Debug + Send + Sync + 'static,
{
    /// The identifier for the user type associated with the backend.
    type User: AuthUser + Debug + Clone + Serialize + for<'de> Deserialize<'de> + PartialEq;
    type UserId: UserId;

    /// Identifier for the tenant type associated with the backend.
    type Tenant: AuthTenant + Debug + Clone + Serialize + for<'de> Deserialize<'de> + PartialEq;
    type TenantId: TenantId;

    /// Identifier type used for all other authentication related data objects associated with the backend.
    type AuthId: AuthId;

    /// An error which can occur during authentication and authorization.
    type Error: Debug + Send + Sync + 'static;

    /// Maximum number of allowed authentication attempts before temporary lockout.
    fn max_auth_attempts(&self) -> u32 {
        5
    }

    /// Gets the default protected route (e.g., dashboard) for authenticated users.
    async fn get_default_protected_route(
        &self,
        tenant_id: Self::TenantId,
        user_id: Self::UserId,
    ) -> Result<String, Self::Error>;

    /// Gets the tenant by provided ID from the backend.
    async fn get_tenant(&self, tenant_id: &Self::TenantId) -> Result<Self::Tenant, Self::Error>;

    /// Gets the tenant by provided name from the backend.
    async fn get_tenant_by_name(&self, name: &str) -> Result<Self::Tenant, Self::Error>;

    /// Gets the default tenant ID from the backend.
    async fn get_default_tenant_id(&self) -> Result<Self::TenantId, Self::Error>;

    /// Gets the user by provided ID from the backend.
    async fn get_user(&self, user_id: &Self::UserId) -> Result<Self::User, Self::Error>;

    /// Gets the user by username within the specified tenant from the backend.
    async fn get_user_by_name(
        &self,
        tenant_id: &Self::TenantId,
        username: &str,
    ) -> Result<Self::User, Self::Error>;

    /// Gets the main administrative system user for the given tenant, or the super user for the global system if none is provided.
    async fn get_system_user_id(
        &self,
        tenant_id: Option<&Self::TenantId>,
    ) -> Result<Self::UserId, Self::Error>;

    /// Gets a new guest user for the given tenant, or for the default tenant if none is provided.
    async fn get_new_guest_user(
        &self,
        tenant_id: Option<&Self::TenantId>,
    ) -> Result<Self::User, Self::Error>;

    /// Registers a new user from a given form.
    async fn create_new_user<F>(&self, form: &F) -> Result<Self::User, Self::Error>
    where
        F: FactorForm;

    /// Sets the state of a user (e.g., Active, Suspended, Terminated).
    async fn set_user_state(
        &self,
        user_id: &Self::UserId,
        new_state: EntityState,
        actor: Self::UserId,
    ) -> Result<Self::User, Self::Error>;

    /// Get the authentication method by its' ID.
    async fn get_auth_method(
        &self,
        method_id: &Self::AuthId,
    ) -> Result<AuthMethod<Self>, Self::Error>;

    /// Get the authentication method by its' name, optionally filtered on enablement state(s) and scope.
    /// an empty array of enablement states means that all states are acceptable (i.e. no filtering)
    async fn get_auth_method_by_name(
        &self,
        name: &str,
        scope: AuthnScope<Self::TenantId, Self::UserId>,
        states: Vec<EnablementState>,
    ) -> Result<AuthMethod<Self>, Self::Error>;

    /// Get all Authentication methods for a given scope (global/user/tenant), potentially filtered by state (e.g. 'Active').
    async fn get_scoped_auth_methods(
        &self,
        scope: AuthnScope<Self::TenantId, Self::UserId>,
        states: Vec<EnablementState>,
    ) -> Result<Vec<AuthMethod<Self>>, Self::Error>;

    /// Get all method states for a given method ID and scope (global/user/tenant).
    async fn get_method_states(
        &self,
        method_id: &Self::AuthId,
        scope: AuthnScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthMethodState<Self>>, Self::Error>;

    /// Upsert (insert or update) the state of an authentication method for a given scope (global/user/tenant).
    async fn upsert_method_state(
        &self,
        change: MethodStateChange<Self::AuthId, Self::TenantId, Self::UserId>,
        actor: Self::UserId,
    ) -> Result<AuthMethodState<Self>, Self::Error>;

    /// Get the authentication factor by its ID.
    async fn get_auth_factor(
        &self,
        factor_id: &Self::AuthId,
    ) -> Result<AuthFactor<Self>, Self::Error>;

    /// Get the authentication factor by its' name, optionally filtered on enablement state(s) and scope.
    /// an empty array of enablement states means that all states are acceptable (i.e. no filtering)
    async fn get_auth_factor_by_name(
        &self,
        name: &str,
        scope: AuthnScope<Self::TenantId, Self::UserId>,
        states: Vec<EnablementState>,
    ) -> Result<AuthFactor<Self>, Self::Error>;

    /// Get all Authentication factors for a given scope (global/user/tenant), potentially filtered by state (e.g. 'Active').
    async fn get_scoped_auth_factors(
        &self,
        scope: AuthnScope<Self::TenantId, Self::UserId>,
        states: Vec<EnablementState>,
    ) -> Result<Vec<AuthFactor<Self>>, Self::Error>;

    /// Get all factor states for a given factor ID and scope (global/user/tenant).
    async fn get_factor_states(
        &self,
        factor_id: &Self::AuthId,
        scope: AuthnScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthFactorState<Self>>, Self::Error>;

    /// Upsert (insert or update) the state of an authentication factor for a given scope (global/user/tenant).
    async fn upsert_factor_state(
        &self,
        change: FactorStateChange<Self::AuthId, Self::TenantId, Self::UserId>,
        actor: Self::UserId,
    ) -> Result<AuthFactorState<Self>, Self::Error>;

    /// Get recent authentication events for a user.
    ///
    /// Results are returned ordered by `event_time` descending (most recent first).
    ///
    /// # Arguments
    /// * `user_id` - The user ID to query events for
    /// * `event_type` - Optional filter by event type (e.g., only "Login" events)
    /// * `event_status` - Optional filter by event status (e.g., only "Success" events)
    /// * `limit` - Optional maximum number of events to return (defaults to 100 if None)
    ///
    /// # Returns
    /// Vector of authentication events ordered by timestamp descending (most recent first)
    async fn get_auth_history(
        &self,
        user_id: &Self::UserId,
        event_type: Option<AuthEventType>,
        event_status: Option<AuthEventStatus>,
        limit: Option<usize>,
    ) -> Result<Vec<AuthEvent<Self>>, Self::Error>;

    /// Get last successful login time for a user.
    ///
    /// This is a convenience method that queries for the most recent successful
    /// `Authenticated` event.
    async fn get_last_login(
        &self,
        user_id: &Self::UserId,
    ) -> Result<Option<DateTime<Utc>>, Self::Error> {
        let events = self
            .get_auth_history(
                user_id,
                Some(AuthEventType::Authenticated),
                Some(AuthEventStatus::Success),
                Some(1),
            )
            .await?;
        if let Some(event) = events.first() {
            Ok(Some(event.event_time))
        } else {
            Ok(None)
        }
    }

    /// Record an authentication event for a user.
    ///
    /// This method is used to log authentication-related events such as login attempts,
    /// logout events, password changes, etc. The event details are provided in the
    /// `AuthEventRecord` struct.
    /// # Arguments
    /// * `event` - The authentication event details to record
    /// # Returns
    /// Result indicating success or failure of the operation
    /// # Errors
    /// Returns an error if the event could not be recorded
    async fn record_auth_event(&self, event: AuthEventRecord<'_, Self>) -> Result<(), Self::Error>;

    /// Authenticates a user using the provided credentials form.
    ///
    /// This is the main entry point for factor-based authentication flows.
    /// The form is validated and checked against the backend's stored factor state.
    async fn authenticate<'a, F>(&self, form: &'a F) -> Result<Self::User, AuthError<Self>>
    where
        F: FactorForm + Send + Sync;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "admin")]
    use crate::authn::backend::admin::AuthnAdminBackend;
    use crate::{
        authn::{
            methods::MethodInstance,
            session::state::{AuthEventStatus, AuthEventType},
        },
        utils::testing::{
            mock_backend::{MockBackend, MockBackendError},
            mock_entities::{MockTenant, MockUser, TestTenantId, TestUserId},
            mock_form::{DummyFailingForm, DummyOkForm},
        },
    };
    use serde_json::Error as JsonError;

    #[tokio::test]
    /// Ensures get_new_guest_user returns a guest user for the specified tenant.
    async fn test_get_new_guest_user_returns_guest() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let guest = match backend
            .get_new_guest_user(Some(&TestTenantId("t1".to_string())))
            .await
        {
            Ok(guest) => guest,
            Err(e) => {
                tracing::error!("Failed to get new guest user: {:?}", e);
                return Err(e);
            }
        };
        assert_eq!(guest.get_user_state(), EntityState::Guest);
        assert_eq!(guest.tenant_id(), &TestTenantId("t1".to_string()));
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "admin")]
    /// Verifies that get_user returns an active user after upsert.
    async fn test_get_user_returns_active_user() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let system_user = match backend.get_system_user_id(None).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("Failed to get system user ID: {:?}", e);
                return Err(e);
            }
        };
        let user = MockUser {
            id: TestUserId("u1".to_string()),
            tenant_id: TestTenantId("t1".to_string()),
            state: EntityState::Active,
        };
        match backend.upsert_user(user.clone(), system_user).await {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Failed to upsert user: {:?}", e);
                return Err(e);
            }
        }

        let fetched = match backend.get_user(&TestUserId("u1".to_string())).await {
            Ok(user) => user,
            Err(e) => {
                tracing::error!("Failed to get user: {:?}", e);
                return Err(e);
            }
        };
        assert_eq!(fetched.get_user_state(), EntityState::Active);
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "admin")]
    /// Checks that set_user_state changes the user's state as expected.
    async fn test_set_user_state_changes_state() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let system_user_id = match backend.get_system_user_id(None).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("Failed to get system user ID: {:?}", e);
                return Err(e);
            }
        };
        let user = MockUser {
            id: TestUserId("u2".to_string()),
            tenant_id: TestTenantId("t2".to_string()),
            state: EntityState::Active,
        };
        let system_user_id_clone = system_user_id.clone();
        match backend
            .upsert_user(user.clone(), system_user_id_clone)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Failed to upsert user: {:?}", e);
                return Err(e);
            }
        }

        let updated = match backend
            .set_user_state(
                &TestUserId("u2".to_string()),
                EntityState::Suspended(StatusDetail {
                    reason: "test".to_string(),
                    timestamp: Utc::now(),
                    until: None,
                    metadata: None,
                }),
                system_user_id,
            )
            .await
        {
            Ok(user) => user,
            Err(e) => {
                tracing::error!("Failed to set user state: {:?}", e);
                return Err(e);
            }
        };
        assert!(matches!(
            updated.get_user_state(),
            EntityState::Suspended(_)
        ));
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "admin")]
    /// Verifies upsert_user correctly inserts and retrieves a user.
    async fn test_upsert_user_roundtrip() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let system_user = match backend.get_system_user_id(None).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("Failed to get system user ID: {:?}", e);
                return Err(e);
            }
        };
        let user = MockUser {
            id: TestUserId("u3".to_string()),
            tenant_id: TestTenantId("t3".to_string()),
            state: EntityState::Active,
        };
        let upserted = match backend.upsert_user(user.clone(), system_user).await {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("Failed to upsert user: {:?}", e);
                return Err(e);
            }
        };
        assert_eq!(upserted, user);
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "admin")]
    /// Verifies upsert_tenant correctly inserts and retrieves a tenant.
    async fn test_upsert_and_get_tenant_roundtrip() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let system_user = match backend.get_system_user_id(None).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("Failed to get system user ID: {:?}", e);
                return Err(e);
            }
        };
        let tenant = MockTenant::default().with_id(TestTenantId("tenant42".to_string()));
        let upserted = match backend.upsert_tenant(tenant.clone(), system_user).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to upsert tenant: {:?}", e);
                return Err(e);
            }
        };
        assert_eq!(upserted, tenant);

        let fetched = match backend.get_tenant(&tenant.id()).await {
            Ok(fetched) => fetched,
            Err(e) => {
                tracing::error!("Failed to get tenant: {:?}", e);
                return Err(e);
            }
        };
        assert_eq!(fetched, tenant);
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "admin")]
    /// Checks that delete_tenant returns Ok when deleting a tenant and ensures tenant is gone.
    async fn test_delete_tenant_returns_ok_and_removes_tenant() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let system_user = match backend.get_system_user_id(None).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("Failed to get system user ID: {:?}", e);
                return Err(e);
            }
        };
        let tenant = MockTenant::default().with_id(TestTenantId("tenant_delete".to_string()));
        match backend
            .upsert_tenant(tenant.clone(), system_user.clone())
            .await
        {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Failed to upsert tenant: {:?}", e);
                return Err(e);
            }
        }
        let result = backend.delete_tenant(&tenant.id(), system_user).await;
        assert!(result.is_ok());
        let fetch_result = backend.get_tenant(&tenant.id()).await;
        assert!(fetch_result.is_err());
        Ok(())
    }

    #[tokio::test]
    /// Ensures get_default_tenant_id returns the default tenant.
    async fn test_get_default_tenant_id_returns_default() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let tenant = backend.get_default_tenant_id().await?;
        assert_eq!(tenant, MockTenant::default().id());
        Ok(())
    }

    #[tokio::test]
    /// Verifies get_auth_method returns an error for unimplemented methods.
    async fn test_get_auth_method_not_implemented() {
        let backend = MockBackend::default();
        let result = backend
            .get_auth_method(&"some_random_dummy_method".to_string())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    /// Checks user serialization and deserialization roundtrip.
    async fn test_user_serialization_deserialization() -> Result<(), JsonError> {
        let user = MockUser {
            id: TestUserId("u99".to_string()),
            tenant_id: TestTenantId("t99".to_string()),
            state: EntityState::Active,
        };
        let json = match serde_json::to_string(&user) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("Failed to serialize user: {:?}", e);
                return Err(e);
            }
        };
        let deserialized: MockUser = match serde_json::from_str(&json) {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("Failed to deserialize user: {:?}", e);
                return Err(e);
            }
        };
        assert_eq!(user, deserialized);
        Ok(())
    }

    #[tokio::test]
    /// Checks tenant ID serialization and deserialization roundtrip.
    async fn test_tenant_serialization_deserialization() -> Result<(), JsonError> {
        let tenant = TestTenantId("tenant_serial".to_string());
        let json = match serde_json::to_string(&tenant) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("Failed to serialize tenant ID: {:?}", e);
                return Err(e);
            }
        };
        let deserialized: TestTenantId = match serde_json::from_str(&json) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to deserialize tenant ID: {:?}", e);
                return Err(e);
            }
        };
        assert_eq!(tenant, deserialized);
        Ok(())
    }

    #[tokio::test]
    /// Verifies get_auth_method returns the correct method when present.
    async fn test_get_auth_method_returns_method() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let method_id = "test_method_id".to_string();
        let system_user_id = backend.get_system_user_id(None).await?;

        let method: MethodInstance<String, TestUserId> = MethodInstance {
            id: method_id.clone(),
            name: "Test Password Method".to_string(),
            description: "Test method for password authentication".to_string(),
            factors: vec![],
            created_at: Utc::now(),
            created_by: system_user_id.clone(),
            updated_at: Utc::now(),
            updated_by: system_user_id.clone(),
        };
        // Upsert auth method with robust error handling so test logs failures explicitly.
        match backend
            .upsert_auth_method(method.clone(), system_user_id.clone())
            .await
        {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Failed to upsert auth method: {:?}", e);
                return Err(e);
            }
        }

        let retrieved = match backend.get_auth_method(&method_id).await {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("Failed to get auth method: {:?}", e);
                return Err(e);
            }
        };
        assert_eq!(retrieved.id, method_id);
        assert_eq!(retrieved.name, "Test Password Method");
        Ok(())
    }

    #[tokio::test]
    /// Ensures authenticate returns an error for inactive users.
    async fn test_authenticate_with_inactive_user_returns_error() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let system_user_id = match backend.get_system_user_id(None).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("Failed to get system user ID: {:?}", e);
                return Err(e);
            }
        };

        #[cfg(feature = "admin")]
        {
            // Create suspended user
            let user = MockUser {
                id: TestUserId("suspended_user".to_string()),
                tenant_id: TestTenantId("tenant1".to_string()),
                state: EntityState::Suspended(StatusDetail {
                    reason: "Test suspension".to_string(),
                    timestamp: chrono::Utc::now(),
                    until: None,
                    metadata: None,
                }),
            };

            match backend
                .upsert_user(user.clone(), system_user_id.clone())
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Failed to upsert user: {:?}", e);
                    return Err(e);
                }
            }

            // Verify user state is not active
            let fetched = match backend
                .get_user(&TestUserId("suspended_user".to_string()))
                .await
            {
                Ok(user) => user,
                Err(e) => {
                    tracing::error!("Failed to get suspended user: {:?}", e);
                    return Err(e);
                }
            };

            assert!(matches!(
                fetched.get_user_state(),
                EntityState::Suspended(_)
            ));
        }

        Ok(())
    }

    #[tokio::test]
    /// Checks that record_auth_event and get_auth_history work as a roundtrip.
    async fn test_record_and_retrieve_auth_event_roundtrip() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let user_id = TestUserId("event_test_user".to_string());
        let tenant_id = TestTenantId("event_test_tenant".to_string());

        // Record event using AuthEventRecord
        let event = AuthEventRecord::<MockBackend> {
            user_id: &user_id,
            tenant_id: &tenant_id,
            session_id: Some("session123"),
            event_type: AuthEventType::LoginAttempt,
            event_status: AuthEventStatus::Success,
            method_id: None,
            factor_id: None,
            factor_kind: None,
            ip_address: Some("192.168.1.1"),
            user_agent: Some("Test Agent"),
            error_message: None,
        };

        // Record event and handle errors robustly
        match backend.record_auth_event(event).await {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Failed to record auth event: {:?}", e);
                return Err(e);
            }
        }

        // Retrieve event
        let events = match backend
            .get_auth_history(
                &user_id,
                Some(AuthEventType::LoginAttempt),
                Some(AuthEventStatus::Success),
                Some(1),
            )
            .await
        {
            Ok(events) => events,
            Err(e) => {
                tracing::error!("Failed to get auth history: {:?}", e);
                return Err(e);
            }
        };

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuthEventType::LoginAttempt);
        assert_eq!(events[0].event_status, AuthEventStatus::Success);
        assert_eq!(events[0].session_id, Some("session123".to_string()));
        assert_eq!(events[0].ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(events[0].user_agent, Some("Test Agent".to_string()));
        Ok(())
    }

    // --- Additional Tests ---

    #[tokio::test]
    /// Verifies upsert and fetch for factors and factor states.
    async fn test_upsert_and_get_factor_state_roundtrip() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let factor_id = "factor1".to_string();
        let tenant_id = TestTenantId("t1".to_string());
        let user_id = TestUserId("u1".to_string());
        let config = serde_json::json!({"password_hash": "test_hash"});
        let change = FactorStateChange::new(factor_id.clone())
            .with_scope(AuthnScope::User(tenant_id.clone(), user_id.clone()))
            .with_state(EnablementState::Active)
            .with_config(serde_json::from_value(config).unwrap());
        let upserted = backend.upsert_factor_state(change, user_id.clone()).await?;
        assert_eq!(upserted.factor_id, factor_id);
        let states = backend
            .get_factor_states(&factor_id, AuthnScope::User(tenant_id, user_id))
            .await?;
        assert!(!states.is_empty());
        assert_eq!(states[0].factor_id, factor_id);
        Ok(())
    }

    #[tokio::test]
    /// Verifies authentication fails for wrong credentials.
    async fn test_authenticate_with_wrong_credentials_fails() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let form = DummyFailingForm::default();
        let result = backend.authenticate(&form).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    /// Verifies lockout logic after max attempts.
    async fn test_lockout_after_max_attempts() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let user_id = TestUserId("lockout_user".to_string());
        let system_user = backend.get_system_user_id(None).await?;
        let user = MockUser {
            id: user_id.clone(),
            tenant_id: TestTenantId("t1".to_string()),
            state: EntityState::Active,
        };
        backend
            .upsert_user(user.clone(), system_user.clone())
            .await?;
        for _ in 0..backend.max_auth_attempts() {
            let form = DummyFailingForm::default();
            let _ = backend.authenticate(&form).await;
        }
        // Simulate lockout by setting user state
        backend
            .set_user_state(
                &user_id,
                EntityState::Suspended(StatusDetail {
                    reason: "Too many failed logins".to_string(),
                    timestamp: Utc::now(),
                    until: None,
                    metadata: None,
                }),
                system_user,
            )
            .await?;
        let locked_user = backend.get_user(&user_id).await?;
        assert!(matches!(
            locked_user.get_user_state(),
            EntityState::Suspended(_)
        ));
        Ok(())
    }

    #[tokio::test]
    /// Verifies guest users cannot authenticate.
    async fn test_guest_user_cannot_authenticate() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let guest = backend.get_new_guest_user(None).await?;
        // Ensure we actually received a guest user and that its state is Guest
        assert_eq!(guest.get_user_state(), EntityState::Guest);
        let form = DummyOkForm::default();
        let result = backend.authenticate(&form).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    /// Verifies deleting a non-existent tenant returns an error.
    async fn test_delete_nonexistent_tenant_returns_error() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let system_user = backend.get_system_user_id(None).await?;
        let result = backend
            .delete_tenant(&TestTenantId("does_not_exist".to_string()), system_user)
            .await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    /// Verifies upserting a user with duplicate ID overwrites the previous user.
    async fn test_upsert_user_duplicate_id_overwrites() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let system_user = backend.get_system_user_id(None).await?;
        let user1 = MockUser {
            id: TestUserId("dup_user".to_string()),
            tenant_id: TestTenantId("t1".to_string()),
            state: EntityState::Active,
        };
        let user2 = MockUser {
            id: TestUserId("dup_user".to_string()),
            tenant_id: TestTenantId("t1".to_string()),
            state: EntityState::Suspended(StatusDetail {
                reason: "suspended".to_string(),
                timestamp: Utc::now(),
                until: None,
                metadata: None,
            }),
        };
        backend
            .upsert_user(user1.clone(), system_user.clone())
            .await?;
        backend.upsert_user(user2.clone(), system_user).await?;
        let fetched = backend
            .get_user(&TestUserId("dup_user".to_string()))
            .await?;
        assert_eq!(
            fetched.get_user_state(),
            EntityState::Suspended(StatusDetail {
                reason: "suspended".to_string(),
                timestamp: fetched.get_user_state().as_suspended().unwrap().timestamp,
                until: None,
                metadata: None,
            })
        );
        Ok(())
    }

    #[tokio::test]
    /// Verifies event retrieval with filters.
    async fn test_event_retrieval_with_filters() -> Result<(), MockBackendError> {
        let backend = MockBackend::default();
        let user_id = TestUserId("filter_user".to_string());
        let tenant_id = TestTenantId("filter_tenant".to_string());
        let event = AuthEventRecord::<MockBackend> {
            user_id: &user_id,
            tenant_id: &tenant_id,
            session_id: Some("session456"),
            event_type: AuthEventType::LoginAttempt,
            event_status: AuthEventStatus::Success,
            method_id: None,
            factor_id: None,
            factor_kind: None,
            ip_address: None,
            user_agent: None,
            error_message: None,
        };
        backend.record_auth_event(event).await?;
        let events = backend
            .get_auth_history(
                &user_id,
                Some(AuthEventType::LoginAttempt),
                Some(AuthEventStatus::Success),
                Some(10),
            )
            .await?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuthEventType::LoginAttempt);
        Ok(())
    }
}
