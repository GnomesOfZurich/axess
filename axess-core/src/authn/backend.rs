//! Core backend abstraction for Axess authentication.
//!
//! This module standardizes how storage backends interact with Axess:
//! - Identifier traits (`TenantId`, `UserId`, `FactorId`, `MethodId`, `DataId`) that
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
    methods::{
        MethodStateChange,
        factor::FactorStateChange,
        form::FactorForm,
        scope::{EnablementState, PermissionScope},
    },
    session::state::{AuthEvent, AuthEventRecord, AuthEventStatus, AuthEventType},
    types::{AuthFactor, AuthFactorState, AuthMethod, AuthMethodState},
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

pub trait FactorId:
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
pub trait MethodId:
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

pub trait DataId:
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

impl<T> FactorId for T where
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

impl<T> MethodId for T where
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

impl<T> DataId for T where
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
/// ```rust,ignore
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
/// ```rust,ignore
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
/// ```rust,ignore
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
/// ```rust,ignore
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
/// - `MethodId`: Authentication method identifier type.
/// - `FactorId`: Authentication factor identifier type.
/// - `DataId`: General-purpose data identifier type.
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
///     type MethodId = String;
///     type FactorId = String;
///     type DataId = String;
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
    type MethodId: MethodId;
    type FactorId: FactorId;

    /// Identifier for other general data types associated with the backend.
    type DataId: DataId;

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

    /// Sets the state of a user (e.g., Active, Suspended, Terminated).
    async fn set_user_state(
        &self,
        user_id: &Self::UserId,
        new_state: EntityState,
    ) -> Result<Self::User, Self::Error>;

    /// Get the authentication method by its ID.
    async fn get_auth_method(
        &self,
        method_id: &Self::MethodId,
    ) -> Result<AuthMethod<Self>, Self::Error>;

    /// Get all authentication methods in the system.
    async fn get_all_auth_methods(&self) -> Result<Vec<AuthMethod<Self>>, Self::Error>;

    /// Get all Authentication methods for a given scope (global/user/tenant), potentially filtered by state (e.g. 'Active').
    async fn get_scoped_auth_methods(
        &self,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
        state: EnablementState,
    ) -> Result<Vec<AuthMethod<Self>>, Self::Error>;

    /// Get all method states for a given method ID and scope (global/user/tenant).
    async fn get_method_states(
        &self,
        method_id: &Self::MethodId,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthMethodState<Self>>, Self::Error>;

    /// Upsert (insert or update) the state of an authentication method for a given scope (global/user/tenant).
    async fn upsert_method_state(
        &self,
        change: MethodStateChange<Self::MethodId, Self::TenantId, Self::UserId>,
        actor: Self::UserId,
    ) -> Result<AuthMethodState<Self>, Self::Error>;

    /// Get the authentication factor by its ID.
    async fn get_auth_factor(
        &self,
        factor_id: &Self::FactorId,
    ) -> Result<AuthFactor<Self>, Self::Error>;

    /// Get all authentication factors in the system.
    async fn get_all_auth_factors(&self) -> Result<Vec<AuthFactor<Self>>, Self::Error>;

    /// Get all authentication factors for a given scope (global/user/tenant).
    /// This includes both enabled and disabled factors.
    /// # Arguments
    /// * `scope` - The permission scope to filter factors (global/user/tenant)
    /// * `states` - Vector of enablement states to filter factors (e.g., Active, Inactive)
    /// # Returns
    /// Vector of authentication factors matching the specified scope and states
    /// Expects the return of an empty vector if no factors match the criteria.
    async fn get_scoped_auth_factors(
        &self,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
        states: Vec<EnablementState>,
    ) -> Result<Vec<AuthFactor<Self>>, Self::Error>;

    /// Get all factor states for a given factor ID and scope (global/user/tenant).
    async fn get_factor_states(
        &self,
        factor_id: &Self::FactorId,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthFactorState<Self>>, Self::Error>;

    /// Upsert (insert or update) the state of an authentication factor for a given scope (global/user/tenant).
    async fn upsert_factor_state(
        &self,
        change: FactorStateChange<Self::FactorId, Self::TenantId, Self::UserId>,
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
    async fn authenticate<'a, F>(&self, creds: &'a F) -> Result<Self::User, Self::Error>
    where
        F: FactorForm + Send + Sync;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "admin")]
    use crate::authn::backend::admin::AuthnAdminBackend;
    use crate::{
        authn::session::state::{AuthEventStatus, AuthEventType},
        utils::testing::{
            mock_authn::mock_method,
            mock_backend::MockBackend,
            mock_entities::{MockTenant, MockUser, TestTenantId, TestUserId},
        },
    };
    use serde_json::Error as JsonError;

    #[tokio::test]
    /// Ensures get_new_guest_user returns a guest user for the specified tenant.
    async fn test_get_new_guest_user_returns_guest()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let guest = backend
            .get_new_guest_user(Some(&TestTenantId("t1".to_string())))
            .await?;
        assert_eq!(guest.get_user_state(), EntityState::Guest);
        assert_eq!(guest.tenant_id(), &TestTenantId("t1".to_string()));
        Ok(())
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    /// Verifies that get_user returns an active user after upsert.
    async fn test_get_user_returns_active_user()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let system_user = backend.get_system_user_id(None).await?;
        let user = MockUser {
            id: TestUserId("u1".to_string()),
            tenant_id: TestTenantId("t1".to_string()),
            state: EntityState::Active,
        };
        backend.upsert_user(user.clone(), system_user).await?;

        let fetched = backend.get_user(&TestUserId("u1".to_string())).await?;
        assert_eq!(fetched.get_user_state(), EntityState::Active);
        Ok(())
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    /// Checks that set_user_state changes the user's state as expected.
    async fn test_set_user_state_changes_state()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let system_user = backend.get_system_user_id(None).await?;
        let user = MockUser {
            id: TestUserId("u2".to_string()),
            tenant_id: TestTenantId("t2".to_string()),
            state: EntityState::Active,
        };
        backend.upsert_user(user.clone(), system_user).await?;

        let updated = backend
            .set_user_state(
                &TestUserId("u2".to_string()),
                EntityState::Suspended(StatusDetail {
                    reason: "test".to_string(),
                    timestamp: Utc::now(),
                    until: None,
                    metadata: None,
                }),
            )
            .await?;
        assert!(matches!(
            updated.get_user_state(),
            EntityState::Suspended(_)
        ));
        Ok(())
    }
    #[cfg(feature = "admin")]
    #[tokio::test]
    /// Verifies upsert_user correctly inserts and retrieves a user.
    async fn test_upsert_user_roundtrip() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let system_user = backend.get_system_user_id(None).await?;
        let user = MockUser {
            id: TestUserId("u3".to_string()),
            tenant_id: TestTenantId("t3".to_string()),
            state: EntityState::Active,
        };
        let upserted = backend.upsert_user(user.clone(), system_user).await?;
        assert_eq!(upserted, user);
        Ok(())
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    /// Verifies upsert_tenant correctly inserts and retrieves a tenant.
    async fn test_upsert_and_get_tenant_roundtrip()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let system_user = backend.get_system_user_id(None).await?;
        let tenant = MockTenant::default().with_id(TestTenantId("tenant42".to_string()));
        let upserted = backend.upsert_tenant(tenant.clone(), system_user).await?;
        assert_eq!(upserted, tenant);

        let fetched = backend.get_tenant(&tenant.id()).await?;
        assert_eq!(fetched, tenant);

        Ok(())
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    /// Checks that delete_tenant returns Ok when deleting a tenant.
    async fn test_delete_tenant_returns_ok() {
        let backend = MockBackend::default();
        let system_user = backend.get_system_user_id(None).await.unwrap();
        let tenant = MockTenant::default().with_id(TestTenantId("tenant_delete".to_string()));
        let result = backend.delete_tenant(&tenant.id(), system_user).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    /// Ensures get_default_tenant_id returns the default tenant.
    async fn test_get_default_tenant_id_returns_default()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    #[test]
    /// Checks user serialization and deserialization roundtrip.
    fn test_user_serialization_deserialization() -> Result<(), JsonError> {
        let user = MockUser {
            id: TestUserId("u99".to_string()),
            tenant_id: TestTenantId("t99".to_string()),
            state: EntityState::Active,
        };
        let json = serde_json::to_string(&user)?;
        let deserialized: MockUser = serde_json::from_str(&json)?;
        assert_eq!(user, deserialized);
        Ok(())
    }

    #[test]
    /// Checks tenant ID serialization and deserialization roundtrip.
    fn test_tenant_serialization_deserialization() -> Result<(), JsonError> {
        let tenant = TestTenantId("tenant_serial".to_string());
        let json = serde_json::to_string(&tenant)?;
        let deserialized: TestTenantId = serde_json::from_str(&json)?;
        assert_eq!(tenant, deserialized);
        Ok(())
    }

    #[tokio::test]
    /// Verifies get_auth_method returns the correct method when present.
    async fn test_get_auth_method_returns_method()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let system_user = backend.get_system_user_id(None).await?;

        #[cfg(feature = "admin")]
        {
            let method = mock_method();

            backend
                .upsert_auth_method(method.clone(), system_user)
                .await?;

            let retrieved = backend.get_auth_method(&method.id).await?;

            assert_eq!(retrieved.id, method.id);
            assert_eq!(retrieved.name, method.name);
            assert_eq!(retrieved.description, method.description);
            assert_eq!(retrieved.factors.len(), method.factors.len());
        }

        #[cfg(not(feature = "admin"))]
        {
            // Without admin feature, get_auth_method should return an error
            let result = backend.get_auth_method(&"test_method".to_string()).await;
            assert!(result.is_err());
        }

        Ok(())
    }

    #[tokio::test]
    /// Ensures authenticate returns an error for inactive users.
    async fn test_authenticate_with_inactive_user_returns_error()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let system_user = backend.get_system_user_id(None).await?;

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

            backend.upsert_user(user, system_user).await?;

            // Verify user state is not active
            let fetched = backend
                .get_user(&TestUserId("suspended_user".to_string()))
                .await?;

            assert!(matches!(
                fetched.get_user_state(),
                EntityState::Suspended(_)
            ));
        }

        Ok(())
    }

    #[tokio::test]
    /// Checks that record_auth_event and get_auth_history work as a roundtrip.
    async fn test_record_and_retrieve_auth_event_roundtrip()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

        backend.record_auth_event(event).await?;

        // Retrieve event
        let events = backend
            .get_auth_history(
                &user_id,
                Some(AuthEventType::LoginAttempt),
                Some(AuthEventStatus::Success),
                Some(1),
            )
            .await?;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuthEventType::LoginAttempt);
        assert_eq!(events[0].event_status, AuthEventStatus::Success);
        assert_eq!(events[0].session_id, Some("session123".to_string()));
        assert_eq!(events[0].ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(events[0].user_agent, Some("Test Agent".to_string()));

        Ok(())
    }
}
