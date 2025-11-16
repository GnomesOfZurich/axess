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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct StatusDetail {
    pub reason: String,
    pub timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", content = "data")]
pub enum EntityState {
    Guest,
    Candidate,
    Pending(StatusDetail),
    Active,
    Suspended(StatusDetail),
    Terminated(StatusDetail),
    Archived(StatusDetail),
}

pub trait AuthTenant: Debug + Clone + Send + Sync + Eq + PartialEq {
    type Id: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + 'static;

    fn id(&self) -> Self::Id;
    fn name(&self) -> String;
    fn get_tenant_state(&self) -> EntityState;
}

/// Enhanced user trait with tenant association
pub trait AuthUser: Debug + Clone + Send + Sync + Eq + PartialEq {
    type Id: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + 'static;
    type TenantId: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + 'static;

    fn id(&self) -> &Self::Id;
    fn tenant_id(&self) -> &Self::TenantId;
    fn get_user_state(&self) -> EntityState;
}

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

    /// Identifier type used for all other authentication reletated data objects associated with the backend.
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

    /// Gets the system super user for the given tenant, or the global system super user if none is provided.
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
    ) -> Result<AuthMethodState<Self>, Self::Error>;

    // Get the authentication factor by its ID.
    async fn get_auth_factor(
        &self,
        factor_id: &Self::FactorId,
    ) -> Result<AuthFactor<Self>, Self::Error>;

    /// Get all authentication factors in the system.
    async fn get_all_auth_factors(&self) -> Result<Vec<AuthFactor<Self>>, Self::Error>;

    /// Get all authentication factors for a given scope (global/user/tenant).
    async fn get_scoped_auth_factors(
        &self,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
        states: EnablementState,
    ) -> Result<Vec<AuthFactor<Self>>, Self::Error>;

    /// Get all factor states for a given factor ID and scope (global/user/tenant).
    async fn get_factor_states(
        &self,
        factor_id: &Self::FactorId,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthFactorState<Self>>, Self::Error>;

    async fn upsert_factor_state(
        &self,
        change: FactorStateChange<Self::FactorId, Self::TenantId, Self::UserId>,
    ) -> Result<AuthFactorState<Self>, Self::Error>;

    /// Get recent authentication events for a user
    ///
    /// Results are returned ordered by `event_time` descending (most recent first).
    ///
    /// # Arguments
    /// * `user_id` - The user ID to query events for
    /// * `event_type` - Optional filter by event type (e.g., only "Login" events)
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

    /// Get last successful login time for a user
    ///
    /// This is a convenience method that queries for the most recent successful
    /// `Authenticated` event.
    async fn get_last_login(
        &self,
        user_id: &Self::UserId,
    ) -> Result<Option<DateTime<Utc>>, Self::Error> {
        // Query for most recent successful authentication event
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

    /// Record an authentication event for a user
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
    ///
    async fn record_auth_event(&self, event: AuthEventRecord<'_, Self>) -> Result<(), Self::Error>;

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

    #[tokio::test]
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
    async fn test_get_user_returns_active_user()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let user = MockUser {
            id: TestUserId("u1".to_string()),
            tenant_id: TestTenantId("t1".to_string()),
            state: EntityState::Active,
        };
        backend.upsert_user(user.clone()).await?;

        let fetched = backend.get_user(&TestUserId("u1".to_string())).await?;
        assert_eq!(fetched.get_user_state(), EntityState::Active);
        Ok(())
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn test_set_user_state_changes_state()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let user = MockUser {
            id: TestUserId("u2".to_string()),
            tenant_id: TestTenantId("t2".to_string()),
            state: EntityState::Active,
        };
        backend.upsert_user(user.clone()).await?;

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
    async fn test_upsert_user_roundtrip() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let user = MockUser {
            id: TestUserId("u3".to_string()),
            tenant_id: TestTenantId("t3".to_string()),
            state: EntityState::Active,
        };
        let upserted = backend.upsert_user(user.clone()).await?;
        assert_eq!(upserted, user);
        Ok(())
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn test_upsert_and_get_tenant_roundtrip()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let tenant = MockTenant::default().with_id(TestTenantId("tenant42".to_string()));
        let upserted = backend.upsert_tenant(tenant.clone()).await?;
        assert_eq!(upserted, tenant);

        let fetched = backend.get_tenant(&tenant.id()).await?;
        assert_eq!(fetched, tenant);

        Ok(())
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn test_delete_tenant_returns_ok() {
        let backend = MockBackend::default();
        let tenant = MockTenant::default().with_id(TestTenantId("tenant_delete".to_string()));
        let result = backend.delete_tenant(&tenant.id()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_default_tenant_id_returns_default()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();
        let tenant = backend.get_default_tenant_id().await?;
        assert_eq!(tenant, MockTenant::default().id());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_auth_method_not_implemented() {
        let backend = MockBackend::default();
        let result = backend
            .get_auth_method(&"some_random_dummy_method".to_string())
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_user_serialization_deserialization() -> Result<(), serde_json::Error> {
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
    fn test_tenant_serialization_deserialization() -> Result<(), serde_json::Error> {
        let tenant = TestTenantId("tenant_serial".to_string());
        let json = serde_json::to_string(&tenant)?;
        let deserialized: TestTenantId = serde_json::from_str(&json)?;
        assert_eq!(tenant, deserialized);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_auth_method_returns_method()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();

        #[cfg(feature = "admin")]
        {
            let method = mock_method();

            backend.upsert_auth_method(method.clone()).await?;

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
    async fn test_authenticate_with_inactive_user_returns_error()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backend = MockBackend::default();

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

            backend.upsert_user(user).await?;

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
