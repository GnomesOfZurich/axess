use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
// use tower_cookies::cookie::time::Date;
use std::{cmp::PartialEq, fmt::Debug, hash::Hash};
// use chrono::{DateTime, Utc};
use crate::authn::{
    methods::{
        form::FactorForm,
        scope::{EnablementState, PermissionScope},
    },
    session::auth_session::{AuthFactor, AuthFactorState, AuthMethod},
};

pub trait TenantId:
    Clone + Debug + Eq + PartialEq + Hash + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}

pub trait UserId:
    Clone + Debug + Eq + PartialEq + Hash + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}

pub trait FactorId:
    Clone + Debug + Eq + PartialEq + Hash + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}
pub trait MethodId:
    Clone + Debug + Eq + PartialEq + Hash + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}

pub trait DataId:
    Clone + Debug + Eq + PartialEq + Hash + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}

impl<T> TenantId for T where
    T: Clone + Debug + Eq + PartialEq + Hash + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}

impl<T> UserId for T where
    T: Clone + Debug + Eq + PartialEq + Hash + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}

impl<T> FactorId for T where
    T: Clone + Debug + Eq + PartialEq + Hash + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}

impl<T> MethodId for T where
    T: Clone + Debug + Eq + PartialEq + Hash + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}

impl<T> DataId for T where
    T: Clone + Debug + Eq + PartialEq + Hash + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct EntityStateInfo {
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SuspensionInfo {
    pub reason: String,
    pub until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", content = "data")]
pub enum EntityState {
    Guest,
    Pending(EntityStateInfo),
    Active,
    Suspended(SuspensionInfo),
    Terminated(EntityStateInfo),
    Archived(EntityStateInfo),
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

    fn auth_session_hash(&self) -> Option<&str>;
    fn set_auth_session_hash(&mut self, hash: Option<String>);
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
    // type MethodState: Serialize + for<'de> Deserialize<'de> + Debug + Clone + Send + Sync;
    type FactorId: FactorId;
    // type FactorState: Serialize + for<'de> Deserialize<'de> + Debug + Clone + Send + Sync;

    /// Identifier for other general data types associated with the backend.
    type DataId: DataId;

    /// An error which can occur during authentication and authorization.
    type Error: Debug + Send + Sync + 'static;

    /// Gets the tenant by provided ID from the backend.
    async fn get_tenant(&self, tenant_id: &Self::TenantId) -> Result<Self::Tenant, Self::Error>;

    async fn get_tenant_by_name(&self, name: &str) -> Result<Self::Tenant, Self::Error>;

    async fn get_default_tenant_id(&self) -> Result<Self::TenantId, Self::Error>;

    /// Gets the user by provided ID from the backend.
    async fn get_user(&self, user_id: &Self::UserId) -> Result<Self::User, Self::Error>;

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
        scope: PermissionScope<&Self::TenantId, &Self::UserId>,
        state: Option<EnablementState>,
    ) -> Result<Vec<AuthMethod<Self>>, Self::Error>;

    async fn get_factor_states(
        &self,
        factor_id: &Self::FactorId,
        scope: PermissionScope<&Self::TenantId, &Self::UserId>,
    ) -> Result<Vec<AuthFactorState<Self>>, Self::Error>;

    // Get the authentication factor by its ID.
    async fn get_auth_factor(
        &self,
        factor_id: &Self::FactorId,
    ) -> Result<AuthFactor<Self>, Self::Error>;

    async fn get_all_auth_factors(&self) -> Result<Vec<AuthFactor<Self>>, Self::Error>;

    /// Get all authentication factors for a given scope (global/user/tenant).
    async fn get_scoped_auth_factors(
        &self,
        scope: PermissionScope<&Self::TenantId, &Self::UserId>,
        state: Option<EnablementState>,
    ) -> Result<Vec<AuthFactor<Self>>, Self::Error>;

    async fn authenticate<'a, F>(&self, creds: &'a F) -> Result<Self::User, Self::Error>
    where
        F: FactorForm + Send + Sync;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "admin")]
    use crate::authn::admin::admin_backend::AuthnAdminBackend;
    use crate::utils::testing::mock_backend::{
        MockBackend, MockTenant, MockUser, TestTenantId, TestUserId,
    };

    #[tokio::test]
    async fn test_get_new_guest_user_returns_guest() {
        let backend = MockBackend::default();
        let guest = backend
            .get_new_guest_user(Some(&TestTenantId("t1".to_string())))
            .await
            .unwrap();
        assert_eq!(guest.get_user_state(), EntityState::Guest);
        assert_eq!(guest.tenant_id(), &TestTenantId("t1".to_string()));
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn test_get_user_returns_active_user() {
        let backend = MockBackend::default();
        let user = MockUser {
            id: TestUserId("u1".to_string()),
            tenant_id: TestTenantId("t1".to_string()),
            state: EntityState::Active,
            session_hash: Some("session123".to_string()),
        };
        backend.upsert_user(user.clone()).await.unwrap();

        let fetched = backend
            .get_user(&TestUserId("u1".to_string()))
            .await
            .unwrap();
        assert_eq!(fetched.get_user_state(), EntityState::Active);
        assert_eq!(fetched.auth_session_hash(), Some("session123"));
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn test_set_user_state_changes_state() {
        let backend = MockBackend::default();
        let user = MockUser {
            id: TestUserId("u2".to_string()),
            tenant_id: TestTenantId("t2".to_string()),
            state: EntityState::Active,
            session_hash: None,
        };
        backend.upsert_user(user.clone()).await.unwrap();

        let updated = backend
            .set_user_state(
                &TestUserId("u2".to_string()),
                EntityState::Suspended(SuspensionInfo {
                    reason: "test".to_string(),
                    until: None,
                }),
            )
            .await
            .unwrap();
        assert!(matches!(
            updated.get_user_state(),
            EntityState::Suspended(_)
        ));
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn test_upsert_user_roundtrip() {
        let backend = MockBackend::default();
        let user = MockUser {
            id: TestUserId("u3".to_string()),
            tenant_id: TestTenantId("t3".to_string()),
            state: EntityState::Active,
            session_hash: Some("xyz789".to_string()),
        };
        let upserted = backend.upsert_user(user.clone()).await.unwrap();
        assert_eq!(upserted, user);
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn test_upsert_and_get_tenant_roundtrip() {
        let backend = MockBackend::default();
        let tenant = MockTenant::default().with_id(TestTenantId("tenant42".to_string()));
        let upserted = backend.upsert_tenant(tenant.clone()).await.unwrap();
        assert_eq!(upserted, tenant);

        let fetched = backend.get_tenant(&tenant.id()).await.unwrap();
        assert_eq!(fetched, tenant);
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
    async fn test_get_default_tenant_id_returns_default() {
        let backend = MockBackend::default();
        let tenant = backend.get_default_tenant_id().await.unwrap();
        assert_eq!(tenant, MockTenant::default().id());
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
    fn test_user_serialization_deserialization() {
        let user = MockUser {
            id: TestUserId("u99".to_string()),
            tenant_id: TestTenantId("t99".to_string()),
            state: EntityState::Active,
            session_hash: Some("hash99".to_string()),
        };
        let json = serde_json::to_string(&user).unwrap();
        let deserialized: MockUser = serde_json::from_str(&json).unwrap();
        assert_eq!(user, deserialized);
    }

    #[test]
    fn test_tenant_serialization_deserialization() {
        let tenant = TestTenantId("tenant_serial".to_string());
        let json = serde_json::to_string(&tenant).unwrap();
        let deserialized: TestTenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(tenant, deserialized);
    }
}
