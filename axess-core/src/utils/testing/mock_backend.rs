#[cfg(feature = "admin")]
use crate::authn::admin::AuthnAdminBackend;
use crate::authn::{
    backend::{AuthTenant, AuthUser, AuthnBackend, EntityState},
    methods::{factor::FactorStateChange, method::MethodStateChange, EnablementState, FactorForm, PermissionScope},
    session::{AuthFactor, AuthFactorState, AuthMethod, AuthMethodState},
};

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

// TODO: Consider letting the mock backend be anin-memory SQLite database
// use sqlx::SqlitePool;

// async fn create_test_backend() -> OurBackend {
//     let pool = SqlitePool::connect(":memory:").await.unwrap();
//     OurBackend::new(pool)
// }

const SYSTEM_SUPER_USER_ID: &str = "SYSTEM_SUPER_USER_ID";
const TENANT_SUPER_USER_ID: &str = "TENANT_SUPER_USER_ID";
const DEFAULT_TENANT_NAME: &str = "Default Tenant";
const DEFAULT_TENANT_ID: &str = "DEFAULT_TENANT_ID";
const DEFAULT_USER_ID: &str = "DEFAULT_USER_ID";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TestTenantId(pub String);

impl From<&str> for TestTenantId {
    fn from(s: &str) -> Self {
        TestTenantId(s.to_string())
    }
}

impl Display for TestTenantId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<String> for TestTenantId {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<TestTenantId> for String {
    fn eq(&self, other: &TestTenantId) -> bool {
        *self == other.0
    }
}

impl PartialEq<&str> for TestTenantId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<TestTenantId> for &str {
    fn eq(&self, other: &TestTenantId) -> bool {
        *self == other.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockTenant {
    pub id: TestTenantId,
    pub name: String,
    pub description: String,
    pub state: EntityState,
}

impl MockTenant {
    pub fn with_id(&mut self, id: TestTenantId) -> Self {
        self.id = id;
        self.clone()
    }
}

impl Default for MockTenant {
    fn default() -> Self {
        Self {
            id: DEFAULT_TENANT_ID.into(),
            name: DEFAULT_TENANT_NAME.to_string(),
            description: "This is the default tenant".to_string(),
            state: EntityState::Active,
        }
    }
}

impl AuthTenant for MockTenant {
    type Id = TestTenantId;

    fn id(&self) -> Self::Id {
        self.id.clone()
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn get_tenant_state(&self) -> EntityState {
        self.state.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TestUserId(pub String);

impl Display for TestUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for TestUserId {
    fn from(s: &str) -> Self {
        TestUserId(s.to_string())
    }
}

impl PartialEq<String> for TestUserId {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<TestUserId> for String {
    fn eq(&self, other: &TestUserId) -> bool {
        *self == other.0
    }
}

impl PartialEq<&str> for TestUserId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<TestUserId> for &str {
    fn eq(&self, other: &TestUserId) -> bool {
        *self == other.0
    }
}


impl TestUserId {
    /// Returns the user ID as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TestTenantId {
    /// Returns the tenant ID as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for TestUserId {
    type Target = str;
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::Deref for TestTenantId {
    type Target = str;
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for TestUserId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TestTenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockUser {
    pub id: TestUserId,
    pub tenant_id: TestTenantId,
    pub state: EntityState,
    pub session_hash: Option<String>,
}

impl Default for MockUser {
    fn default() -> Self {
        Self {
            id: TestUserId("default_user".to_string()),
            tenant_id: DEFAULT_TENANT_ID.into(),
            state: EntityState::Active,
            session_hash: None,
        }
    }
}

impl AuthUser for MockUser {
    type Id = TestUserId;
    type TenantId = TestTenantId;
    fn id(&self) -> &Self::Id {
        &self.id
    }
    fn tenant_id(&self) -> &Self::TenantId {
        &self.tenant_id
    }
    fn get_user_state(&self) -> EntityState {
        self.state.clone()
    }
    fn auth_session_hash(&self) -> Option<&str> {
        self.session_hash.as_deref()
    }
    fn set_auth_session_hash(&mut self, hash: Option<String>) {
        self.session_hash = hash;
    }
}

type MockAuthFactor = AuthFactor<MockBackend>;
type MockAuthFactorState = AuthFactorState<MockBackend>;
type MockAuthMethod = AuthMethod<MockBackend>;
type MockAuthMethodState = AuthMethodState<MockBackend>;

#[derive(Debug)]
pub struct MockBackend {
    pub users: DashMap<TestUserId, MockUser>,
    pub tenants: DashMap<TestTenantId, MockTenant>,
    pub auth_factors: DashMap<String, MockAuthFactor>,
    pub auth_factor_states: DashMap<String, MockAuthFactorState>,
    pub auth_methods: DashMap<String, MockAuthMethod>,
    pub auth_method_states: DashMap<String, MockAuthMethodState>,
}

impl Clone for MockBackend {
    fn clone(&self) -> Self {
        let users = self.users.clone();
        let tenants = self.tenants.clone();
        let auth_factors = self.auth_factors.clone();
        let auth_factor_states = self.auth_factor_states.clone();
        let auth_methods = self.auth_methods.clone();
        let auth_method_states = self.auth_method_states.clone();

        Self {
            users,
            tenants,
            auth_factors,
            auth_factor_states,
            auth_methods,
            auth_method_states,
        }
    }
    // fn clone(&self) -> Self {
    //     let users = DashMap::new();
    //     for entry in self.users.iter() {
    //         users.insert(entry.key().clone(), entry.value().clone());
    //     }
    //     let tenants = DashMap::new();
    //     for entry in self.tenants.iter() {
    //         tenants.insert(entry.key().clone(), entry.value().clone());
    //     }
    //     let auth_factors = DashMap::new();
    //     for entry in self.auth_factors.iter() {
    //         auth_factors.insert(entry.key().clone(), entry.value().clone());
    //     }
    //     let auth_factor_states = DashMap::new();
    //     for entry in self.auth_factor_states.iter() {
    //         auth_factor_states.insert(entry.key().clone(), entry.value().clone());
    //     }
    //     let auth_methods = DashMap::new();
    //     for entry in self.auth_methods.iter() {
    //         auth_methods.insert(entry.key().clone(), entry.value().clone());
    //     }
    //     let auth_method_states = DashMap::new();
    //     for entry in self.auth_method_states.iter() {
    //         auth_method_states.insert(entry.key().clone(), entry.value().clone());
    //     }
    //     Self {
    //         users,
    //         tenants,
    //         auth_factors,
    //         auth_factor_states,
    //         auth_methods,
    //         auth_method_states,
    //     }
    // }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            users: DashMap::new(),
            tenants: DashMap::new(),
            auth_factors: DashMap::new(),
            auth_factor_states: DashMap::new(),
            auth_methods: DashMap::new(),
            auth_method_states: DashMap::new(),
        }
    }
}

#[async_trait]
impl AuthnBackend for MockBackend {
    type User = MockUser;
    type UserId = TestUserId;
    type Tenant = MockTenant;
    type TenantId = TestTenantId;
    type MethodId = String;
    // type MethodState: AuthMethodState<Self>;
    type FactorId = String;
    // type FactorState = AuthFactorState<Self>;
    type DataId = String;
    type Error = String;

    async fn get_tenant(&self, tenant_id: &Self::TenantId) -> Result<Self::Tenant, Self::Error> {
        self.tenants
            .get(tenant_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| "Tenant not found".to_string())
    }

    async fn get_tenant_by_name(&self, name: &str) -> Result<Self::Tenant, Self::Error> {
        self.tenants
            .iter()
            .find(|entry| entry.value().name == name)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| "Tenant not found".to_string())
    }

    async fn get_default_tenant_id(&self) -> Result<Self::TenantId, Self::Error> {
        Ok(MockTenant::default().id())
    }

    async fn get_user(&self, user_id: &Self::UserId) -> Result<Self::User, Self::Error> {
        self.users
            .get(user_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| "User not found".to_string())
    }

    async fn get_user_by_name(
        &self,
        tenant_id: &Self::TenantId,
        username: &str,
    ) -> Result<Self::User, Self::Error> {
        self.users
            .iter()
            .find(|entry| entry.value().tenant_id == *tenant_id && entry.value().id.0 == username)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| "User not found".to_string())
    }

    async fn get_system_user_id(
        &self,
        tenant_id: Option<&Self::TenantId>,
    ) -> Result<Self::UserId, Self::Error> {
        match tenant_id {
            // Compare the inner string explicitly to avoid ambiguous `Into`/`From<&str>` impls
            Some(tid) if tid.0.as_str() == DEFAULT_TENANT_ID => {
                Ok(TestUserId(TENANT_SUPER_USER_ID.to_string()))
            }
            Some(_) => Err("User not found".to_string()),
            None => Ok(TestUserId(SYSTEM_SUPER_USER_ID.to_string())),
        }
    }

    async fn set_user_state(
        &self,
        user_id: &Self::UserId,
        new_state: EntityState,
    ) -> Result<Self::User, Self::Error> {
        if let Some(mut entry) = self.users.get_mut(user_id) {
            entry.state = new_state;
            Ok(entry.clone())
        } else {
            Err("User not found".to_string())
        }
    }

    async fn get_new_guest_user(
        &self,
        tenant_id: Option<&Self::TenantId>,
    ) -> Result<Self::User, Self::Error> {
        Ok(MockUser {
            id: TestUserId("guest".to_string()),
            tenant_id: tenant_id
                .cloned()
                .unwrap_or(TestTenantId("default".to_string())),
            state: EntityState::Guest,
            session_hash: None,
        })
    }

    async fn get_auth_method(
        &self,
        method_id: &Self::MethodId,
    ) -> Result<AuthMethod<Self>, Self::Error> {
        self.auth_methods
            .get(method_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| "Method not found".to_string())
    }

    async fn get_all_auth_methods(&self) -> Result<Vec<AuthMethod<Self>>, Self::Error> {
        Ok(self
            .auth_methods
            .iter()
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn get_scoped_auth_methods(
        &self,
        _scope: PermissionScope<Self::TenantId, Self::UserId>,
        _state: EnablementState,
    ) -> Result<Vec<AuthMethod<Self>>, Self::Error> {
        Ok(self
            .auth_methods
            .iter()
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn get_method_states(
        &self,
        method_id: &Self::MethodId,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthMethodState<Self>>, Self::Error> {
        Ok(self
            .auth_method_states
            .iter()
            .filter(|entry| {
                &entry.value().method_id == method_id
                    && match &scope {
                        PermissionScope::Global | PermissionScope::Any => true,
                        PermissionScope::Tenant(tenant_id) => {
                            entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                == Some(tenant_id.0.as_str())
                        }
                        PermissionScope::User(tenant_id, user_id) => {
                            entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                == Some(tenant_id.0.as_str())
                                && entry.value().user_id.as_ref().map(|u| u.as_str())
                                    == Some(user_id.0.as_str())
                        }
                    }
            })
            .map(|entry| entry.value().clone())
            .collect())
    }

    /// Upserts (inserts or updates) the authentication method state for the given method.
    /// If a state for the method already exists, it will be updated; otherwise, it will be inserted.
    async fn upsert_method_state(
        &self,
        change: MethodStateChange<Self::MethodId, Self::TenantId, Self::UserId>,
    ) -> Result<AuthMethodState<Self>, Self::Error> {
        // Create natural key from method_id, tenant_id, user_id
        let key = format!(
            "{}:{}:{}",
            change.method_id,
            change
                .tenant_id
                .as_ref()
                .map(|t| t.to_string())
                .unwrap_or_else(|| "null".to_string()),
            change
                .user_id
                .as_ref()
                .map(|u| u.to_string())
                .unwrap_or_else(|| "null".to_string())
        );

        let now = Utc::now();

        // Check if state exists first (borrow only)
        let existing_id_and_audit = self.auth_method_states.get(&key).map(|existing| {
            (
                existing.id.clone(),
                existing.created_at,
                existing.created_by.clone(),
            )
        });

        // Build method state based on whether it exists
        let method_state = if let Some((id, created_at, created_by)) = existing_id_and_audit {
            // Update: preserve existing audit trail
            AuthMethodState::<MockBackend> {
                id,
                method_id: change.method_id,
                tenant_id: change.tenant_id,
                user_id: change.user_id,
                state: change.state,
                created_at,
                created_by,
                updated_at: now,
                updated_by: change.updated_by,
            }
        } else {
            // Insert: generate new ID
            let id = format!("method_state_{}", self.auth_method_states.len());

            AuthMethodState::<MockBackend> {
                id,
                method_id: change.method_id,
                tenant_id: change.tenant_id,
                user_id: change.user_id,
                state: change.state,
                created_at: now,
                created_by: change.updated_by.clone(),
                updated_at: now,
                updated_by: change.updated_by,
            }
        };

        // Store and return
        self.auth_method_states
            .insert(key, method_state.clone());
        Ok(method_state)
    }

    async fn get_auth_factor(
        &self,
        factor_id: &Self::FactorId,
    ) -> Result<AuthFactor<Self>, Self::Error> {
        self.auth_factors
            .get(factor_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| "Factor not found".to_string())
    }

    async fn get_all_auth_factors(&self) -> Result<Vec<AuthFactor<Self>>, Self::Error> {
        Ok(self
            .auth_factors
            .iter()
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn get_scoped_auth_factors(
        &self,
        _scope: PermissionScope<Self::TenantId, Self::UserId>,
        _state: EnablementState,
    ) -> Result<Vec<AuthFactor<Self>>, Self::Error> {
        // For mock implementation, return empty vector
        Ok(Vec::new())
    }

    async fn get_factor_states(
        &self,
        factor_id: &Self::FactorId,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthFactorState<Self>>, Self::Error> {
        Ok(self
            .auth_factor_states
            .iter()
            .filter(|entry| {
                &entry.value().factor_id == factor_id
                    && match &scope {
                        PermissionScope::Global | PermissionScope::Any => true,
                        PermissionScope::Tenant(tenant_id) => {
                            entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                == Some(tenant_id.0.as_str())
                        }
                        PermissionScope::User(tenant_id, user_id) => {
                            entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                == Some(tenant_id.0.as_str())
                                && entry.value().user_id.as_ref().map(|u| u.as_str())
                                    == Some(user_id.0.as_str())
                        }
                    }
            })
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn upsert_factor_state(
        &self,
        change: FactorStateChange<Self::FactorId, Self::TenantId, Self::UserId>,
    ) -> Result<AuthFactorState<Self>, Self::Error> {
        // Create natural key from factor_id, tenant_id, user_id
        let key = format!(
            "{}:{}:{}",
            change.factor_id,
            change
                .tenant_id
                .as_ref()
                .map(|t| t.to_string())
                .unwrap_or_else(|| "null".to_string()),
            change
                .user_id
                .as_ref()
                .map(|u| u.to_string())
                .unwrap_or_else(|| "null".to_string())
        );

        let now = Utc::now();

        // Check if state exists first (borrow only)
        let existing_id_and_audit = self.auth_factor_states.get(&key).map(|existing| {
            (
                existing.id.clone(),
                existing.created_at,
                existing.created_by.clone(),
            )
        });

        // Build factor state based on whether it exists
        let factor_state = if let Some((id, created_at, created_by)) = existing_id_and_audit {
            // Update: preserve existing audit trail
            // AuthFactorState type params: <DataId, FactorId, UserId, TenantId>
            AuthFactorState::<MockBackend> {
                id,
                factor_id: change.factor_id,
                tenant_id: change.tenant_id,
                user_id: change.user_id,
                state: change.state,
                config: change.config,
                created_at,
                created_by,
                updated_at: now,
                updated_by: change.updated_by,
            }
        } else {
            // Insert: generate new ID
            let id = format!("factor_state_{}", self.auth_factor_states.len());

            AuthFactorState::<MockBackend> {
                id,
                factor_id: change.factor_id,
                tenant_id: change.tenant_id,
                user_id: change.user_id,
                state: change.state,
                config: change.config,
                created_at: now,
                created_by: change.updated_by.clone(),
                updated_at: now,
                updated_by: change.updated_by,
            }
        };

        // Store and return
        self.auth_factor_states
            .insert(key, factor_state.clone());
        Ok(factor_state)
    }

    async fn authenticate<'a, F>(&self, _creds: &'a F) -> Result<Self::User, Self::Error>
    where
        F: FactorForm + Send + Sync,
    {
        // For mock implementation, return a default active user
        Ok(MockUser {
            id: DEFAULT_USER_ID.into(),
            tenant_id: DEFAULT_TENANT_ID.into(),
            state: EntityState::Active,
            session_hash: Some("mock_session_hash".to_string()),
        })
    }
}

#[cfg(feature = "admin")]
#[async_trait]
impl AuthnAdminBackend for MockBackend {
    async fn upsert_user(&self, user: Self::User) -> Result<Self::User, Self::Error> {
        self.users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn delete_user(&self, user_id: &Self::UserId) -> Result<(), Self::Error> {
        self.users.remove(user_id);
        Ok(())
    }

    async fn upsert_tenant(&self, tenant: Self::Tenant) -> Result<Self::Tenant, Self::Error> {
        self.tenants.insert(tenant.id.clone(), tenant.clone());
        Ok(tenant)
    }

    async fn delete_tenant(&self, tenant_id: &Self::TenantId) -> Result<(), Self::Error> {
        self.tenants.remove(tenant_id);
        Ok(())
    }

    async fn delete_method_state(
        &self,
        method_state_id: &Self::MethodId,
    ) -> Result<(), Self::Error> {
        self.auth_method_states.remove(method_state_id);
        Ok(())
    }

    async fn upsert_auth_method(
        &self,
        method: AuthMethod<Self>,
    ) -> Result<AuthMethod<Self>, Self::Error> {
        let method_id = format!("method_{}", self.auth_methods.len());
        self.auth_methods.insert(method_id, method.clone());
        Ok(method)
    }

    async fn delete_auth_method(&self, method_id: &Self::MethodId) -> Result<(), Self::Error> {
        self.auth_methods.remove(method_id);
        Ok(())
    }

    async fn delete_factor_state(
        &self,
        factor_state_id: &Self::FactorId,
    ) -> Result<(), Self::Error> {
        self.auth_factor_states.remove(factor_state_id);
        Ok(())
    }

    async fn upsert_auth_factor(
        &self,
        factor: AuthFactor<Self>,
    ) -> Result<AuthFactor<Self>, Self::Error> {
        let factor_id = format!("factor_{}", self.auth_factors.len());
        self.auth_factors.insert(factor_id, factor.clone());
        Ok(factor)
    }

    async fn delete_auth_factor(&self, factor_id: &Self::FactorId) -> Result<(), Self::Error> {
        self.auth_factors.remove(factor_id);
        Ok(())
    }
}
