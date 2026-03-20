use crate::authn::backend::{AuthTenant, AuthUser, EntityState};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

pub const SYSTEM_SUPER_USER_ID: &str = "SYSTEM_SUPER_USER_ID";
pub const TENANT_SUPER_USER_ID: &str = "TENANT_SUPER_USER_ID";
pub const DEFAULT_TENANT_NAME: &str = "Default Tenant";
pub const DEFAULT_TENANT_ID: &str = "DEFAULT_TENANT_ID";
#[allow(dead_code)] // WIP: used when default-user test fixtures are wired up
pub const DEFAULT_USER_ID: &str = "DEFAULT_USER_ID";

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
}

impl Default for MockUser {
    fn default() -> Self {
        Self {
            id: TestUserId("default_user".to_string()),
            tenant_id: DEFAULT_TENANT_ID.into(),
            state: EntityState::Active,
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
}
