use crate::authn::{
    backend::AuthnBackend,
    types::{AuthFactor, AuthMethod},
};
use async_trait::async_trait;
// use serde::{Deserialize, Serialize};
// use std::{cmp::PartialEq, fmt::Debug};

#[async_trait]
pub trait AuthnAdminBackend: AuthnBackend {
    // Tenant & User
    async fn upsert_user(&self, user: Self::User) -> Result<Self::User, Self::Error>;
    async fn delete_user(&self, user_id: &Self::UserId) -> Result<(), Self::Error>;
    async fn upsert_tenant(&self, tenant: Self::Tenant) -> Result<Self::Tenant, Self::Error>;
    async fn delete_tenant(&self, tenant_id: &Self::TenantId) -> Result<(), Self::Error>;

    // Authentication Method
    async fn upsert_auth_method(
        &self,
        method: AuthMethod<Self>,
    ) -> Result<AuthMethod<Self>, Self::Error>;
    async fn delete_auth_method(&self, method_id: &Self::MethodId) -> Result<(), Self::Error>;
    async fn delete_method_state(&self, method_state_id: &Self::DataId) -> Result<(), Self::Error>;

    // Authentication Factor
    async fn upsert_auth_factor(
        &self,
        factor: AuthFactor<Self>,
    ) -> Result<AuthFactor<Self>, Self::Error>;
    async fn delete_auth_factor(&self, factor_id: &Self::FactorId) -> Result<(), Self::Error>;
    async fn delete_factor_state(&self, factor_state_id: &Self::DataId) -> Result<(), Self::Error>;
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::utils::testing::mock_backend::{
//         MockBackend, MockTenant, MockUser, TestTenantId, TestUserId,
//     };

// }
