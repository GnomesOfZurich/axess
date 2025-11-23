//! Administrative backend extensions for Axess authentication.
//!
//! Implement [`AuthnAdminBackend`] to support CRUD operations on tenants, users,
//! factors, and methods in addition to the core [`AuthnBackend`] contract.
//!
//! These operations are intended for privileged actors (administrators, system users)
//! and should be protected by appropriate authorization checks in your backend implementation.

use crate::authn::{
    backend::AuthnBackend,
    types::{AuthFactor, AuthMethod},
};
use async_trait::async_trait;

/// Trait for administrative operations on authentication entities.
///
/// `AuthnAdminBackend` extends [`AuthnBackend`] with methods for creating, updating,
/// and deleting tenants, users, authentication methods, and factors. All admin operations
/// require an `actor` parameter to record and validate the identity of the user performing
/// the action, supporting audit logging and fine-grained authorization.
///
/// # Security
/// - Always validate that the `actor` is authorized to perform the requested operation.
/// - Use audit logging to track all administrative changes.
///
/// # Example
/// ```rust,ignore
/// use axess_core::authn::backend::admin::AuthnAdminBackend;
///
/// // Upsert a user as an admin
/// backend.upsert_user(user, admin_id).await?;
/// ```
#[async_trait]
pub trait AuthnAdminBackend: AuthnBackend {
    // Tenant & User

    /// Creates or updates a user record.
    ///
    /// If the user exists, updates all fields; otherwise, inserts a new user.
    /// The `actor` is the user performing the operation (for audit and authorization).
    async fn upsert_user(
        &self,
        user: Self::User,
        actor: Self::UserId,
    ) -> Result<Self::User, Self::Error>;

    /// Deletes a user by ID.
    ///
    /// The `actor` is the user performing the operation (for audit and authorization).
    async fn delete_user(
        &self,
        user_id: &Self::UserId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error>;

    /// Creates or updates a tenant record.
    ///
    /// If the tenant exists, updates all fields; otherwise, inserts a new tenant.
    /// The `actor` is the user performing the operation (for audit and authorization).
    async fn upsert_tenant(
        &self,
        tenant: Self::Tenant,
        actor: Self::UserId,
    ) -> Result<Self::Tenant, Self::Error>;

    /// Deletes a tenant by ID.
    ///
    /// The `actor` is the user performing the operation (for audit and authorization).
    async fn delete_tenant(
        &self,
        tenant_id: &Self::TenantId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error>;

    // Authentication Method

    /// Creates or updates an authentication method.
    ///
    /// If the method exists, updates all fields; otherwise, inserts a new method.
    /// The `actor` is the user performing the operation (for audit and authorization).
    async fn upsert_auth_method(
        &self,
        method: AuthMethod<Self>,
        actor: Self::UserId,
    ) -> Result<AuthMethod<Self>, Self::Error>;

    /// Deletes an authentication method by ID.
    ///
    /// The `actor` is the user performing the operation (for audit and authorization).
    async fn delete_auth_method(
        &self,
        method_id: &Self::MethodId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error>;

    /// Deletes a method state by composite key.
    ///
    /// The `actor` is the user performing the operation (for audit and authorization).
    async fn delete_method_state(
        &self,
        method_state_id: &Self::DataId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error>;

    // Authentication Factor

    /// Creates or updates an authentication factor.
    ///
    /// If the factor exists, updates all fields; otherwise, inserts a new factor.
    /// The `actor` is the user performing the operation (for audit and authorization).
    async fn upsert_auth_factor(
        &self,
        factor: AuthFactor<Self>,
        actor: Self::UserId,
    ) -> Result<AuthFactor<Self>, Self::Error>;

    /// Deletes an authentication factor by ID.
    ///
    /// The `actor` is the user performing the operation (for audit and authorization).
    async fn delete_auth_factor(
        &self,
        factor_id: &Self::FactorId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error>;

    /// Deletes a factor state by composite key.
    ///
    /// The `actor` is the user performing the operation (for audit and authorization).
    async fn delete_factor_state(
        &self,
        factor_state_id: &Self::DataId,
        actor: Self::UserId,
    ) -> Result<(), Self::Error>;
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::utils::testing::mock_backend::{
//         MockBackend, MockTenant, MockUser, TestTenantId, TestUserId,
//     };

// }
