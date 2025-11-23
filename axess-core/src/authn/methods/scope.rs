//! Factor enablement states and scope helpers used when provisioning or resolving
//! methods and factors within Axess.

use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Represents the lifecycle and activation status of an authentication factor or method.
///
/// `EnablementState` is used throughout Axess to track whether a factor or method is available
/// for authentication, pending setup, disabled, or archived. This enum is central to provisioning,
/// verification, and audit flows.
///
/// # Variants
/// - `Pending`: Not yet active, awaiting approval or setup (e.g., user must complete setup).
/// - `Active`: Fully enabled and operational; available for authentication.
/// - `Inactive`: Explicitly disabled, but not deleted; cannot be used for authentication.
/// - `Suspended`: Temporarily disabled (e.g., due to policy violation or lockout).
/// - `Archived`: No longer available for new use, but kept for history/audit.
///
/// # Usage
/// Use `EnablementState` to filter factors/methods in backend queries, control authentication flows,
/// and record state transitions in audit logs.
///
/// # Example
/// ```rust,ignore
/// use axess_core::authn::methods::scope::EnablementState;
///
/// let state = EnablementState::Active;
/// assert_eq!(format!("{:?}", state), "Active");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum EnablementState {
    /// Not yet active, awaiting approval or setup (e.g., user must complete setup).
    Pending,
    /// Fully enabled and operational; available for authentication.
    Active,
    /// Explicitly disabled, but not deleted; cannot be used for authentication.
    Inactive,
    /// Temporarily disabled (e.g., due to policy violation or lockout).
    Suspended,
    /// No longer available for new use, but kept for history/audit.
    Archived,
}

/// Describes the scope at which authentication factors or methods are defined and resolved.
///
/// `PermissionScope` is used throughout Axess to specify whether a factor or method applies globally,
/// to a specific tenant, or to a specific user within a tenant. This enables fine-grained control
/// over authentication and authorization flows, supporting multi-tenancy and per-user overrides.
///
/// # Variants
/// - `Any`: Matches all defined states—global, tenant, and user-level.
/// - `Global`: Applies to all globally defined states (not tied to any tenant or user).
/// - `Tenant(TenantId)`: Applies to all states defined for a specific tenant.
/// - `User(TenantId, UserId)`: Applies to a specific user within a tenant.
///
/// # Usage
/// Use `PermissionScope` to filter factors/methods in backend queries, resolve authentication flows,
/// and enforce policy decisions. Helper methods are provided to extract tenant/user IDs and to check scope type.
///
/// # Example
/// ```rust,ignore
/// use axess_core::authn::methods::scope::PermissionScope;
///
/// let global = PermissionScope::<String, String>::Global;
/// let tenant = PermissionScope::Tenant("tenant1".to_string());
/// let user = PermissionScope::User("tenant1".to_string(), "user42".to_string());
///
/// assert!(global.is_global());
/// assert!(tenant.is_tenant());
/// assert!(user.is_user());
/// assert_eq!(tenant.tenant_id(), Some(&"tenant1".to_string()));
/// assert_eq!(user.user_id(), Some(&"user42".to_string()));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionScope<TenantId, UserId> {
    /// Matches all defined states—global, tenant, and user-level.
    Any,
    /// Applies to all globally defined states (not tied to any tenant or user).
    Global,
    /// Applies to all states defined for a specific tenant.
    Tenant(TenantId),
    /// Applies to a specific user within a tenant.
    User(TenantId, UserId),
}

impl<T, U> PermissionScope<T, U> {
    /// Returns `true` if this scope is global.
    pub fn is_global(&self) -> bool {
        matches!(self, PermissionScope::Global)
    }

    /// Returns `true` if this scope is tenant-specific.
    pub fn is_tenant(&self) -> bool {
        matches!(self, PermissionScope::Tenant(_))
    }

    /// Returns `true` if this scope is user-specific.
    pub fn is_user(&self) -> bool {
        matches!(self, PermissionScope::User(_, _))
    }

    /// Returns the tenant ID if present, or `None` otherwise.
    pub fn tenant_id(&self) -> Option<&T> {
        match self {
            PermissionScope::Global => None,
            PermissionScope::Tenant(tid) => Some(tid),
            PermissionScope::User(tid, _) => Some(tid),
            PermissionScope::Any => None,
        }
    }

    /// Returns the user ID if present, or `None` otherwise.
    pub fn user_id(&self) -> Option<&U> {
        match self {
            PermissionScope::Global => None,
            PermissionScope::Tenant(_) => None,
            PermissionScope::User(_, uid) => Some(uid),
            PermissionScope::Any => None,
        }
    }
}
