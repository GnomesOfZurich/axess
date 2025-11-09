//! Factor enablement states and scope helpers used when provisioning or resolving
//! methods and factors within Axess.

use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum EnablementState {
    Pending,   // Not yet active, awaiting approval or setup
    Active,    // Fully enabled and operational
    Inactive,  // Explicitly disabled, but not deleted
    Suspended, // Temporarily disabled (e.g., for violations)
    Archived,  // No longer available for new use, but kept for history
}

// Scope for permission resolution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionScope<TenantId, UserId> {
    Any, // Applies to all defined states; i.e. globally defined states, as well as on user- and tenant-level
    Global, // Applies to all globally defined states
    Tenant(TenantId), // Applies to all states defined for a specific tenant
    User(TenantId, UserId), // Applies to a specific user within a tenant
}

impl<T, U> PermissionScope<T, U> {
    pub fn is_global(&self) -> bool {
        matches!(self, PermissionScope::Global)
    }

    pub fn is_tenant(&self) -> bool {
        matches!(self, PermissionScope::Tenant(_))
    }

    pub fn is_user(&self) -> bool {
        matches!(self, PermissionScope::User(_, _))
    }

    pub fn tenant_id(&self) -> Option<&T> {
        match self {
            PermissionScope::Global => None,
            PermissionScope::Tenant(tid) => Some(tid),
            PermissionScope::User(tid, _) => Some(tid),
            PermissionScope::Any => None,
        }
    }

    pub fn user_id(&self) -> Option<&U> {
        match self {
            PermissionScope::Global => None,
            PermissionScope::Tenant(_) => None,
            PermissionScope::User(_, uid) => Some(uid),
            PermissionScope::Any => None,
        }
    }
}
