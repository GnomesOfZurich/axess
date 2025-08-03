// use crate::authn::backend::{TenantId, UserId};
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
    // pub fn ids(&self) -> (Option<&T>, Option<&U>) {
    //     match self {
    //         PermissionScope::Global | PermissionScope::Any => (None, None),
    //         PermissionScope::Tenant(tid) => (Some(tid), None),
    //         PermissionScope::User(tid, uid) => (Some(tid), Some(uid)),
    //     }
    // }

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

// impl<T: Clone, U: Clone> PermissionScope<&T, &U> {
//     /// Convert a borrowed scope to an owned scope.
//     pub fn to_owned(&self) -> PermissionScope<T, U> {
//         match self {
//             PermissionScope::Global => PermissionScope::Global,
//             PermissionScope::Any => PermissionScope::Any,
//             PermissionScope::Tenant(tid) => PermissionScope::Tenant((*tid).clone()),
//             PermissionScope::User(tid, uid) => PermissionScope::User((*tid).clone(), (*uid).clone()),
//         }
//     }
// }
