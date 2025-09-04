// pub use axess_core::authn::{
//     backend::{
//         AuthTenant, AuthUser, AuthnBackend, FactorId, MethodId, TenantId, UserId, UserState,
//     },
//     errors::{AuthError, FormError},
//     methods::{
//         factor::FactorInstance,
//         form::FactorForm,
//         method::MethodInstance,
//         scope::PermissionScope,
//     },
//     middleware::{AuthnLayer, AuthnLayerBuilder, AuthnManager},
//     sessions::{
//         registry::SessionRegistry,
//         auth_session::{AuthFactor, AuthMethod, AuthSession},
//     },
// };

#[cfg(feature = "admin")]
pub use axess_core::authn::admin::AuthnAdminBackend;
pub use axess_core::{
    authn::{
        self,
        backend::{
            AuthTenant, AuthUser, AuthnBackend, EntityState, EntityStateInfo, FactorId, MethodId,
            TenantId, UserId,
        },
        errors::{AuthError, FormError},
        methods::{AuthFactorKind, EnablementState, FactorForm, PermissionScope},
        middleware::{AuthnLayer, AuthnLayerBuilder, AuthnManager},
        session::{
            AuthFactor, AuthFactorState, AuthMethod, AuthMethodState, AuthSession, SessionRegistry,
        },
    },
    utils::validation::verify_totp,
};

#[cfg(feature = "authz")]
pub mod authorization;

#[cfg(feature = "request_id")]
pub mod request_id {
    pub use axess_core::extras::request_id::*;
}

#[cfg(feature = "trace_id")]
pub mod trace_id {
    pub use axess_core::extras::trace_id::*;
}

#[cfg(feature = "memory")]
pub use axess_core::storage::in_memory;

#[cfg(feature = "valkey")]
pub mod valkey {
    pub use axess_core::storage::valkey::*;
}

pub use axess_macros::{login_required, require_partial_authn};
