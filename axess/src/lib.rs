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

#[cfg(feature = "authn")]
pub use axess_core::{
    authn::{
        self,
        backend::{
            AuthTenant, AuthUser, AuthnBackend, EntityState, FactorId, MethodId, StatusDetail,
            TenantId, UserId,
        },
        errors::{AuthError, FormError, HandlerError},
        methods::{
            AuthFactorKind, EnablementState, FactorForm, FactorStateChange, MethodStateChange,
            PermissionScope,
        },
        middleware::{AuthnLayer, AuthnLayerBuilder, AuthnManager},
        session::{
            AuthEvent, AuthEventRecord, AuthEventStatus, AuthEventType, AuthSession,
            SessionRegistry, StoreSessionRegistry,
        },
        types::{
            AuthFactor, AuthFactorState, AuthMethod, AuthMethodState, PartialState, SessionData,
            SessionState,
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
    pub use axess_core::storage::valkey::{ValkeyStore, ValkeyStoreError};
}

pub use axess_macros::{login_required, require_partial_authn};
