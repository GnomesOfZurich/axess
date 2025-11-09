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
            AuthFactorKind, EnablementState, FactorForm, FactorFormExt, FactorInstance,
            FactorStateChange, FormField, FormFieldValue, MethodBuilder, MethodInstance,
            MethodStateChange, PermissionScope,
        },
        middleware::{AuthnManager, AuthnService, AuthnServiceBuilder},
        session::{
            AuthEvent, AuthEventRecord, AuthEventStatus, AuthEventType, AuthSession,
            SessionRegistry, SessionRegistryStore,
        },
        types::{
            AuthFactor, AuthFactorState, AuthMethod, AuthMethodState, PartialState, SessionData,
            SessionState,
        },
    },
    utils::{self, random::SystemRng, validation},
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
    pub use axess_core::storage::valkey::{
        ValkeyStore, ValkeyStoreError, init_valkey_cluster_client,
    };
}

pub use axess_factors::{
    build_totp_uri, generate_password_hash, generate_totp_secret, verify_hotp, verify_password,
    verify_totp,
};
pub use axess_macros::{login_required, require_partial_authn};
