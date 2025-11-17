#[cfg(feature = "admin")]
pub use axess_core::authn::backend::admin::AuthnAdminBackend;

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
            MethodBuilder, MethodInstance, MethodStateChange,
            factor::{AuthFactorKind, FactorInstance, FactorStateChange},
            form::{FactorForm, FactorFormExt, FormField, FormFieldValue},
            scope::{EnablementState, PermissionScope},
        },
        middleware::{AuthnManager, AuthnService, AuthnServiceBuilder},
        session::{
            AuthSession,
            registry::{SessionRegistry, SessionRegistryStore},
            state::{AuthEvent, AuthEventRecord, AuthEventStatus, AuthEventType},
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
    verify_totp, HOTP_LENGTH, TOTP_LENGTH, TOTP_PERIOD,
};
pub use axess_macros::{login_required, require_partial_authn};
