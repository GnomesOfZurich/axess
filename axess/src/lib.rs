#[cfg(feature = "admin")]
pub use axess_core::authn::backend::admin::AuthnAdminBackend;

#[cfg(feature = "authn")]
pub use axess_core::{
    authn::{
        self,
        backend::{
            AuthId, AuthTenant, AuthUser, AuthnBackend, EntityState, StatusDetail, TenantId, UserId,
        },
        errors::{AuthError, FormError, HandlerError, WorkflowError},
        methods::{
            MethodBuilder, MethodInstance, MethodStateChange,
            factor::{FactorInstance, FactorStateChange, FederatedProvider, Kind, Operation},
            form::{
                self, Action, FactorForm, FactorFormExt, FormField, FormFieldValue,
                form_fields_to_json,
            },
            policy::{FactorConfig, FactorConfigBuilder},
            scope::{AuthnScope, EnablementState},
        },
        middleware::{AuthnManager, AuthnService, AuthnServiceBuilder},
        session::{
            AuthSession,
            registry::{SessionRegistry, SessionRegistryStore},
            state::{
                AuthEvent, AuthEventRecord, AuthEventStatus, AuthEventType, AuthState,
                PartialAuthState,
            },
        },
        types::{
            AuthFactor, AuthFactorState, AuthMethod, AuthMethodState, PartialState, SessionData,
            SessionState,
        },
        workflows::{StepKind, Workflow, WorkflowAction, WorkflowState, WorkflowStep},
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
        ValkeyStore, ValkeyStoreError, init_valkey_cluster_client, init_valkey_standalone_client,
    };
}

pub use axess_factors::{
    HOTP_LENGTH, TOTP_LENGTH, TOTP_PERIOD, build_totp_uri, generate_password_hash,
    generate_totp_secret, verify_hotp, verify_password, verify_totp,
};
pub use axess_macros::{login_required, require_partial_authn};
