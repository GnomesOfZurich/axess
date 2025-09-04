#![forbid(unsafe_code)]

#[cfg(feature = "authn")]
pub mod authn;

#[cfg(feature = "authz")]
pub mod authz;

pub mod utils;

// Declare and re-export extras submodules
#[cfg(any(feature = "request_id", feature = "trace_id"))]
pub mod extras {
    #[cfg(feature = "request_id")]
    pub mod request_id;

    #[cfg(feature = "trace_id")]
    pub mod trace_id;
}

// Declare and re-export storage submodules
#[cfg(any(feature = "memory", feature = "valkey"))]
pub mod storage {
    #[cfg(feature = "memory")]
    pub mod in_memory;

    #[cfg(feature = "valkey")]
    pub mod valkey;
}

// Re-export axum and tracing for macro hygiene and version consistency
// This ensures our macros work correctly regardless of the user's axum version
#[doc(hidden)]
pub use axum;
#[doc(hidden)]
pub use tracing;

// TODO: Consider re-exporting important types/traits for easier access
//
// // Re-export the most important types/traits for easy access
// pub use authn::{
//     session::{AuthSession, AuthError},
//     service::{AuthManager, AuthManagerLayer},
//     backend::{AuthnBackend, AuthUser, AuthTenant, MethodId, FactorId, UserId, UserState},
//     methods::{AuthMethod, AuthFactor, FactorForm},
// };
