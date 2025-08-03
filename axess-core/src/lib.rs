#![forbid(unsafe_code)]

pub mod authn;
// TODO: Consider re-exporting important types/traits for easier access
//
// // Re-export the most important types/traits for easy access
// pub use authn::{
//     session::{AuthSession, AuthError},
//     service::{AuthManager, AuthManagerLayer},
//     backend::{AuthnBackend, AuthUser, AuthTenant, MethodId, FactorId, UserId, UserState},
//     methods::{AuthMethod, AuthFactor, FactorForm},
// };

#[cfg(feature = "authz")]
pub mod authz;
pub mod utils;

pub mod extras;
pub mod storage;

// Re-export axum and tracing for macro hygiene and version consistency
// This ensures our macros work correctly regardless of the user's axum version
#[doc(hidden)]
pub use axum;
#[doc(hidden)]
pub use tracing;
