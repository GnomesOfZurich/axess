#[cfg(feature = "admin")]
pub mod admin;
pub mod backend;
pub mod errors;
pub mod methods;
pub mod middleware;
pub mod session;

// // Re-export key types for ergonomics
// pub use backend::{AuthTenant, AuthUser, AuthnBackend, FactorId, MethodId, TenantId, UserId, UserState};
// pub use errors::{AuthError, FormError};
// pub use methods::{AuthFactorKind, FactorForm, FactorInstance, MethodInstance, PermissionScope};
// pub use middleware::{AuthnLayer, AuthnLayerBuilder, AuthnManager};
// pub use sessions::{SessionRegistry, AuthFactor, AuthMethod, AuthSession};
