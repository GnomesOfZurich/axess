pub mod auth_session;
pub mod extractor;
pub mod registry;
pub mod state;

// Re-export key types for ergonomics
pub use auth_session::{AuthFactor, AuthFactorState, AuthMethod, AuthMethodState, AuthSession};
pub use registry::SessionRegistry;
