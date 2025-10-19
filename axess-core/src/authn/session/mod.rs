pub mod auth_session;
pub mod extractor;
pub mod registry;
pub mod state;

// Re-export key types for ergonomics
pub use auth_session::AuthSession;
pub use registry::{SessionRegistry, SessionRegistryStore};
pub use state::{AuthEvent, AuthEventRecord, AuthEventStatus, AuthEventType};
