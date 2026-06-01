//! Session layer: custom tower middleware providing signed cookies and typed session data.
//!
//! # Overview
//!
//! - `SessionLayer`: the tower `Layer` to add to your Axum router.
//! - `AuthSession`: the Axum extractor handlers use to read/mutate session state.
//! - [`SessionData`] / [`AuthState`]: the typed payload stored in the session store.
//! - `SessionId`: a 16-byte stack-only session identifier.
//! - [`SessionStore`] / [`SessionRegistry`]: the traits storage backends implement.
//! - [`MemorySessionStore`] / [`MemorySessionRegistry`]: in-memory implementations for tests.

pub mod binding;
pub mod config;
pub mod cookies;
#[cfg(any(
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
pub mod crypto;
pub mod data;
pub mod extractor;
pub mod hmac;
pub mod id;
pub mod layer;
pub mod refresh;
pub mod store;

pub mod storage;

pub use binding::{SessionBinding, UserAgentBinding};
pub use config::{SameSite, SessionConfig, SessionConfigBuilder};
#[cfg(any(
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
pub use crypto::{CryptoError, SessionCrypto};
pub use data::{AuthState, SessionData, WorkflowKind, WorkflowState};
pub use extractor::{AuthSession, SessionMissing};
pub use id::SessionId;
pub use layer::SessionLayer;
pub use refresh::{
    IssueRequest, RefreshError, RefreshToken, RefreshTokenConfig, RefreshTokenStore,
};
#[cfg(any(test, feature = "memory"))]
pub use store::{MemoryRegistryError, MemorySessionRegistry, MemorySessionStore, MemoryStoreError};
pub use store::{
    SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle, SessionRevoker, SessionStore,
};
