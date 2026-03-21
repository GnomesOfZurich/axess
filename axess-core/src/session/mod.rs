//! Session layer — custom tower middleware providing signed cookies and typed session data.
//!
//! # Overview
//!
//! - [`SessionLayer`] — the tower `Layer` to add to your Axum router.
//! - [`AuthSession`] — the Axum extractor handlers use to read/mutate session state.
//! - [`SessionData`] / [`AuthState`] — the typed payload stored in the session store.
//! - [`SessionId`] — a 16-byte stack-only session identifier.
//! - [`SessionStore`] / [`SessionRegistry`] — the traits storage backends implement.
//! - [`MemorySessionStore`] / [`MemorySessionRegistry`] — in-memory implementations for tests.

pub mod data;
pub mod extractor;
pub mod id;
pub mod layer;
pub mod store;

pub use data::{AuthState, SessionData, WorkflowKind, WorkflowState};
pub use extractor::{AuthSession, SessionMissing};
pub use id::SessionId;
pub use layer::{SessionHandle, SessionInner, SessionLayer};
pub use store::{
    MemoryRegistryError, MemorySessionRegistry, MemorySessionStore, MemoryStoreError,
    SessionRegistry, SessionStore,
};
