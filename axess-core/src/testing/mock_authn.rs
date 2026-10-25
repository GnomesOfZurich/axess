//! In-memory [`IdentityStore`](crate::authn::IdentityStore) and [`FactorStore`](crate::authn::FactorStore) for unit tests.
//!
//! Use the builder methods to pre-load users, tenants, and factor configs before
//! running tests. The mocks are fully thread-safe (`Arc<DashMap<…>>`).

mod call_log;
mod factor;
mod identity;

pub use call_log::CallLog;
use call_log::note;
pub use factor::{MockFactorStore, make_password_service};
pub use identity::MockIdentityStore;

// ── MockStoreError ─────────────────────────────────────────────────────────────

/// Infallible-ish error for the in-memory mock stores.
#[derive(Debug, thiserror::Error)]
pub enum MockStoreError {
    /// Lookup target was not present in the in-memory map.
    #[error("entity not found")]
    NotFound,
    /// Insert collided with an existing entry under the same key.
    #[error("entity already exists")]
    AlreadyExists,
    /// A tenant lookup was made but no default tenant has been configured.
    #[error("no default tenant configured")]
    NoDefaultTenant,
    /// Caller tried to persist an auth method at [`AuthnScope::System`](crate::authn::types::AuthnScope::System), which is rejected.
    #[error("auth methods cannot be stored at system scope")]
    InvalidSystemMethod,
}

#[cfg(test)]
mod tests;
