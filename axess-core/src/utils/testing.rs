pub mod mock_authn;
pub mod mock_clock;
/// DST mocks — always available for any code that pulls in `axess-core` in `[dev-dependencies]`.
pub mod mock_random;

// Tracing mock is test-only.
#[cfg(test)]
pub(crate) mod mock_tracing;

// Authz mocks are not restricted to #[cfg(test)] so that downstream crates
// can use them in their own test suites.
#[cfg(feature = "authz")]
pub mod mock_policy;

pub use mock_authn::{MockFactorStore, MockIdentityStore, MockStoreError};
pub use mock_clock::MockClock;
pub use mock_random::MockRng;

/// Create an `AuthSession` with a fresh session ID for use in tests.
///
/// This avoids needing access to `pub(crate)` constructors from integration tests.
pub fn test_session() -> crate::session::extractor::AuthSession {
    use crate::session::{
        data::SessionData,
        id::SessionId,
        layer::{SessionHandle, SessionInner},
    };
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let inner = SessionInner {
        id: SessionId::new(&mut crate::utils::random::SystemRng),
        data: SessionData::default(),
        modified: false,
        regenerate: false,
    };
    crate::session::extractor::AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
}
