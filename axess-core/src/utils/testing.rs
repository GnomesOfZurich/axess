/// DST mocks — always available for any code that pulls in `axess-core` in `[dev-dependencies]`.
pub mod mock_random;
pub mod mock_clock;
pub mod mock_authn;

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
