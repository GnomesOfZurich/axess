//! [`MockClock`] re-export for callers
//! reaching the deterministic-time fixture through the `axess-core::testing`
//! umbrella. Mirror of [`mock_random`](super::mock_random).

pub use axess_clock::testing::MockClock;
