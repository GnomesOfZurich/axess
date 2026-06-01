//! Deterministic [`MockRng`] for DST.
//!
//! Gated on the `testing` feature so production builds don't compile the
//! seeded-PRNG surface. Downstream crates that need the mock in their
//! integration tests enable it via:
//!
//! ```toml
//! [dev-dependencies]
//! axess-rng = { version = "0.1", features = ["testing"] }
//! ```
//!
//! Workspace crates that re-export the trait surface forward the feature
//! through their own `testing` feature (see `axess-core/Cargo.toml`).

use crate::SecureRng;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

/// Deterministic RNG for testing (NOT cryptographically secure).
///
/// State (`seed`) lives behind a `Mutex` because [`SecureRng::fill_bytes`]
/// takes `&self`. Single-threaded test usage never contends. Use
/// [`MockRng::new`] to mint two independent generators with the same
/// seed. `Clone` is deliberately not implemented because cloning
/// mid-sequence and diverging from the parent is rarely what tests want.
#[derive(Debug)]
pub struct MockRng {
    seed: Mutex<u64>,
    calls: Option<Arc<AtomicUsize>>,
}

impl MockRng {
    /// Construct a deterministic RNG seeded by `seed` with no call counter.
    pub fn new(seed: u64) -> Self {
        Self {
            seed: Mutex::new(seed),
            calls: None,
        }
    }

    /// Construct a deterministic RNG that increments `calls` on every
    /// `fill_bytes` invocation, for asserting call counts in tests.
    pub fn with_counter(seed: u64, calls: Arc<AtomicUsize>) -> Self {
        Self {
            seed: Mutex::new(seed),
            calls: Some(calls),
        }
    }
}

impl SecureRng for MockRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        if let Some(counter) = &self.calls {
            counter.fetch_add(1, Ordering::SeqCst);
        }

        let mut seed = self.seed.lock().expect("MockRng mutex poisoned");
        for chunk in dest.chunks_mut(8) {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let bytes = seed.to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
    }
}
