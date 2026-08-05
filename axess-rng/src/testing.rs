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

// ── Numeric surface (feature-gated) ──────────────────────────────────────

#[cfg(feature = "numeric")]
use crate::numeric::{NumericRng, Xoshiro256pp};

#[cfg(feature = "numeric")]
use std::collections::VecDeque;

/// Deterministic [`NumericRng`] for DST tests.
///
/// Two construction styles:
///
/// - [`MockNumericRng::from_seed`]: wraps a seeded [`Xoshiro256pp`].
///   Reproducible sequence, same as production but under caller-controlled
///   seed.
/// - [`MockNumericRng::from_sequence`]: replays a pre-programmed `u64`
///   sequence. Lets DST tests inject exact draws and observe MC pricers
///   with controlled uniforms and normals. Panics if the sequence is
///   exhausted; a test that consumes more draws than expected should
///   fail loudly, not silently start emitting zeros.
///
/// No interior mutability: [`NumericRng::next_u64`] takes `&mut self`, so
/// the mock has exclusive access and needs no `Mutex`. Callers wanting
/// shared ownership across threads wrap this in `Arc<Mutex<_>>` themselves.
#[cfg(feature = "numeric")]
#[derive(Debug)]
pub enum MockNumericRng {
    /// Seeded xoshiro256++.
    Seeded(Xoshiro256pp),
    /// Pre-programmed sequence of `u64` draws.
    Sequence(VecDeque<u64>),
}

#[cfg(feature = "numeric")]
impl MockNumericRng {
    /// Construct a deterministic `NumericRng` from a `u64` seed.
    ///
    /// Yields the same sequence as production [`Xoshiro256pp::new`] under
    /// the caller's control.
    pub fn from_seed(seed: u64) -> Self {
        MockNumericRng::Seeded(Xoshiro256pp::new(seed))
    }

    /// Construct a `NumericRng` that replays a pre-programmed sequence of
    /// `u64` draws.
    ///
    /// Once the sequence is exhausted, [`NumericRng::next_u64`] panics.
    /// This is deliberate: a test that over-consumes should surface the
    /// mistake immediately, not silently emit zeros.
    pub fn from_sequence(values: impl IntoIterator<Item = u64>) -> Self {
        MockNumericRng::Sequence(values.into_iter().collect())
    }
}

#[cfg(feature = "numeric")]
impl NumericRng for MockNumericRng {
    fn next_u64(&mut self) -> u64 {
        match self {
            MockNumericRng::Seeded(rng) => rng.next_u64(),
            MockNumericRng::Sequence(queue) => queue.pop_front().expect(
                "MockNumericRng sequence exhausted: test consumed more draws than programmed",
            ),
        }
    }
}
