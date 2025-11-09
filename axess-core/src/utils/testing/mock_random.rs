//! Deterministic `SecureRng` implementation for tests, enabling reproducible
//! simulations and call-count tracking when exercising authentication flows.

use crate::utils::random::SecureRng;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Deterministic RNG for testing (NOT cryptographically secure)
#[derive(Debug, Clone)]
pub struct MockRng {
    seed: u64,
    calls: Option<Arc<AtomicUsize>>,
}

impl MockRng {
    pub fn new(seed: u64) -> Self {
        Self { seed, calls: None }
    }

    pub fn with_counter(seed: u64, calls: Arc<AtomicUsize>) -> Self {
        Self {
            seed,
            calls: Some(calls),
        }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.seed = self.seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.seed
    }
}

impl SecureRng for MockRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Some(counter) = &self.calls {
            counter.fetch_add(1, Ordering::SeqCst);
        }

        for chunk in dest.chunks_mut(8) {
            let value = self.next_u64();
            let bytes = value.to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
    }
}
