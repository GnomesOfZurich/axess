//! Secure random number generation utilities.
//!
//! Defines the [`SecureRng`] trait used across Axess for DST-friendly
//! randomness, provides the OS-backed [`SystemRng`] implementation for
//! production, and includes deterministic helpers for testing.

use rand::{RngCore, rngs::OsRng};

/// Trait for secure random number generation (DST-friendly)
pub trait SecureRng: Send + Sync + 'static {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

/// Production implementation using OS-provided cryptographically secure RNG
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRng;

impl SecureRng for SystemRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut rng = OsRng;
        rng.fill_bytes(dest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::mock_random::MockRng;

    #[test]
    fn mock_rng_is_deterministic_for_same_seed() {
        let mut rng1 = MockRng::new(123);
        let mut rng2 = MockRng::new(123);

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        assert_eq!(
            buf1, buf2,
            "MockRng should produce identical output for identical seeds"
        );
    }

    #[test]
    fn mock_rng_differs_for_different_seeds() {
        let mut rng1 = MockRng::new(123);
        let mut rng2 = MockRng::new(456);

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        assert_ne!(
            buf1, buf2,
            "MockRng outputs should differ for different seeds"
        );
    }

    #[test]
    fn system_rng_fills_buffer() {
        let mut rng = SystemRng;
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);

        assert_ne!(
            buf, [0u8; 32],
            "SystemRng should write non-zero data into the buffer (extremely unlikely to fail spuriously)"
        );
    }
}
