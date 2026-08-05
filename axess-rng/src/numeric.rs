//! Reproducible numeric RNG for Monte Carlo, statistical sampling, and DST.
//!
//! Enabled by the `numeric` feature. Downstream consumers of `axess-rng`
//! who only need the cryptographic surface ([`crate::SecureRng`]) don't
//! pay for this code path.
//!
//! The trait [`NumericRng`] is number-oriented (`u64`, `f64`) and stateful
//! (`&mut self`), unlike [`crate::SecureRng`], which is byte-oriented and
//! uses interior mutability. The two serve different roles:
//!
//! - [`crate::SecureRng`]: cryptographic (key generation, invite tokens,
//!   session-id fill). Must be OS-quality entropy in production.
//! - [`NumericRng`]: reproducible statistical sampling (Monte Carlo pricing,
//!   quasi-random sequences, DST scenario replay). Must be deterministic
//!   given a seed.
//!
//! For a standard-normal variate, see the `NumericRngExt` extension trait
//! in `nomos-numerics`. The framework-canonical inverse-CDF Gaussian
//! transform is owned there, not here.

/// Trait for reproducible numeric random-number generation.
///
/// Unlike [`crate::SecureRng`], `NumericRng` is:
///
/// - Deterministic given a seed (reproducibility for MC pricing, DST tests).
/// - Number-oriented (`u64`, `f64`) rather than byte-oriented.
/// - Stateful. Every method takes `&mut self` since sequential draws
///   advance internal state.
///
/// Production implementation: [`Xoshiro256pp`].
///
/// DST testing: `MockNumericRng` in [`crate::testing`].
pub trait NumericRng {
    /// Generate the next `u64` sample.
    fn next_u64(&mut self) -> u64;

    /// Generate a uniform `f64` in `[0, 1)`.
    ///
    /// Uses the upper 53 bits of `next_u64` for full f64 mantissa precision.
    #[inline]
    fn next_uniform(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }
}

// ── xoshiro256++ PRNG ────────────────────────────────────────────────────
//
// High-quality, fast, small-state (256-bit) PRNG by Blackman & Vigna (2019).
// Period: 2^256 - 1. Passes all BigCrush tests. Chosen over LCG for its
// statistical properties in Monte Carlo simulation.

/// xoshiro256++ 256-bit PRNG.
///
/// Reproducible: constructing two `Xoshiro256pp` with the same seed yields
/// identical `next_u64`/`next_uniform` sequences forever.
#[derive(Debug, Clone)]
pub struct Xoshiro256pp {
    s: [u64; 4],
}

impl Xoshiro256pp {
    /// Seed from a single `u64` using SplitMix64 expansion.
    pub fn new(seed: u64) -> Self {
        let mut sm = seed;
        let mut s = [0u64; 4];
        for slot in &mut s {
            *slot = splitmix64(&mut sm);
        }
        Self { s }
    }
}

impl NumericRng for Xoshiro256pp {
    #[inline]
    fn next_u64(&mut self) -> u64 {
        let result = (self.s[0].wrapping_add(self.s[3]))
            .rotate_left(23)
            .wrapping_add(self.s[0]);

        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);

        result
    }
}

/// SplitMix64: used only for seeding xoshiro256++ from a single `u64`.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seeding() {
        let mut a = Xoshiro256pp::new(42);
        let mut b = Xoshiro256pp::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_differ() {
        let mut a = Xoshiro256pp::new(1);
        let mut b = Xoshiro256pp::new(2);
        let va: Vec<u64> = (0..10).map(|_| a.next_u64()).collect();
        let vb: Vec<u64> = (0..10).map(|_| b.next_u64()).collect();
        assert_ne!(va, vb);
    }

    #[test]
    fn uniform_in_range() {
        let mut rng = Xoshiro256pp::new(42);
        for _ in 0..10_000 {
            let u = rng.next_uniform();
            assert!((0.0..1.0).contains(&u), "uniform out of range: {u}");
        }
    }

    #[test]
    fn uniform_default_impl_matches_manual_shift() {
        // The default `next_uniform` impl derives from `next_u64`; verify
        // that a wrapper type that implements only `next_u64` sees the
        // same uniform stream as the concrete `Xoshiro256pp`.
        struct Wrap(Xoshiro256pp);
        impl NumericRng for Wrap {
            fn next_u64(&mut self) -> u64 {
                self.0.next_u64()
            }
        }
        let mut direct = Xoshiro256pp::new(7);
        let mut wrapped = Wrap(Xoshiro256pp::new(7));
        for _ in 0..1_000 {
            assert_eq!(direct.next_uniform(), wrapped.next_uniform());
        }
    }
}
