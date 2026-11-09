#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Injectable [`SecureRng`] trait for deterministic simulation testing (DST).
//!
//! Production code depends on the trait, not on the operating system generator directly, so
//! tests can swap in a [`testing::MockRng`] (a seeded PRNG) and get
//! reproducible outputs from auth flows, token issuance, and key generation.
//! This crate is a foundational primitive used by
//! [`axess`](https://crates.io/crates/axess) and other crates that want
//! random-driven behaviour to be reproducible.
//!
//! # Quick start
//!
//! ```rust
//! use axess_rng::{SecureRng, SystemRng};
//!
//! fn random_token<R: SecureRng>(rng: &R) -> [u8; 32] {
//!     let mut buf = [0u8; 32];
//!     rng.fill_bytes(&mut buf);
//!     buf
//! }
//!
//! let production = SystemRng;
//! let _ = random_token(&production);
//! ```
//!
//! And in tests (requires the `testing` feature):
//!
//! ```rust,ignore
//! use axess_rng::SecureRng;
//! use axess_rng::testing::MockRng;
//!
//! let rng_a = MockRng::new(42);
//! let rng_b = MockRng::new(42);
//! let mut a = [0u8; 16];
//! let mut b = [0u8; 16];
//! rng_a.fill_bytes(&mut a);
//! rng_b.fill_bytes(&mut b);
//! assert_eq!(a, b, "same seed → same bytes");
//! ```

// The `testing` feature compiles deterministic clocks and random sources and
// constructors that skip key checks. A release build that links it ships
// those in a production binary, and cargo feature unification lets any one
// dependent switch it on for the whole build, so the build refuses by name.
// `allow-testing-in-release` is the named opt-out for a build that means it.
#[cfg(all(
    feature = "testing",
    not(debug_assertions),
    not(feature = "allow-testing-in-release")
))]
compile_error!(
    "the `testing` feature of axess-rng is enabled in a release build; it ships test doubles in a \
     production binary. Remove the feature from the release build, or enable \
     `allow-testing-in-release` to keep it on purpose."
);

#[cfg(any(test, feature = "testing"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

pub mod hex;

#[cfg(feature = "numeric")]
#[cfg_attr(docsrs, doc(cfg(feature = "numeric")))]
pub mod numeric;

#[cfg(feature = "numeric")]
#[cfg_attr(docsrs, doc(cfg(feature = "numeric")))]
pub use numeric::{NumericRng, Xoshiro256pp};

/// Trait for secure random number generation (DST-friendly).
///
/// Uses interior mutability: `fill_bytes` takes `&self`, not `&mut self`,
/// so a single RNG instance can be shared behind `Arc<dyn SecureRng>`
/// (the shape used by `AuthnService`) without needing per-call write
/// access. Production impls like [`SystemRng`] are stateless;
/// stateful impls (e.g. [`testing::MockRng`]) must use an internal
/// `Mutex`/atomic.
pub trait SecureRng: Send + Sync + 'static {
    /// Fill `dest` with cryptographically secure random bytes.
    fn fill_bytes(&self, dest: &mut [u8]);
}

/// Blanket impl so `Arc<dyn SecureRng>` (and `Arc<T> where T: SecureRng`)
/// satisfies `SecureRng` itself. This is what lets `AuthnService` hold
/// the RNG as `Arc<dyn SecureRng>` and pass it directly to functions
/// taking `&impl SecureRng` without an explicit deref dance.
impl<R: SecureRng + ?Sized> SecureRng for std::sync::Arc<R> {
    fn fill_bytes(&self, dest: &mut [u8]) {
        (**self).fill_bytes(dest);
    }
}

/// Production implementation backed by the operating system's random
/// generator (`getrandom`: `getrandom(2)`, `getentropy`, `BCryptGenRandom`
/// and the like). It keeps no state of its own.
///
/// # Panics
///
/// [`SecureRng::fill_bytes`] cannot report a failure, so it panics if the
/// operating system generator refuses, rather than hand back bytes that are
/// not random.
///
/// # Platform support
///
/// This type is **not available on `wasm32-unknown-unknown`**. The
/// underlying `getrandom` crate has no backend there unless the consumer
/// opts into one, which is a contract that belongs to the application, not
/// to this auth library. Refusing to compile here surfaces the choice at
/// build time instead of at the first call.
///
/// On `wasm32-unknown-unknown`, supply your own [`SecureRng`] (typically
/// one wrapping `web_sys::Crypto::get_random_values`) when constructing
/// the `AuthnService`. WASI targets (`wasm32-wasi*`) and the browser-via-
/// `wasm-bindgen` flow are unaffected because their `getrandom` backends
/// are wired automatically.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRng;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl SecureRng for SystemRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        if let Err(err) = getrandom::fill(dest) {
            panic!("the operating system random generator failed: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockRng;

    #[test]
    fn mock_rng_is_deterministic_for_same_seed() {
        let rng1 = MockRng::new(123);
        let rng2 = MockRng::new(123);

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
        let rng1 = MockRng::new(123);
        let rng2 = MockRng::new(456);

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
    fn arc_blanket_impl_forwards_fill_bytes_to_inner() {
        let inner = MockRng::new(0x5A5A_5A5A);
        let mut direct = [0u8; 32];
        inner.fill_bytes(&mut direct);

        let arc: std::sync::Arc<dyn SecureRng> = std::sync::Arc::new(MockRng::new(0x5A5A_5A5A));
        let mut via_arc = [0u8; 32];
        arc.fill_bytes(&mut via_arc);

        assert_eq!(
            direct, via_arc,
            "Arc<dyn SecureRng> blanket impl must delegate fill_bytes to inner, not no-op"
        );
        assert_ne!(
            via_arc, [0u8; 32],
            "delegated fill_bytes must actually write bytes (no-op mutation would leave zeros)"
        );
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn system_rng_fills_buffer() {
        let rng = SystemRng;
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);

        assert_ne!(
            buf, [0u8; 32],
            "SystemRng should write non-zero data into the buffer (extremely unlikely to fail spuriously)"
        );
    }
}
