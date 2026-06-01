# axess-rng

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-rng)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-rng) · [docs.rs](https://docs.rs/axess-rng) · [GitHub](https://github.com/GnomesOfZurich/axess)

Injectable cryptographically-secure RNG trait for deterministic simulation testing (DST). Foundational primitive used by [Axess](https://github.com/GnomesOfZurich/axess) and adjacent crates.

Production code depends on the `SecureRng` trait. Tests inject `MockRng` (a seeded PRNG) for reproducible randomness in auth flows, token issuance, and key generation; the same seed always produces the same byte stream.

## Usage

```rust
use axess_rng::{MockRng, SecureRng, SystemRng};
use std::sync::Arc;

// Production: pulls from the OS CSPRNG.
let rng: Arc<dyn SecureRng> = Arc::new(SystemRng);

// Tests: deterministic seed.
let rng: Arc<dyn SecureRng> = Arc::new(MockRng::new(0xDEADBEEF));

let mut buf = [0u8; 32];
rng.fill_bytes(&mut buf);
```

`SecureRng::fill_bytes(&self, …)` uses interior mutability so `Arc<dyn SecureRng>` is dyn-compatible. `MockRng` serialises its seed under `std::sync::Mutex` so concurrent calls never produce colliding byte streams while single-threaded determinism is preserved.

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).
