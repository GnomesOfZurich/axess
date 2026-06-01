# axess-clock

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-clock)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-clock) · [docs.rs](https://docs.rs/axess-clock) · [Book](https://gnomesofzurich.github.io/axess/) · [GitHub](https://github.com/GnomesOfZurich/axess)

Injectable `Clock` trait for deterministic simulation testing (DST). Foundational primitive used by [Axess](https://github.com/GnomesOfZurich/axess) and adjacent crates.

Production code depends on the `Clock` trait. Tests inject `MockClock` to make time-dependent behaviour reproducible; TTL expiry, lockout windows, OTP step counters, refresh-token rotation, audit timestamps.

## Usage

```rust
use axess_clock::{Clock, MockClock, SystemClock};
use std::sync::Arc;
use std::time::Duration;

// Production:
let clock: Arc<dyn Clock> = Arc::new(SystemClock);

// Tests:
let mock = MockClock::default();
let clock: Arc<dyn Clock> = Arc::new(mock.clone());
mock.advance(Duration::from_secs(60));   // wall clock jumps forward
```

`Clock::now()` returns `chrono::DateTime<chrono::Utc>`. `Clock::monotonic_now()` returns a `std::time::Instant`-equivalent backed by the same logical timeline so monotonic-only callers stay DST-pinned too.

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).
