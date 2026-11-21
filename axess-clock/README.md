# axess-clock

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-clock)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-clock) · [docs.rs](https://docs.rs/axess-clock) · [Book](https://gnomesofzurich.github.io/axess/) · [GitHub](https://github.com/GnomesOfZurich/axess)

Injectable `Clock` trait for deterministic simulation testing (DST), and the base time types `Timestamp`, `SignedDuration`, `Until` and `UtcDate`, built on the standard library alone. Foundational primitive used by [Axess](https://github.com/GnomesOfZurich/axess) and adjacent crates.

Production code depends on the `Clock` trait. Tests inject `MockClock` to make time-dependent behaviour reproducible; TTL expiry, lockout windows, OTP step counters, refresh-token rotation, audit timestamps.

## Usage

```rust
use axess_clock::testing::MockClock;
use axess_clock::{Clock, SignedDuration, SystemClock, Timestamp};
use std::sync::Arc;

// Code that needs the time takes a clock and reads it.
fn issued_at(clock: &dyn Clock) -> Timestamp {
    clock.now()
}

// Production: the system clock.
let clock: Arc<dyn Clock> = Arc::new(SystemClock);

// Tests: a clock that moves only when the test moves it.
let mock = MockClock::at_reference();
let clock: Arc<dyn Clock> = Arc::new(mock.clone());
assert_eq!(issued_at(&clock).to_rfc3339(), "2026-01-01T00:00:00Z");
mock.advance(SignedDuration::seconds(60));
assert_eq!(issued_at(&clock).to_rfc3339(), "2026-01-01T00:01:00Z");
```

`Clock::now()` returns a `Timestamp`, and `SystemClock` is the one read of the system clock in the crate. `MockClock` is in `axess_clock::testing`, behind the `testing` feature, which a crate enables for its tests:

```toml
[dev-dependencies]
axess-clock = { version = "0.20", features = ["testing"] }
```

`MockClock::at(time)` starts at a stated reading and `MockClock::at_reference()` at 2026-01-01T00:00:00Z; `advance`, `advance_secs` and `set` move it. `axess_clock::DeterministicClock` is the same type under another name. The module also has `Shift`, which gives test code `reading.plus(span)` and `reading.minus(span)`: the shifted reading itself, and a panic outside the range.

## Time types

| Type | Holds |
|---|---|
| `Timestamp` | A reading of the UTC wall clock to the nanosecond, from `-262143-01-01T00:00:00Z` to `+262142-12-31T23:59:59.999999999Z`, with its RFC 3339 text |
| `SignedDuration` | An exact signed span of elapsed time; a day is 86,400 seconds |
| `Until` | An end that comes at a reading or never: `Until::At(..)` or `Until::Forever` |
| `UtcDate` | The calendar day in UTC a reading falls on |

```rust
use axess_clock::{SignedDuration, Timestamp, Until};
use std::time::Duration;

let start = Timestamp::parse_rfc3339("2026-01-01T00:00:00Z").expect("RFC 3339 text");
let later = start
    .checked_add(SignedDuration::minutes(5))
    .expect("inside the range");
assert_eq!(later.to_rfc3339(), "2026-01-01T00:05:00Z");
assert_eq!(later.since(start), SignedDuration::seconds(300));

let end = Until::after(start, Duration::from_secs(900));
assert!(!end.is_past(later));
assert!(end < Until::Forever);
```

Arithmetic is checked: a result outside the range is `None`, never a panic or a clamped value, and none of the types reads a clock. A `Timestamp` is written as RFC 3339 text in UTC with a `Z` and the fewest of 0, 3, 6 or 9 fraction digits that hold it, and `Timestamp::parse_rfc3339` reads that text and every form earlier releases stored. With the `serde` feature a `Timestamp`, an `Until` and a `UtcDate` are written as their text and read back through their readers.

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).
