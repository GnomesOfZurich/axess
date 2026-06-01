//! DST-friendly local hot-path cache primitives.
//!
//! [`ClockTtlCache`] is a TTL+LRU cache where every time-dependent decision
//! goes through an injected [`Clock`](axess_clock::Clock) (from
//! `axess-clock`). It exists so axess can offer hot-path caching without
//! falling back to the `Instant::now()` + background-task model used by
//! `moka` and friends, both of which break deterministic-simulation
//! testing because their TTL eviction is invisible to test-mocked time.
//!
//! # Why not use moka directly?
//!
//! - **DST**: moka's TTL is wall-clock only; advancing a `MockClock` does
//!   not expire moka entries. Tests covering "entry expires after T" become
//!   impossible to write deterministically.
//! - **Background scheduler**: moka spawns its own housekeeping task on a
//!   real-time interval. In a test runtime that controls time, this still
//!   advances on real wall-clock, leaking non-determinism.
//!
//! `ClockTtlCache` resolves both: TTL is checked on access against
//! `clock.now()`, capacity-bounded eviction happens at insert time (LRU
//! oldest-first), and there are no background tasks.
//!
//! # Compliance posture
//!
//! Caching authentication state (session validity, user identity) is widely
//! flagged by PSD2/FAPI/SCA-style auditors. Caching *authorization input
//! data* (the entity graph that Cedar evaluates against) is not. The
//! decision is recomputed every request against fresh-from-cache entities.
//! When you reach for this primitive, ask which side of that line you're
//! on. The same code shape can be used for either, but the tradeoffs
//! differ. See `axess-core::authz::cache` for the canonical authz use.
//!
//! # Quick start
//!
//! ```rust
//! use axess_cache::ClockTtlCache;
//! use axess_clock::Clock;
//! use axess_clock::testing::MockClock;
//! use chrono::{TimeZone, Utc};
//! use std::num::NonZeroUsize;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! let clock = Arc::new(MockClock::at(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()));
//! let cache: ClockTtlCache<&'static str, u32> = ClockTtlCache::new(
//!     NonZeroUsize::new(128).unwrap(),
//!     Duration::from_secs(60),
//!     clock.clone() as Arc<dyn Clock>,
//! );
//!
//! cache.insert("k", 42);
//! assert_eq!(cache.get(&"k"), Some(42));
//!
//! // Advance past the TTL; entry must be gone on next access.
//! clock.advance_secs(61);
//! assert_eq!(cache.get(&"k"), None);
//! ```
//!
//! # Module layout
//!
//! - `stats`: [`CacheStats`] public counter snapshot.
//! - `cache`: [`ClockTtlCache`] core: LRU + TTL + single-flight loader.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cache;
pub mod stats;

#[cfg(test)]
mod tests;

pub use cache::ClockTtlCache;
pub use stats::CacheStats;
