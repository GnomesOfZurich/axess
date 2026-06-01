//! Caching wrappers for [`RequestEntityProvider`](super::RequestEntityProvider).
//!
//! Cedar evaluation is in-process and cheap (~10µs); the expensive part of
//! authorization is **building the entity set**: typically one or more DB
//! queries to load the principal, their roles, and the resource. Caching
//! that result is the single biggest perf win available to a Cedar+axess
//! consumer.
//!
//! axess provides cache **decorators** that wrap any
//! [`RequestEntityProvider`](super::RequestEntityProvider) in a caching
//! layer. They are themselves `RequestEntityProvider` implementations,
//! so they compose: stack moka over a valkey-backed cache over your
//! concrete provider, and the consumer
//! (the `require_authz!` macro from `axess_macros`,
//! [`AuthzStore`](super::session::AuthzStore)) sees a single provider
//! whose `entities_for` is now multi-tier cached.
//!
//! # Why decorators (and not a separate trait)
//!
//! `RequestEntityProvider` is the only abstraction needed. A cache is just
//! a provider that consults its memo before falling through to an inner
//! provider. New trait = new abstraction tax; decorator = composition over
//! the existing trait. This is the [tower]-style pattern Rust web stacks
//! converge on.
//!
//! # Available caches
//!
//! | Decorator | Tier | Backing crate | Feature |
//! |---|---|---|---|
//! | [`MokaEntityCache`] | in-process (per-pod) | [`moka`] | `moka-cache` (default-on) |
//! | [`ValkeyEntityCache`] | cluster (network) | [`fred`] | `valkey-cache` (opt-in; needs Valkey/Redis) |
//!
//! Production deployments typically compose both: `MokaEntityCache` over
//! `ValkeyEntityCache` over the concrete provider. moka catches the
//! per-pod hot path; valkey ensures new pods (after restart or scale-out)
//! see warm cache rather than thundering-herd onto the DB.
//!
//! [tower]: https://docs.rs/tower
//! [`moka`]: https://docs.rs/moka
//! [`fred`]: https://docs.rs/fred

mod invalidator;
pub use invalidator::CacheInvalidator;

// `EntityCache` is the canonical DST-friendly decorator for any
// `RequestEntityProvider`; TTL evaluated against an injected `Clock`
// (from `axess-clock`), capacity-bounded LRU via `axess-cache`'s
// `ClockTtlCache`. Always available; the Moka/Valkey backends below are
// alternatives for deployments that already standardised on those caches.
mod entity_cache;
pub use entity_cache::EntityCache;

#[cfg(feature = "moka-cache")]
mod moka_cache;

#[cfg(feature = "moka-cache")]
pub use moka_cache::MokaEntityCache;

#[cfg(feature = "valkey-cache")]
mod valkey_cache;

#[cfg(feature = "valkey-cache")]
pub use valkey_cache::ValkeyEntityCache;
