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
//! so they compose: stack the in-process cache over a valkey-backed
//! cache over your concrete provider, and the consumer
//! (the `require_authz!` macro from `axess_macros`,
//! [`AuthzStore`](super::session::AuthzStore)) sees a single provider
//! whose `entities_for` is now multi-tier cached.
//!
//! # Caching contract
//!
//! An entry is keyed on `(principal, tenant, resource, action)` and the
//! wrapped provider's
//! [`cache_discriminator`](super::RequestEntityProvider::cache_discriminator),
//! nothing more. Entities that depend on other session state (MFA status,
//! step-up recency, impersonation) are therefore shared between sessions of
//! the same user and tenant for the whole TTL, unless the provider names
//! that state in its discriminator. The supported shape is to keep the
//! entities to durable facts and put per-session facts in the Cedar
//! context, which is never cached.
//!
//! An invalidation also stops a load that was already running from
//! repopulating the entry it just removed.
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
//! | [`EntityCache`] | in-process (per-pod) | `axess-cache` | always available |
//! | [`ValkeyEntityCache`] | cluster (network) | [`fred`] | `valkey-cache` (opt-in; needs Valkey/Redis) |
//!
//! Production deployments typically compose both: `EntityCache` over
//! `ValkeyEntityCache` over the concrete provider. The in-process cache
//! catches the per-pod hot path; valkey ensures new pods (after restart or scale-out)
//! see warm cache rather than thundering-herd onto the DB.
//!
//! [tower]: https://docs.rs/tower
//! [`fred`]: https://docs.rs/fred

mod generation;
mod invalidator;
pub use invalidator::CacheInvalidator;

// `EntityCache` is the canonical DST-friendly decorator for any
// `RequestEntityProvider`; TTL evaluated against an injected `Clock`
// (from `axess-clock`), capacity-bounded LRU via `axess-cache`'s
// `ClockTtlCache`. Always available; the Valkey backend below is an
// alternative for deployments that share a cache across pods.
mod entity_cache;
pub use entity_cache::EntityCache;

#[cfg(feature = "valkey-cache")]
pub(crate) mod valkey_cache;

#[cfg(feature = "valkey-cache")]
pub use valkey_cache::ValkeyEntityCache;

#[cfg(test)]
mod shared_entities;
