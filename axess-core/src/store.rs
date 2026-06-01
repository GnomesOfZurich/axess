//! Shared key/value-with-TTL store abstraction.
//!
//! Provides a single `Store<K, V>` trait so `SessionStore` (and any
//! adopter-defined kv-shaped store) can share one set of backends
//! instead of each shipping its own copy of the SQL/Valkey glue.
//! Per-backend serialization is owned by the concrete backend wrapper
//! (`SessionCodec`, `BindingsCodec`); there is no cross-backend
//! `Codec<V>` trait: the dialect-specific SQL bodies were too thin to
//! justify a `sqlx::Database` + `Codec<V>` bound surface (see
//! `session/storage/sql_helpers.rs` for the close-out rationale).
//!
//! Stores with non-kv semantics, `IdentityStore`, `FactorStore`,
//! `DeviceStore`, `SessionRegistry`, stay distinct because their
//! domain primitives (secondary indexes, set membership, pub/sub on
//! revocation) don't fit a flat key/value put.

use std::future::Future;
use std::time::Duration;

/// In-memory [`Store`] backend: `DashMap` + monotonic `Instant`
/// deadlines for TTL. Codec-free (values stored by `Clone` rather
/// than serialised) so adopters reaching for `MemoryStore` for tests
/// don't pay an encode/decode round-trip per operation. Per-store
/// wrappers like `MemoryRefreshTokenStore` are thin newtypes around
/// this backend.
///
/// Gated behind `cfg(any(test, feature = "memory"))` so production
/// builds without the `memory` feature cannot ship an in-memory store
/// by accident.
#[cfg(any(test, feature = "memory"))]
pub mod memory;
#[cfg(any(test, feature = "memory"))]
pub use memory::MemoryStore;

/// Generic key/value-with-TTL store. Implemented by per-backend
/// wrappers (`MemoryStore`, `SqlStore`, `ValkeyStore`) so each
/// per-store newtype (e.g. `SqliteSessionStore`) reduces to a thin
/// delegating shim.
///
/// The trait carries no `cycle` / index-query primitives; those are
/// per-store specifics that live on the domain trait
/// (`SessionStore::cycle`, `RefreshTokenStore::revoke_family`, …)
/// which wraps the underlying `Store` and dispatches to backend-specific
/// helpers for the non-kv operations.
pub trait Store<K, V>: Send + Sync + Clone + 'static
where
    K: Send + Sync + ?Sized,
    V: Send + Sync,
{
    /// Backend-specific error. Use the shared [`StoreError`] enum for
    /// new backends; legacy wrappers may continue to surface
    /// `SqlStoreError` / `ValkeyStoreError` / `PostgresStoreError`
    /// until each is consolidated.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Fetch the value for `key`. `Ok(None)` when the key is absent
    /// (including TTL-expired); `Err` only on backend failure.
    fn get(&self, key: &K) -> impl Future<Output = Result<Option<V>, Self::Error>> + Send;

    /// Insert or replace the value at `key` with the given TTL.
    fn put(
        &self,
        key: &K,
        value: &V,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Remove the entry at `key`. Idempotent; does not error if absent.
    fn delete(&self, key: &K) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Bulk-evict every TTL-expired entry. Returns the number reclaimed.
    /// Backends with native TTL eviction (Valkey/Redis) may implement
    /// this as a no-op returning `Ok(0)`; backends owning their own
    /// row table (SQLite, Postgres, in-memory) actually delete.
    fn prune_expired(&self) -> impl Future<Output = Result<u64, Self::Error>> + Send;
}

/// Generic store error. Adopters and per-backend `SqlStore` /
/// `ValkeyStore` impls use this in place of the legacy per-store
/// errors (`SqlStoreError`, `ValkeyStoreError`, …) once they have
/// been migrated.
///
/// The type parameter `B` is the backend's native error type
/// (`sqlx::Error`, `fred::error::Error`, `Infallible` for memory).
#[derive(Debug, thiserror::Error)]
pub enum StoreError<B>
where
    B: std::error::Error + Send + Sync + 'static,
{
    /// Underlying backend reported an error (network, protocol,
    /// schema, …).
    #[error("backend: {0}")]
    Backend(#[source] B),
}
