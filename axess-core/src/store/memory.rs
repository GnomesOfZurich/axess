//! In-memory [`Store`] backend for tests, single-process dev, and
//! prototyping. Implements [`Store<K, V>`] over a [`DashMap`](dashmap::DashMap) with
//! `chrono::DateTime<Utc>` deadlines driven by an injectable
//! [`axess_clock::Clock`] (so DST tests can advance time via
//! `MockClock` without `tokio::time::sleep`).
//!
//! Not for production: process-local, lost on restart, no encryption
//! at rest. Per-store wrappers like `MemorySessionStore` are thin
//! newtypes around this backend.

use crate::store::Store;
use axess_clock::{Clock, SystemClock};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use std::convert::Infallible;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

/// In-memory `Store<K, V>` backend.
///
/// `K` must be `Eq + Hash + Clone + Sized + Send + Sync + 'static` for
/// the underlying `DashMap`; `V` must be `Clone + Send + Sync +
/// 'static`. (`Store<K, V>` allows `K: ?Sized`, but a memory map keys
/// by value so we tighten here.)
///
/// `prune_expired` reclaims entries whose deadline has passed. Backends
/// with native TTL (Valkey) implement `prune_expired` as a no-op;
/// this one actually deletes: it owns its own row table.
///
/// Time source is the injected [`axess_clock::Clock`] (default
/// [`SystemClock`]); tests inject a
/// `MockClock` and call
/// `advance_secs` instead of sleeping. The injected clock flows into
/// every wrapper that delegates to this backend, so the wrapper's
/// own `with_clock(...)` is just a re-export of the backend's.
pub struct MemoryStore<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    inner: Arc<DashMap<K, Entry<V>>>,
    clock: Arc<dyn Clock>,
}

#[derive(Debug, Clone)]
struct Entry<V> {
    value: V,
    expires_at: DateTime<Utc>,
}

impl<K, V> std::fmt::Debug for MemoryStore<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStore")
            .field("entries", &self.inner.len())
            .finish()
    }
}

impl<K, V> Clone for MemoryStore<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            clock: self.clock.clone(),
        }
    }
}

impl<K, V> Default for MemoryStore<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> MemoryStore<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create an empty store driven by [`SystemClock`]. Use
    /// [`with_clock`](Self::with_clock) for DST.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            clock: Arc::new(SystemClock),
        }
    }

    /// Inject a [`Clock`] for deterministic-simulation testing. In
    /// production, leave at the default [`SystemClock`].
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Shared handle to the injected clock: wrappers that delegate to
    /// this backend re-expose `now()` through their own clock view by
    /// reaching here.
    pub fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }

    /// Snapshot every live (non-expired) entry as `(key, value)` clones.
    /// Wrappers use this for secondary-index scans (`find_by_hash`,
    /// `active_for_user`, …): the [`Store`] trait carries no
    /// iteration primitive because byte-serialising backends can't
    /// implement one cheaply.
    ///
    /// Allocates a `Vec` per call; appropriate for in-memory dev/test
    /// loads, not production hot paths.
    pub fn snapshot(&self) -> Vec<(K, V)> {
        let now = self.clock.now();
        self.inner
            .iter()
            .filter(|e| e.value().expires_at > now)
            .map(|e| (e.key().clone(), e.value().value.clone()))
            .collect()
    }

    /// Read-modify-write on a single key. Returns `true` if the key
    /// existed and `f` ran. Expired entries are treated as absent
    /// (returns `false`, does not run `f`).
    pub fn update<F>(&self, key: &K, mut f: F) -> bool
    where
        F: FnMut(&mut V),
    {
        let now = self.clock.now();
        match self.inner.get_mut(key) {
            Some(mut entry) if entry.expires_at > now => {
                f(&mut entry.value);
                true
            }
            _ => false,
        }
    }

    /// Synchronous prune for callers that want to reclaim expired
    /// entries without an `await`. The async [`Store::prune_expired`]
    /// wraps this; both have identical semantics.
    pub fn prune_expired_sync(&self) -> u64 {
        let now = self.clock.now();
        let before = self.inner.len();
        self.inner.retain(|_, entry| entry.expires_at > now);
        let after = self.inner.len();
        (before - after) as u64
    }

    /// Current entry count (including expired entries that have not
    /// yet been pruned). Use [`prune_expired`](Store::prune_expired)
    /// to reclaim them first if the count must be precise.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the underlying map is empty (live + expired-not-pruned).
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Whether the key has a physical entry in the map, **including
    /// expired-not-yet-pruned**. Primarily for diagnostics + tests
    /// that need to distinguish "absent" from "expired-still-present"
    /// (e.g. asserting that an eviction sweep ran).
    ///
    /// Most callers want [`Store::get`] (which returns `None` for
    /// expired entries) instead.
    pub fn physically_contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }
}

impl<K, V> Store<K, V> for MemoryStore<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    type Error = Infallible;

    fn get(&self, key: &K) -> impl Future<Output = Result<Option<V>, Self::Error>> + Send {
        let now = self.clock.now();
        let result = self
            .inner
            .get(key)
            .filter(|e| e.expires_at > now)
            .map(|e| e.value.clone());
        async move { Ok(result) }
    }

    fn put(
        &self,
        key: &K,
        value: &V,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        // Saturating: chrono's `Duration::from_std` errors on
        // overflow-large values (caller passing `Duration::MAX` as
        // an explicit "never expire" sentinel). Fall back to a far-
        // future deadline rather than panicking.
        let now = self.clock.now();
        let expires_at = ChronoDuration::from_std(ttl)
            .ok()
            .and_then(|d| now.checked_add_signed(d))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        self.inner.insert(
            key.clone(),
            Entry {
                value: value.clone(),
                expires_at,
            },
        );
        async { Ok(()) }
    }

    fn delete(&self, key: &K) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.remove(key);
        async { Ok(()) }
    }

    fn prune_expired(&self) -> impl Future<Output = Result<u64, Self::Error>> + Send {
        let removed = self.prune_expired_sync();
        async move { Ok(removed) }
    }
}

#[cfg(test)]
mod tests;
