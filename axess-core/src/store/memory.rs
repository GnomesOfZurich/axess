//! In-memory [`Store`] backend for tests, single-process dev, and
//! prototyping. Implements [`Store<K, V>`] over a [`DashMap`](dashmap::DashMap) with
//! `chrono::DateTime<Utc>` deadlines driven by an injectable
//! [`axess_clock::Clock`] (so DST tests can advance time via
//! [`MockClock`](axess_clock::testing::MockClock) without `tokio::time::sleep`).
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
/// [`MockClock`](axess_clock::testing::MockClock) and call
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
mod tests {
    use super::*;
    use axess_clock::testing::MockClock;
    use chrono::TimeZone;

    type S = MemoryStore<String, u32>;

    fn anchor() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn store_with_clock() -> (S, Arc<MockClock>) {
        let clock = Arc::new(MockClock::at(anchor()));
        let store = S::new().with_clock(clock.clone() as Arc<dyn Clock>);
        (store, clock)
    }

    #[tokio::test]
    async fn put_then_get_returns_value() {
        let (s, _clock) = store_with_clock();
        s.put(&"k".to_string(), &42, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(s.get(&"k".to_string()).await.unwrap(), Some(42));
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let (s, _clock) = store_with_clock();
        assert_eq!(s.get(&"missing".to_string()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn put_overwrites_existing_value() {
        let (s, _clock) = store_with_clock();
        s.put(&"k".to_string(), &1, Duration::from_secs(60))
            .await
            .unwrap();
        s.put(&"k".to_string(), &2, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(s.get(&"k".to_string()).await.unwrap(), Some(2));
    }

    #[tokio::test]
    async fn delete_removes_entry() {
        let (s, _clock) = store_with_clock();
        s.put(&"k".to_string(), &1, Duration::from_secs(60))
            .await
            .unwrap();
        s.delete(&"k".to_string()).await.unwrap();
        assert_eq!(s.get(&"k".to_string()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn delete_missing_is_idempotent() {
        let (s, _clock) = store_with_clock();
        s.delete(&"never-existed".to_string()).await.unwrap();
    }

    #[tokio::test]
    async fn get_returns_none_after_ttl_expiry() {
        let (s, clock) = store_with_clock();
        s.put(&"k".to_string(), &1, Duration::from_secs(10))
            .await
            .unwrap();
        clock.advance_secs(11);
        assert_eq!(
            s.get(&"k".to_string()).await.unwrap(),
            None,
            "expired entry must not be returned by get"
        );
    }

    #[tokio::test]
    async fn prune_expired_reclaims_only_expired_entries() {
        let (s, clock) = store_with_clock();
        s.put(&"short".to_string(), &1, Duration::from_secs(10))
            .await
            .unwrap();
        s.put(&"long".to_string(), &2, Duration::from_secs(3600))
            .await
            .unwrap();
        clock.advance_secs(11);
        let removed = s.prune_expired().await.unwrap();
        assert_eq!(removed, 1, "only the short-TTL entry must be reclaimed");
        assert_eq!(s.get(&"long".to_string()).await.unwrap(), Some(2));
    }

    #[tokio::test]
    async fn prune_expired_returns_zero_when_nothing_expired() {
        let (s, _clock) = store_with_clock();
        s.put(&"k".to_string(), &1, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(s.prune_expired().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn duration_max_treated_as_never_expire_without_panic() {
        let (s, clock) = store_with_clock();
        s.put(&"forever".to_string(), &1, Duration::MAX)
            .await
            .unwrap();
        // Even after a century, the never-expire entry is still readable.
        clock.advance_secs(60 * 60 * 24 * 365 * 100);
        assert_eq!(s.get(&"forever".to_string()).await.unwrap(), Some(1));
    }

    #[tokio::test]
    async fn snapshot_returns_live_entries_only() {
        let (s, clock) = store_with_clock();
        s.put(&"alive".to_string(), &1, Duration::from_secs(3600))
            .await
            .unwrap();
        s.put(&"dead".to_string(), &2, Duration::from_secs(10))
            .await
            .unwrap();
        clock.advance_secs(11);
        let snap = s.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0], ("alive".to_string(), 1));
    }

    #[tokio::test]
    async fn snapshot_excludes_entry_at_exact_expiry_time() {
        // Pins the `expires_at > now` comparison in `snapshot` against the
        // `>=` mutation. At `now == expires_at` the entry must be treated
        // as expired (not visible). With `>=`, the same instant would
        // count as still-live and the entry would surface.
        let (s, clock) = store_with_clock();
        s.put(&"boundary".to_string(), &7, Duration::from_secs(10))
            .await
            .unwrap();
        clock.advance_secs(10);
        let snap = s.snapshot();
        assert!(
            snap.is_empty(),
            "entry at `expires_at == now` must be expired, not live; got {snap:?}"
        );
    }

    #[tokio::test]
    async fn update_returns_false_at_exact_expiry_time() {
        // Pins the `expires_at > now` comparison in `update` against the
        // `>=` mutation. Same logic as snapshot: the entry must be
        // considered absent at the exact expiry instant.
        let (s, clock) = store_with_clock();
        s.put(&"boundary".to_string(), &7, Duration::from_secs(10))
            .await
            .unwrap();
        clock.advance_secs(10);
        let updated = s.update(&"boundary".to_string(), |v| *v += 1);
        assert!(
            !updated,
            "update at `expires_at == now` must be a no-op (entry expired)"
        );
    }

    #[tokio::test]
    async fn update_mutates_existing_entry() {
        let (s, _clock) = store_with_clock();
        s.put(&"k".to_string(), &10, Duration::from_secs(60))
            .await
            .unwrap();
        let updated = s.update(&"k".to_string(), |v| *v += 5);
        assert!(updated);
        assert_eq!(s.get(&"k".to_string()).await.unwrap(), Some(15));
    }

    #[tokio::test]
    async fn update_returns_false_for_missing_key() {
        let (s, _clock) = store_with_clock();
        let updated = s.update(&"never-existed".to_string(), |v| *v += 1);
        assert!(!updated);
    }

    #[tokio::test]
    async fn update_returns_false_for_expired_entry() {
        let (s, clock) = store_with_clock();
        s.put(&"k".to_string(), &1, Duration::from_secs(10))
            .await
            .unwrap();
        clock.advance_secs(11);
        let updated = s.update(&"k".to_string(), |v| *v += 1);
        assert!(!updated, "expired entry must be treated as absent");
    }

    #[tokio::test]
    async fn clone_shares_state_via_arc() {
        let (s1, _clock) = store_with_clock();
        let s2 = s1.clone();
        s1.put(&"k".to_string(), &42, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(s2.get(&"k".to_string()).await.unwrap(), Some(42));
    }

    #[tokio::test]
    async fn len_and_is_empty_track_size() {
        let (s, _clock) = store_with_clock();
        assert!(s.is_empty());
        s.put(&"a".to_string(), &1, Duration::from_secs(60))
            .await
            .unwrap();
        s.put(&"b".to_string(), &2, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(s.len(), 2);
        assert!(!s.is_empty());
    }

    #[tokio::test]
    async fn default_clock_is_system_clock() {
        // Default `new()` uses SystemClock; verified by `now()` falling
        // within ~5s of std `Utc::now()`. (Not 0; SystemClock is
        // wall-clock-driven; we just confirm the value is plausibly
        // current.)
        let s = S::new();
        let now_via_clock = s.clock().now();
        let now_via_std = Utc::now();
        let drift = (now_via_std - now_via_clock).num_seconds().abs();
        assert!(drift < 5, "SystemClock drift {drift}s exceeds tolerance");
    }
}
