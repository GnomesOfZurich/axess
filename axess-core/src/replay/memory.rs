//! The replay store in one process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axess_clock::Clock;
use axess_clock::Timestamp;
use axess_factors::jwt::verifier::{JtiReplayError, JtiReplayStore};
use sha2::{Digest, Sha256};

/// Live records a [`MemoryJtiReplayStore`] holds by default. A record is a
/// 32-byte digest and a time whatever the `jti`'s length, so the bound is a
/// bound in bytes too.
pub const DEFAULT_MEMORY_JTI_CAPACITY: usize = 262_144;

/// A [`JtiReplayStore`] in one process, for a single node, a test or a
/// development server.
///
/// It records what it is handed, so a `jti` is accepted once for as long as
/// its `ttl` runs on the store's clock. It protects the process it lives
/// in: of several nodes each keeps its own, and a token one node accepted is
/// accepted once more by every other, so a fleet uses a store every node
/// reaches (`ValkeyJtiReplayStore`).
///
/// The `jti` is kept as its SHA-256 digest: the sender chose it, and a
/// record has one size whatever it sent. The store holds at most
/// [`DEFAULT_MEMORY_JTI_CAPACITY`] live records
/// ([`with_capacity`](Self::with_capacity) changes it). At the bound it
/// first drops what has expired; if it is still full it refuses with
/// [`JtiReplayError::Backend`], a store that cannot answer, and never
/// forgets a live record to make room: the cost of a flood is availability
/// for the length of the replay window, not a replay.
#[derive(Clone)]
pub struct MemoryJtiReplayStore {
    live: Arc<Mutex<HashMap<[u8; 32], Timestamp>>>,
    capacity: usize,
    clock: Arc<dyn Clock>,
}

impl Default for MemoryJtiReplayStore {
    fn default() -> Self {
        Self {
            live: Arc::new(Mutex::new(HashMap::new())),
            capacity: DEFAULT_MEMORY_JTI_CAPACITY,
            clock: Arc::new(axess_clock::SystemClock),
        }
    }
}

impl MemoryJtiReplayStore {
    /// An empty store on the system clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use `clock` to decide when a record has expired. Give it the clock
    /// the verifier runs on.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Bound the number of live records. Size it above what legitimate
    /// clients present inside one replay window.
    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }
}

impl std::fmt::Debug for MemoryJtiReplayStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryJtiReplayStore")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl JtiReplayStore for MemoryJtiReplayStore {
    async fn check_and_record(&self, jti: &str, ttl: Duration) -> Result<(), JtiReplayError> {
        let now = self.clock.now();
        let expires_at = axess_clock::SignedDuration::try_from(ttl)
            .ok()
            .and_then(|ttl| now.checked_add(ttl))
            .ok_or_else(|| JtiReplayError::Backend("replay window does not fit a date".into()))?;
        let digest: [u8; 32] = Sha256::digest(jti.as_bytes()).into();
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A record is live until its expiry and gone at it.
        if live.get(&digest).is_some_and(|until| *until > now) {
            // The sender's `jti` is not echoed.
            return Err(JtiReplayError::already_used(
                "a jti this store already holds",
            ));
        }
        if live.len() >= self.capacity {
            live.retain(|_, until| *until > now);
            if live.len() >= self.capacity {
                return Err(JtiReplayError::Backend(
                    "the in-process replay store is at its capacity".into(),
                ));
            }
        }
        live.insert(digest, expires_at);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_clock::testing::MockClock;

    fn store(clock: &MockClock) -> MemoryJtiReplayStore {
        MemoryJtiReplayStore::new().with_clock(Arc::new(clock.clone()))
    }

    /// A `jti` is accepted once for its `ttl` on the store's clock: refused
    /// one second before the end, accepted again at it.
    #[tokio::test]
    async fn a_jti_is_recorded_once_until_its_ttl_ends() {
        let clock = MockClock::at_reference();
        let store = store(&clock);
        let ttl = Duration::from_secs(30);
        assert!(store.records());
        assert!(store.check_and_record("a", ttl).await.is_ok());
        assert!(matches!(
            store.check_and_record("a", ttl).await,
            Err(JtiReplayError::AlreadyUsed(text)) if text.as_str() == "a jti this store already holds"
        ));
        assert!(store.check_and_record("b", ttl).await.is_ok());
        clock.advance_secs(29);
        assert!(matches!(
            store.check_and_record("a", ttl).await,
            Err(JtiReplayError::AlreadyUsed(_))
        ));
        clock.advance_secs(1);
        assert!(store.check_and_record("a", ttl).await.is_ok());
    }

    /// A full store drops what has expired to make room, and when nothing
    /// has, it is a store that cannot answer: never a replay, and never a
    /// live record forgotten.
    #[tokio::test]
    async fn a_full_store_refuses_as_a_fault_and_forgets_nothing_live() {
        let clock = MockClock::at_reference();
        let store = store(&clock).with_capacity(2);
        let ttl = Duration::from_secs(30);
        assert!(store.check_and_record("a", ttl).await.is_ok());
        clock.advance_secs(10);
        assert!(store.check_and_record("b", ttl).await.is_ok());
        assert!(matches!(
            store.check_and_record("c", ttl).await,
            Err(JtiReplayError::Backend(_))
        ));
        assert!(matches!(
            store.check_and_record("a", ttl).await,
            Err(JtiReplayError::AlreadyUsed(_))
        ));
        // `a` expires; its place is taken and `b` is still held.
        clock.advance_secs(20);
        assert!(store.check_and_record("c", ttl).await.is_ok());
        assert!(matches!(
            store.check_and_record("b", ttl).await,
            Err(JtiReplayError::AlreadyUsed(_))
        ));
        assert_eq!(
            format!("{store:?}"),
            "MemoryJtiReplayStore { capacity: 2, .. }"
        );
    }

    /// A window that does not fit a date is refused, not wrapped.
    #[tokio::test]
    async fn a_window_past_the_end_of_time_is_a_fault() {
        let clock = MockClock::at_reference();
        assert!(matches!(
            store(&clock).check_and_record("a", Duration::MAX).await,
            Err(JtiReplayError::Backend(_))
        ));
    }
}
