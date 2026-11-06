//! [`MemorySessionRegistry`]: the in-memory [`SessionRegistry`] for tests and
//! single-node development.

use super::SessionRegistry;
use crate::health::{HealthCheck, HealthStatus};
use crate::locked::lock;
use crate::session::id::SessionId;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// In-memory session registry backed by one `Mutex<HashMap>`.
///
/// Maps `user_id -> Vec<SessionId>` (insertion-ordered). **For testing
/// and single-node development only.**
///
/// Uses a `Vec<SessionId>` whose push order tracks insertion order so
/// [`Self::active_sessions`] returns sessions oldest-first, satisfying
/// the [`SessionRegistry::active_sessions`] "ordered oldest first"
/// contract (load-bearing for the
/// [`max_sessions_per_user`](crate::authn::service::AuthnServiceBuilder::with_max_sessions_per_user)
/// FIFO eviction in `complete_factor_step`). The cost is O(N) lookup
/// for `is_valid` and `invalidate_session`, but N is bounded by the
/// concurrent-session limit (typically ≤10) and the Memory registry
/// is testing-only.
///
/// # Lifetime
///
/// Each entry carries the time it was registered or last used, and is
/// forgotten once it is older than the registry's TTL (24 hours by default,
/// as in `ValkeySessionRegistry`; see [`with_ttl`](Self::with_ttl)). A
/// session that is used keeps its entry: `is_valid` moves the stamp forward
/// once half the TTL has gone. The clock is injectable with
/// [`with_clock`](Self::with_clock).
#[derive(Clone)]
pub struct MemorySessionRegistry {
    pub(super) valid: Arc<Mutex<HashMap<Arc<str>, Vec<RegisteredSession>>>>,
    ttl: Duration,
    clock: Arc<dyn axess_clock::Clock>,
    /// The number of users at which `register` next drops the expired
    /// entries of every user, not only the registering one.
    sweep_at: Arc<std::sync::atomic::AtomicUsize>,
}

/// The fewest users a registry holds before it sweeps for expired entries;
/// after a sweep the next one waits for twice the users that remained, so a
/// sweep's cost is spread over the registrations that fill the map.
const MIN_SWEEP_USERS: usize = 32;

/// A session id and when it was registered or last used.
type RegisteredSession = (SessionId, chrono::DateTime<chrono::Utc>);

impl Default for MemorySessionRegistry {
    fn default() -> Self {
        Self {
            valid: Arc::default(),
            ttl: Duration::from_secs(24 * 60 * 60),
            clock: Arc::new(axess_clock::SystemClock),
            sweep_at: Arc::new(std::sync::atomic::AtomicUsize::new(MIN_SWEEP_USERS)),
        }
    }
}

impl MemorySessionRegistry {
    /// Create an empty in-memory session registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// This registry as the handle [`SessionLayer::new`](crate::session::layer::SessionLayer::new)
    /// takes.
    pub fn handle(self) -> Arc<dyn super::SessionRegistryHandle> {
        Arc::new(super::SessionRegistryAdapter(self))
    }

    /// Set how long an entry lives without being used. Defaults to 24 hours.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Inject a [`Clock`](axess_clock::Clock) for deterministic simulation
    /// testing. Defaults to [`SystemClock`](axess_clock::SystemClock).
    pub fn with_clock(mut self, clock: Arc<dyn axess_clock::Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The oldest stamp that is still live at `now`.
    fn cutoff(&self, now: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
        chrono::Duration::from_std(self.ttl)
            .ok()
            .and_then(|ttl| now.checked_sub_signed(ttl))
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC)
    }
}

/// Infallible error for the in-memory registry. The in-memory backend
/// cannot fail at the storage boundary, so callers can prove statically
/// that no error case is possible. Aliased to `std::convert::Infallible`
/// rather than carrying an empty enum so `?`-propagation and exhaustive
/// matches behave the canonical way.
pub type MemoryRegistryError = std::convert::Infallible;

impl SessionRegistry for MemorySessionRegistry {
    type Error = MemoryRegistryError;

    async fn register(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        // Dedup-on-insert preserves FIFO semantics; a re-register of an
        // existing id keeps the original position (it renews the stamp)
        // rather than appending a duplicate. Entries past the TTL go.
        let now = self.clock.now();
        let cutoff = self.cutoff(now);
        let mut valid = lock(&self.valid);
        let entry = valid.entry(Arc::from(user_id.to_string())).or_default();
        entry.retain(|(_, at)| *at > cutoff);
        match entry.iter_mut().find(|(s, _)| s == session_id) {
            Some((_, at)) => *at = now,
            None => entry.push((*session_id, now)),
        }
        // Users who never return would keep their entries for ever, since
        // the prune above reaches only the registering user. Once the map
        // has grown to the sweep size, every user's expired entries go.
        use std::sync::atomic::Ordering::Relaxed;
        if valid.len() >= self.sweep_at.load(Relaxed) {
            valid.retain(|_, sessions| {
                sessions.retain(|(_, at)| *at > cutoff);
                !sessions.is_empty()
            });
            self.sweep_at
                .store(valid.len().saturating_mul(2).max(MIN_SWEEP_USERS), Relaxed);
        }
        Ok(())
    }

    async fn is_valid(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<bool, Self::Error> {
        let now = self.clock.now();
        let cutoff = self.cutoff(now);
        let mut valid = lock(&self.valid);
        let Some(sessions) = valid.get_mut(user_id.to_string().as_str()) else {
            return Ok(false);
        };
        let half = chrono::Duration::from_std(self.ttl / 2).unwrap_or(chrono::Duration::MAX);
        Ok(sessions
            .iter_mut()
            .find(|(s, _)| s == session_id)
            .is_some_and(|(_, at)| {
                let live = *at > cutoff;
                // A session that is used keeps its entry, as in the Valkey
                // registry: the stamp moves forward once half the TTL has gone.
                if live && now - *at >= half {
                    *at = now;
                }
                live
            }))
    }

    async fn invalidate_user(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), Self::Error> {
        lock(&self.valid).remove(user_id.to_string().as_str());
        Ok(())
    }

    async fn invalidate_session(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        let key = user_id.to_string();
        let mut valid = lock(&self.valid);
        if let Some(sessions) = valid.get_mut(key.as_str()) {
            sessions.retain(|(s, _)| s != session_id);
        }
        // A user with no session left keeps no entry.
        valid.retain(|k, v| &**k != key.as_str() || !v.is_empty());
        Ok(())
    }

    async fn active_sessions(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<Vec<SessionId>, Self::Error> {
        let cutoff = self.cutoff(self.clock.now());
        Ok(lock(&self.valid)
            .get(user_id.to_string().as_str())
            .map(|sessions| {
                sessions
                    .iter()
                    .filter(|(_, at)| *at > cutoff)
                    .map(|(s, _)| *s)
                    .collect()
            })
            .unwrap_or_default())
    }
}

impl HealthCheck for MemorySessionRegistry {
    fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async { HealthStatus::Healthy })
    }
}
