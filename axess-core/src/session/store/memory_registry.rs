//! [`MemorySessionRegistry`]: the in-memory [`SessionRegistry`] for tests and
//! single-node development.

use super::{CutOff, MAX_MOVE_RECORDS_PER_USER, MoveOutcome, SessionRegistry};
use crate::authn::ids::UserId;
use crate::health::{HealthCheck, HealthStatus};
use crate::locked::lock;
use crate::session::id::SessionKey;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// In-memory session registry backed by one `Mutex<HashMap>`.
///
/// Maps each user to their entries (insertion-ordered) and the records of
/// their sessions' moves. **For testing and single-node development only.**
///
/// The entries are a `Vec<SessionKey>` whose push order tracks insertion order so
/// [`Self::active_sessions`] returns sessions oldest-first, satisfying
/// the [`SessionRegistry::active_sessions`] "ordered oldest first"
/// contract (load-bearing for the
/// [`max_sessions_per_user`](crate::authn::service::AuthnServiceBuilder::with_max_sessions_per_user)
/// FIFO eviction in `complete_factor_step`). A move replaces a session's
/// key in place, so the session keeps its place in that order. The cost is
/// O(N) lookup for `is_valid` and `invalidate_session`, but N is bounded by
/// the concurrent-session limit (typically ≤10) and the Memory registry is
/// testing-only.
///
/// Every method takes the one lock once, so each is one step: no other
/// call on the registry falls inside a move, a cut-off or an ending.
///
/// # Lifetime
///
/// Each entry carries the time it was registered or last used, and is
/// forgotten once it is older than the registry's TTL (24 hours by default,
/// as in `ValkeySessionRegistry`; see [`with_ttl`](Self::with_ttl)). A
/// session that is used keeps its entry: `is_valid` moves the stamp forward
/// once half the TTL has gone. A move record lives as long as the entry it
/// leads to. The clock is injectable with [`with_clock`](Self::with_clock).
#[derive(Clone)]
pub struct MemorySessionRegistry {
    pub(super) valid: Arc<Mutex<HashMap<Arc<str>, UserEntries>>>,
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

/// A session's key and when it was registered or last used.
type RegisteredSession = (SessionKey, axess_clock::Timestamp);

/// A move record: the session that was under `former` is under `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MoveRecord {
    pub(super) former: SessionKey,
    pub(super) target: SessionKey,
}

/// One user's entries, in registration order, and the records of their
/// sessions' moves, in the order the moves were made: a record keeps its
/// place when it is re-pointed, and a new one goes last.
#[derive(Debug, Default)]
pub(super) struct UserEntries {
    pub(super) sessions: Vec<RegisteredSession>,
    pub(super) moves: Vec<MoveRecord>,
}

impl UserEntries {
    /// Drop the entries older than `cutoff` and the records that lead to
    /// none of the entries left.
    fn prune(&mut self, cutoff: axess_clock::Timestamp) {
        self.sessions.retain(|(_, at)| *at > cutoff);
        let held: HashSet<SessionKey> = self.sessions.iter().map(|(s, _)| *s).collect();
        self.moves.retain(|record| held.contains(&record.target));
    }

    /// Whether the entry under `session` is live at `cutoff`.
    fn live(&self, session: &SessionKey, cutoff: axess_clock::Timestamp) -> bool {
        self.sessions
            .iter()
            .any(|(s, at)| s == session && *at > cutoff)
    }

    /// The key the session once under `session` is under now, when live.
    fn current(&self, session: &SessionKey, cutoff: axess_clock::Timestamp) -> Option<SessionKey> {
        if self.live(session, cutoff) {
            return Some(*session);
        }
        self.moves
            .iter()
            .find(|record| record.former == *session)
            .map(|record| record.target)
            .filter(|target| self.live(target, cutoff))
    }

    /// At the bound, give up the earliest record that is not the first
    /// former key of its session. The records are in the order the moves
    /// were made, so the first record seen for a target is that session's
    /// first former key; the first record whose target was seen before is
    /// the one given up. `false` when every record is a first former key.
    fn give_up_one_record(&mut self) -> bool {
        let mut seen = HashSet::new();
        let Some(at) = self
            .moves
            .iter()
            .position(|record| !seen.insert(record.target))
        else {
            return false;
        };
        self.moves.remove(at);
        true
    }
}

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
    fn cutoff(&self, now: axess_clock::Timestamp) -> axess_clock::Timestamp {
        axess_clock::SignedDuration::try_from(self.ttl)
            .ok()
            .and_then(|ttl| now.checked_sub(ttl))
            // A lifetime longer than the range reaches back before every
            // reading: every stamp is still live.
            .unwrap_or(axess_clock::Timestamp::MIN)
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

    async fn register(&self, user_id: &UserId, session: &SessionKey) -> Result<(), Self::Error> {
        // Dedup-on-insert preserves FIFO semantics; a re-register of an
        // existing key keeps the original position (it renews the stamp)
        // rather than appending a duplicate. Entries past the TTL go, and so
        // do the records that led to them.
        let now = self.clock.now();
        let cutoff = self.cutoff(now);
        let mut valid = lock(&self.valid);
        let entry = valid.entry(Arc::from(user_id.to_string())).or_default();
        entry.prune(cutoff);
        match entry.sessions.iter_mut().find(|(s, _)| s == session) {
            Some((_, at)) => *at = now,
            None => entry.sessions.push((*session, now)),
        }
        // A registered key is not a former one.
        entry.moves.retain(|record| record.former != *session);
        // Users who never return would keep their entries for ever, since
        // the prune above reaches only the registering user. Once the map
        // has grown to the sweep size, every user's expired entries go.
        use std::sync::atomic::Ordering::Relaxed;
        if valid.len() >= self.sweep_at.load(Relaxed) {
            valid.retain(|_, entry| {
                entry.prune(cutoff);
                !entry.sessions.is_empty()
            });
            self.sweep_at
                .store(valid.len().saturating_mul(2).max(MIN_SWEEP_USERS), Relaxed);
        }
        Ok(())
    }

    async fn is_valid(&self, user_id: &UserId, session: &SessionKey) -> Result<bool, Self::Error> {
        // The entries alone decide: a key the session was moved away from
        // has a record and no entry, so it is not valid.
        let now = self.clock.now();
        let cutoff = self.cutoff(now);
        let mut valid = lock(&self.valid);
        let Some(entry) = valid.get_mut(user_id.to_string().as_str()) else {
            return Ok(false);
        };
        let half = axess_clock::SignedDuration::try_from(self.ttl / 2)
            .unwrap_or(axess_clock::SignedDuration::MAX);
        Ok(entry
            .sessions
            .iter_mut()
            .find(|(s, _)| s == session)
            .is_some_and(|(_, at)| {
                let live = *at > cutoff;
                // A session that is used keeps its entry, as in the Valkey
                // registry: the stamp moves forward once half the TTL has gone.
                if live && now.since(*at) >= half {
                    *at = now;
                }
                live
            }))
    }

    async fn invalidate_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
        lock(&self.valid).remove(user_id.to_string().as_str());
        Ok(())
    }

    async fn invalidate_session(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> Result<(), Self::Error> {
        // One hold of the lock: the session `session` names, or the one a
        // move took it to, is ended with everything under `session` and the
        // records that led to it.
        let cutoff = self.cutoff(self.clock.now());
        let key = user_id.to_string();
        let mut valid = lock(&self.valid);
        if let Some(entry) = valid.get_mut(key.as_str()) {
            let target = entry.current(session, cutoff);
            entry
                .sessions
                .retain(|(s, _)| s != session && Some(*s) != target);
            entry
                .moves
                .retain(|record| record.former != *session && Some(record.target) != target);
        }
        // A user with no session left keeps no entry.
        valid.retain(|k, v| &**k != key.as_str() || !v.sessions.is_empty());
        Ok(())
    }

    async fn invalidate_other_sessions(
        &self,
        user_id: &UserId,
        keep: &SessionKey,
    ) -> Result<CutOff, Self::Error> {
        // One hold of the map's lock from the look for `keep` to the last
        // removal: a registration or a move lands before it and is ended, or
        // after it.
        let cutoff = self.cutoff(self.clock.now());
        let key = user_id.to_string();
        let mut valid = lock(&self.valid);
        let Some(entry) = valid.get_mut(key.as_str()) else {
            return Ok(CutOff::NotHeld);
        };
        if entry.live(keep, cutoff) {
            let ended = entry
                .sessions
                .iter()
                .filter(|(s, _)| s != keep)
                .map(|(s, _)| *s)
                .collect();
            entry.sessions.retain(|(s, _)| s == keep);
            entry.moves.retain(|record| record.target == *keep);
            return Ok(CutOff::KeptOne(ended));
        }
        if entry.current(keep, cutoff).is_none() {
            return Ok(CutOff::NotHeld);
        }
        // Another request moved the session to keep: every session of the
        // user ends, that one included (see the trait).
        let ended = entry.sessions.iter().map(|(s, _)| *s).collect();
        valid.remove(key.as_str());
        Ok(CutOff::KeptNone(ended))
    }

    async fn move_session(
        &self,
        user_id: &UserId,
        old: &SessionKey,
        new: &SessionKey,
    ) -> Result<MoveOutcome, Self::Error> {
        // One hold of the lock from the look for `old` to the last record
        // written: no registration, ending or cut-off of the user falls
        // between them.
        let now = self.clock.now();
        let cutoff = self.cutoff(now);
        let mut valid = lock(&self.valid);
        let Some(entry) = valid.get_mut(user_id.to_string().as_str()) else {
            return Ok(MoveOutcome::OldGone);
        };
        entry.prune(cutoff);
        let Some(at) = entry.sessions.iter().position(|(s, _)| s == old) else {
            return Ok(MoveOutcome::OldGone);
        };
        if old == new {
            entry.sessions[at].1 = now;
            return Ok(MoveOutcome::Moved);
        }
        if entry.moves.len() >= MAX_MOVE_RECORDS_PER_USER && !entry.give_up_one_record() {
            return Ok(MoveOutcome::Full);
        }
        // An entry already under `new` gives way: the session keeps the
        // place `old` had, which is its registration time.
        let at = match entry.sessions.iter().position(|(s, _)| s == new) {
            Some(other) => {
                entry.sessions.remove(other);
                if other < at { at - 1 } else { at }
            }
            None => at,
        };
        entry.sessions[at] = (*new, now);
        for record in &mut entry.moves {
            if record.target == *old {
                record.target = *new;
            }
        }
        entry
            .moves
            .retain(|record| record.former != *new && record.former != *old);
        entry.moves.push(MoveRecord {
            former: *old,
            target: *new,
        });
        Ok(MoveOutcome::Moved)
    }

    async fn current_key(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> Result<Option<SessionKey>, Self::Error> {
        let cutoff = self.cutoff(self.clock.now());
        Ok(lock(&self.valid)
            .get(user_id.to_string().as_str())
            .and_then(|entry| entry.current(session, cutoff)))
    }

    async fn active_sessions(&self, user_id: &UserId) -> Result<Vec<SessionKey>, Self::Error> {
        let cutoff = self.cutoff(self.clock.now());
        Ok(lock(&self.valid)
            .get(user_id.to_string().as_str())
            .map(|entry| {
                entry
                    .sessions
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
