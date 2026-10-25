//! The OIDC `sid` map: which local session a logout from the IdP ends.
//!
//! Populated by `complete_oauth_login` for every login whose ID token carries
//! a `sid`, read and drained by the back-channel and front-channel logout
//! handlers.
//!
//! # Shape
//!
//! One lock guards the structures below:
//!
//! - the entries, keyed `(issuer, sid)`;
//! - an index from `(issuer, user)` to that user's `sid`s under the issuer,
//!   so a logout by `sub` finds a user's sessions without a scan of the map;
//! - a queue of entries in insertion order, so ageing out the oldest costs
//!   the number of entries aged out, not the size of the map.
//!
//! A fourth structure, the subject registry, is separate in meaning: it maps
//! `(issuer, user)` to every session an OAuth login of that user under that
//! issuer established, whether or not the ID token carried a `sid`. A logout
//! by `sub` alone reaches a session through it even when the login has no
//! `sid` mapping, or when the mapping was dropped at capacity. Capacity
//! eviction of the `sid` entries never touches it, because the session may be
//! live; an entry leaves it when its session ends (a `sid` logout, a `sub`
//! logout, an aged-out mapping, a refused login) or when a bounded sweep finds
//! the session gone from the session registry. A `sid`-keyed logout for a
//! mapping that capacity evicted finds nothing under its key, and falls
//! through to the `sub` path when the logout token carries both.
//!
//! The queue may hold items whose entry has since been removed or replaced.
//! Such an item is recognised when it reaches the front (its entry is gone,
//! or carries another insertion time) and dropped; when stale items outnumber
//! live entries the queue is compacted, so it never grows past a small
//! multiple of the map.
//!
//! No registry call happens under the lock. Eviction returns what it removed
//! and the caller decides what to do with the sessions.

use crate::authn::ids::UserId;
use crate::session::id::SessionId;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

/// Key of the `sid` map: `(issuer, sid)`.
///
/// The `sid` is per-issuer in OIDC: two providers can legitimately mint the
/// same `sid` for different sessions, so the issuer is part of the key.
/// Without it a malicious or buggy IdP could log out sessions established
/// through another provider with a colliding `sid`.
pub type SidKey = (String, String);

/// What a `sid` maps to: the local user, their session, and when the mapping
/// was inserted.
pub type SidEntry = (UserId, SessionId, DateTime<Utc>);

/// Shared map from `(issuer, sid)` to the local session.
///
/// Cheap to clone; clones share one map. See the [module docs](self) for the
/// structure behind it.
#[derive(Clone, Default)]
pub struct SidMap {
    state: Arc<Mutex<SidState>>,
}

#[derive(Default)]
struct SidState {
    entries: HashMap<SidKey, SidEntry>,
    /// `(issuer, user)` -> the `sid`s of that user under that issuer.
    by_user: HashMap<(String, UserId), HashSet<String>>,
    /// Insertion order, oldest first. May hold stale items.
    order: VecDeque<(DateTime<Utc>, SidKey)>,
    /// `(issuer, user)` -> sessions their OAuth logins established.
    subjects: HashMap<(String, UserId), HashSet<SessionId>>,
    /// Number of `(issuer, user, session)` triples in `subjects`.
    subject_count: usize,
    /// Rotation queue over the subject triples, for the bounded sweep. May
    /// hold items whose triple has since been forgotten.
    subject_order: VecDeque<(String, UserId, SessionId)>,
}

/// Compact the queue once it exceeds this many items beyond twice the
/// number of live entries.
const QUEUE_SLACK: usize = 64;

impl SidState {
    fn insert(&mut self, key: SidKey, entry: SidEntry) -> Option<SidEntry> {
        let (user, _, at) = entry;
        let displaced = self.entries.insert(key.clone(), entry);
        if let Some((old_user, _, _)) = &displaced
            && *old_user != user
        {
            self.unindex(&key.0, old_user, &key.1);
        }
        self.by_user
            .entry((key.0.clone(), user))
            .or_default()
            .insert(key.1.clone());
        self.order.push_back((at, key));
        if self.order.len() > 2 * self.entries.len() + QUEUE_SLACK {
            let entries = &self.entries;
            self.order
                .retain(|(at, key)| entries.get(key).is_some_and(|e| e.2 == *at));
        }
        displaced
    }

    fn register_subject(&mut self, issuer: &str, user: UserId, session: SessionId) {
        let fresh = self
            .subjects
            .entry((issuer.to_string(), user))
            .or_default()
            .insert(session);
        if !fresh {
            return;
        }
        self.subject_count += 1;
        self.subject_order
            .push_back((issuer.to_string(), user, session));
        if self.subject_order.len() > 2 * self.subject_count + QUEUE_SLACK {
            let subjects = &self.subjects;
            self.subject_order.retain(|(iss, u, s)| {
                subjects
                    .get(&(iss.clone(), *u))
                    .is_some_and(|set| set.contains(s))
            });
        }
    }

    fn forget_subject(&mut self, issuer: &str, user: &UserId, session: &SessionId) -> bool {
        let slot = (issuer.to_string(), *user);
        let Some(set) = self.subjects.get_mut(&slot) else {
            return false;
        };
        let removed = set.remove(session);
        if set.is_empty() {
            self.subjects.remove(&slot);
        }
        if removed {
            self.subject_count -= 1;
        }
        removed
    }

    fn unindex(&mut self, issuer: &str, user: &UserId, sid: &str) {
        let slot = (issuer.to_string(), *user);
        if let Some(sids) = self.by_user.get_mut(&slot) {
            sids.remove(sid);
            if sids.is_empty() {
                self.by_user.remove(&slot);
            }
        }
    }

    fn remove(&mut self, key: &SidKey) -> Option<SidEntry> {
        let entry = self.entries.remove(key)?;
        self.unindex(&key.0, &entry.0, &key.1);
        Some(entry)
    }

    /// Pop up to `max` queue items from the front while `due` holds for the
    /// item's insertion time, removing the live entries among them.
    fn evict_front(
        &mut self,
        max: usize,
        due: impl Fn(DateTime<Utc>) -> bool,
    ) -> Vec<(SidKey, SidEntry)> {
        let mut evicted = Vec::new();
        for _ in 0..max {
            match self.order.front() {
                Some((at, _)) if due(*at) => {}
                _ => break,
            }
            let Some((at, key)) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&key).is_some_and(|e| e.2 == at)
                && let Some(entry) = self.remove(&key)
            {
                evicted.push((key, entry));
            }
        }
        evicted
    }
}

impl SidMap {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, SidState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Map `key` to the session. Returns the entry it displaced, if the key
    /// was already mapped; the caller owns ending that session.
    pub fn insert(
        &self,
        key: SidKey,
        user: UserId,
        session: SessionId,
        inserted_at: DateTime<Utc>,
    ) -> Option<SidEntry> {
        self.lock().insert(key, (user, session, inserted_at))
    }

    /// The entry for `key`, if any.
    pub fn get(&self, key: &SidKey) -> Option<SidEntry> {
        self.lock().entries.get(key).copied()
    }

    /// Whether `key` is mapped.
    pub fn contains_key(&self, key: &SidKey) -> bool {
        self.lock().entries.contains_key(key)
    }

    /// Remove and return the entry for `key`, and forget its session in the
    /// subject registry: the caller is about to end that session.
    pub fn remove(&self, key: &SidKey) -> Option<SidEntry> {
        let mut state = self.lock();
        let entry = state.remove(key)?;
        state.forget_subject(&key.0, &entry.0, &entry.1);
        Some(entry)
    }

    /// Record that `session` was established for `user` by a login under
    /// `issuer`, whether or not the login has a `sid` mapping. A `sub`-only
    /// logout reaches the session through [`take_subject_sessions`](Self::take_subject_sessions).
    pub fn register_subject_session(&self, issuer: &str, user: UserId, session: SessionId) {
        self.lock().register_subject(issuer, user, session);
    }

    /// Drop one session from the subject registry; returns whether it was
    /// there. Called once the session is known to have ended.
    pub fn forget_subject_session(&self, issuer: &str, user: &UserId, session: &SessionId) -> bool {
        self.lock().forget_subject(issuer, user, session)
    }

    /// Remove every session of `user` under `issuer` from the subject
    /// registry and return them, together with the `sid` entries that map to
    /// the same user and issuer. Other issuers and other users stay.
    pub fn take_subject_sessions(&self, issuer: &str, user: &UserId) -> Vec<SessionId> {
        let mut state = self.lock();
        let mut out: Vec<SessionId> = state
            .subjects
            .remove(&(issuer.to_string(), *user))
            .map(|set| set.into_iter().collect())
            .unwrap_or_default();
        state.subject_count -= out.len();
        if let Some(sids) = state.by_user.get(&(issuer.to_string(), *user)).cloned() {
            for sid in sids {
                if let Some((_, session, _)) = state.remove(&(issuer.to_string(), sid))
                    && !out.contains(&session)
                {
                    out.push(session);
                }
            }
        }
        out
    }

    /// Up to `max` subject triples to check for liveness, rotated to the back
    /// of the sweep queue so repeated calls cover the whole registry. Items
    /// whose triple was forgotten are dropped on the way.
    pub fn sweep_subject_candidates(&self, max: usize) -> Vec<(String, UserId, SessionId)> {
        let mut state = self.lock();
        let mut out = Vec::new();
        for _ in 0..max.min(state.subject_order.len()) {
            let Some((iss, user, session)) = state.subject_order.pop_front() else {
                break;
            };
            let live = state
                .subjects
                .get(&(iss.clone(), user))
                .is_some_and(|set| set.contains(&session));
            if live {
                state.subject_order.push_back((iss.clone(), user, session));
                out.push((iss, user, session));
            }
        }
        out
    }

    /// Number of sessions in the subject registry.
    pub fn subject_len(&self) -> usize {
        self.lock().subject_count
    }

    /// Remove every entry of `user` under `issuer` and return their sessions.
    /// Entries under other issuers, and other users' entries, stay.
    pub fn take_user_sessions(&self, issuer: &str, user: &UserId) -> Vec<SessionId> {
        let mut state = self.lock();
        let Some(sids) = state.by_user.get(&(issuer.to_string(), *user)).cloned() else {
            return Vec::new();
        };
        let taken: Vec<SessionId> = sids
            .into_iter()
            .filter_map(|sid| state.remove(&(issuer.to_string(), sid)))
            .map(|(_, session, _)| session)
            .collect();
        for session in &taken {
            state.forget_subject(issuer, user, session);
        }
        taken
    }

    /// Remove every entry that maps to `session`, in the subject registry too;
    /// returns how many `sid` entries went.
    ///
    /// A scan of the map, for the rare path that unwinds one login. The hot
    /// paths never call it.
    pub fn remove_session(&self, session: &SessionId) -> usize {
        let mut state = self.lock();
        let keys: Vec<SidKey> = state
            .entries
            .iter()
            .filter(|(_, e)| e.1 == *session)
            .map(|(k, _)| k.clone())
            .collect();
        let removed = keys.iter().filter_map(|k| state.remove(k)).count();
        let held: Vec<(String, UserId)> = state
            .subjects
            .iter()
            .filter(|(_, set)| set.contains(session))
            .map(|(slot, _)| slot.clone())
            .collect();
        for (issuer, user) in held {
            state.forget_subject(&issuer, &user, session);
        }
        removed
    }

    /// Remove up to `max` entries inserted before `cutoff`, oldest first.
    pub fn evict_inserted_before(
        &self,
        cutoff: DateTime<Utc>,
        max: usize,
    ) -> Vec<(SidKey, SidEntry)> {
        self.lock().evict_front(max, |at| at < cutoff)
    }

    /// Remove up to `max` of the oldest entries.
    pub fn evict_oldest(&self, max: usize) -> Vec<(SidKey, SidEntry)> {
        self.lock().evict_front(max, |_| true)
    }

    /// Number of mapped `sid`s.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Whether nothing is mapped.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for SidMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidMap")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
