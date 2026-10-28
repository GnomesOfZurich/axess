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
//! - an index from `(issuer, subject)` to the `sid`s of that IdP subject under
//!   the issuer, so a logout by `sub` finds a subject's sessions without a
//!   scan of the map;
//! - a queue of entries in insertion order, so ageing out the oldest costs
//!   the number of entries aged out, not the size of the map.
//!
//! Subjects are the IdP's own `sub` values, as the verified ID token carried
//! them, and are never the local user id: after account linking the two
//! differ, and a logout token names only the IdP's. Each session also records
//! the local user it belongs to, because ending a session in the registry
//! takes that id.
//!
//! A fourth structure, the subject registry, is separate in meaning: it maps
//! `(issuer, subject)` to every session an OAuth login of that subject under
//! that issuer established, whether or not the ID token carried a `sid`. A logout
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

/// A `sid` mapping together with the IdP subject it belongs to.
struct Stored {
    subject: String,
    user: UserId,
    session: SessionId,
    at: DateTime<Utc>,
}

impl Stored {
    fn entry(&self) -> SidEntry {
        (self.user, self.session, self.at)
    }
}

/// What the subject registry knows about one session.
struct SubjectOf {
    issuer: String,
    subject: String,
    user: UserId,
}

#[derive(Default)]
struct SidState {
    entries: HashMap<SidKey, Stored>,
    /// Session -> the keys that map to it, so unwinding one login costs its
    /// own entries and not a scan of the map.
    keys_of_session: HashMap<SessionId, HashSet<SidKey>>,
    /// `(issuer, subject)` -> the `sid`s of that subject under that issuer.
    by_subject: HashMap<(String, String), HashSet<String>>,
    /// Insertion order, oldest first. May hold stale items.
    order: VecDeque<(DateTime<Utc>, SidKey)>,
    /// `(issuer, subject)` -> sessions their OAuth logins established, each
    /// with the local user it belongs to.
    subjects: HashMap<(String, String), HashSet<(UserId, SessionId)>>,
    /// Session -> the subject registry record that holds it. One login
    /// establishes one session, so a session has at most one record.
    subject_of: HashMap<SessionId, SubjectOf>,
    /// Rotation queue over the subject triples, for the bounded sweep. May
    /// hold items whose triple has since been forgotten.
    subject_order: VecDeque<(String, UserId, SessionId)>,
}

/// Compact the queue once it exceeds this many items beyond twice the
/// number of live entries.
const QUEUE_SLACK: usize = 64;

impl SidState {
    fn insert(&mut self, key: SidKey, stored: Stored) -> Option<SidEntry> {
        let at = stored.at;
        let slot = (key.0.clone(), stored.subject.clone());
        let session = stored.session;
        let displaced = self.entries.insert(key.clone(), stored);
        if let Some(old) = &displaced {
            if old.subject != slot.1 {
                self.unindex(&key.0, &old.subject, &key.1);
            }
            self.unlink_session(&old.session, &key);
        }
        self.keys_of_session
            .entry(session)
            .or_default()
            .insert(key.clone());
        self.by_subject
            .entry(slot)
            .or_default()
            .insert(key.1.clone());
        // Re-inserting the same key at the same time (a frozen clock) leaves
        // the queue item already there; a second copy would only ever be
        // stale.
        if !displaced.as_ref().is_some_and(|old| old.at == at) {
            self.order.push_back((at, key));
        }
        if self.order.len() > 2 * self.entries.len() + QUEUE_SLACK {
            let entries = &self.entries;
            self.order
                .retain(|(at, key)| entries.get(key).is_some_and(|e| e.at == *at));
        }
        displaced.map(|old| old.entry())
    }

    fn register_subject(&mut self, issuer: &str, subject: &str, user: UserId, session: SessionId) {
        if let Some(held) = self.subject_of.get(&session) {
            if held.issuer == issuer && held.subject == subject && held.user == user {
                return;
            }
            // The session was recorded under another subject; a session
            // belongs to one login.
            let (old_issuer, old_user) = (held.issuer.clone(), held.user);
            self.forget_subject(&old_issuer, &old_user, &session);
        }
        self.subjects
            .entry((issuer.to_string(), subject.to_string()))
            .or_default()
            .insert((user, session));
        self.subject_of.insert(
            session,
            SubjectOf {
                issuer: issuer.to_string(),
                subject: subject.to_string(),
                user,
            },
        );
        self.subject_order
            .push_back((issuer.to_string(), user, session));
        if self.subject_order.len() > 2 * self.subject_of.len() + QUEUE_SLACK {
            let subject_of = &self.subject_of;
            self.subject_order.retain(|(iss, u, s)| {
                subject_of
                    .get(s)
                    .is_some_and(|held| held.issuer == *iss && held.user == *u)
            });
        }
    }

    /// Drop `session` from the subject registry when the record names this
    /// issuer and user.
    fn forget_subject(&mut self, issuer: &str, user: &UserId, session: &SessionId) -> bool {
        let matches = self
            .subject_of
            .get(session)
            .is_some_and(|held| held.issuer == issuer && held.user == *user);
        if !matches {
            return false;
        }
        let Some(held) = self.subject_of.remove(session) else {
            return false;
        };
        let slot = (held.issuer, held.subject);
        if let Some(set) = self.subjects.get_mut(&slot) {
            set.remove(&(held.user, *session));
            if set.is_empty() {
                self.subjects.remove(&slot);
            }
        }
        true
    }

    fn unlink_session(&mut self, session: &SessionId, key: &SidKey) {
        if let Some(keys) = self.keys_of_session.get_mut(session) {
            keys.remove(key);
            if keys.is_empty() {
                self.keys_of_session.remove(session);
            }
        }
    }

    fn unindex(&mut self, issuer: &str, subject: &str, sid: &str) {
        let slot = (issuer.to_string(), subject.to_string());
        if let Some(sids) = self.by_subject.get_mut(&slot) {
            sids.remove(sid);
            if sids.is_empty() {
                self.by_subject.remove(&slot);
            }
        }
    }

    fn remove(&mut self, key: &SidKey) -> Option<Stored> {
        let stored = self.entries.remove(key)?;
        self.unindex(&key.0, &stored.subject, &key.1);
        self.unlink_session(&stored.session, key);
        Some(stored)
    }

    /// Remove up to `max` live entries from the front of the queue while
    /// `due` holds for the item's insertion time. Stale items met on the way
    /// are dropped without counting toward `max`; each item is popped once,
    /// so the walk costs the items passed, amortised over the inserts.
    fn evict_front(
        &mut self,
        max: usize,
        due: impl Fn(DateTime<Utc>) -> bool,
    ) -> Vec<(SidKey, SidEntry)> {
        let mut evicted = Vec::new();
        while evicted.len() < max {
            match self.order.front() {
                Some((at, _)) if due(*at) => {}
                _ => break,
            }
            let Some((at, key)) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&key).is_some_and(|e| e.at == at)
                && let Some(stored) = self.remove(&key)
            {
                evicted.push((key, stored.entry()));
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

    /// Map `key` to the session of `user`, who logged in as the IdP subject
    /// `subject`. Returns the entry it displaced, if the key was already
    /// mapped; the caller owns ending that session.
    pub fn insert(
        &self,
        key: SidKey,
        subject: &str,
        user: UserId,
        session: SessionId,
        inserted_at: DateTime<Utc>,
    ) -> Option<SidEntry> {
        self.lock().insert(
            key,
            Stored {
                subject: subject.to_string(),
                user,
                session,
                at: inserted_at,
            },
        )
    }

    /// The entry for `key`, if any.
    pub fn get(&self, key: &SidKey) -> Option<SidEntry> {
        self.lock().entries.get(key).map(Stored::entry)
    }

    /// Whether `key` is mapped.
    pub fn contains_key(&self, key: &SidKey) -> bool {
        self.lock().entries.contains_key(key)
    }

    /// Remove and return the entry for `key`, and forget its session in the
    /// subject registry: the caller is about to end that session.
    pub fn remove(&self, key: &SidKey) -> Option<SidEntry> {
        let mut state = self.lock();
        let stored = state.remove(key)?;
        state.forget_subject(&key.0, &stored.user, &stored.session);
        Some(stored.entry())
    }

    /// Record that `session` was established for the local `user`, who logged
    /// in under `issuer` as the IdP subject `subject`, whether or not the
    /// login has a `sid` mapping. A `sub`-only logout reaches the session
    /// through [`take_subject_sessions`](Self::take_subject_sessions).
    pub fn register_subject_session(
        &self,
        issuer: &str,
        subject: &str,
        user: UserId,
        session: SessionId,
    ) {
        self.lock().register_subject(issuer, subject, user, session);
    }

    /// Drop one session from the subject registry; returns whether it was
    /// there. Called once the session is known to have ended.
    pub fn forget_subject_session(&self, issuer: &str, user: &UserId, session: &SessionId) -> bool {
        self.lock().forget_subject(issuer, user, session)
    }

    /// Remove every session of the IdP subject `subject` under `issuer` from
    /// the subject registry and return each with its local user, together
    /// with the sessions of the `sid` entries that map to the same subject and
    /// issuer. Other issuers and other subjects stay.
    pub fn take_subject_sessions(&self, issuer: &str, subject: &str) -> Vec<(UserId, SessionId)> {
        let mut state = self.lock();
        let slot = (issuer.to_string(), subject.to_string());
        let mut out: Vec<(UserId, SessionId)> = state
            .subjects
            .remove(&slot)
            .map(|set| set.into_iter().collect())
            .unwrap_or_default();
        for (_, session) in &out {
            state.subject_of.remove(session);
        }
        if let Some(sids) = state.by_subject.get(&slot).cloned() {
            for sid in sids {
                if let Some(stored) = state.remove(&(issuer.to_string(), sid)) {
                    let pair = (stored.user, stored.session);
                    if !out.contains(&pair) {
                        state.forget_subject(issuer, &stored.user, &stored.session);
                        out.push(pair);
                    }
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
                .subject_of
                .get(&session)
                .is_some_and(|held| held.issuer == iss && held.user == user);
            if live {
                state.subject_order.push_back((iss.clone(), user, session));
                out.push((iss, user, session));
            }
        }
        out
    }

    /// Number of sessions in the subject registry.
    pub fn subject_len(&self) -> usize {
        self.lock().subject_of.len()
    }

    /// Remove every entry that maps to `session`, in the subject registry too;
    /// returns how many `sid` entries went.
    ///
    /// Costs the session's own entries, through an index; the rare path that
    /// unwinds one login calls it.
    pub fn remove_session(&self, session: &SessionId) -> usize {
        let mut state = self.lock();
        let keys: Vec<SidKey> = state
            .keys_of_session
            .get(session)
            .map(|keys| keys.iter().cloned().collect())
            .unwrap_or_default();
        let removed = keys.iter().filter_map(|k| state.remove(k)).count();
        if let Some(held) = state.subject_of.get(session) {
            let (issuer, user) = (held.issuer.clone(), held.user);
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
