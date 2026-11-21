//! The doors a session's name leaves the layer and the service by, each
//! with a recorder: the session store, the registry, the sid store, the
//! audit sinks and the log, and the metrics beside them. Each trait is the
//! only way the layer and the service reach its backend, so what a recorder
//! was handed is everything that could have been written.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axess_clock::Timestamp;
use axess_core::authn::ids::{TenantId, UserId};
use axess_core::federation::backchannel_logout::{IdpSessionEnded, LogoutAudit};
use axess_core::federation::sid_map::{DisplacedSid, SidEntry, SidKey};
use axess_core::federation::sid_store::{SidFuture, SidStore};
use axess_core::session::store::{ConditionalUpdate, SessionStore};
use axess_core::session::{
    CycleOutcome, LayerSessionEnded, SessionData, SessionEndAudit, SessionKey,
};

/// What one door was handed: text and byte strings, in arrival order.
#[derive(Clone, Default)]
pub struct Seen(Arc<Mutex<Vec<Vec<u8>>>>);

impl Seen {
    pub fn text(&self, text: impl Into<String>) {
        self.bytes(text.into().into_bytes());
    }

    pub fn bytes(&self, bytes: Vec<u8>) {
        self.0.lock().unwrap().push(bytes);
    }

    pub fn key(&self, key: &SessionKey) {
        self.text(key.to_string());
    }

    pub fn all(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
}

// ── The session store ────────────────────────────────────────────────────────

/// A failure the recording store answers for a cycle while it is told to.
#[derive(Debug)]
pub enum StoreFault<E> {
    Inner(E),
    Refused,
}

impl<E: std::fmt::Display> std::fmt::Display for StoreFault<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(e) => e.fmt(f),
            Self::Refused => f.write_str("the test refused this cycle"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for StoreFault<E> {}

/// A session store that records the text of every key and the MessagePack
/// bytes of every row it is handed, and can be told to fail its cycles.
#[derive(Clone)]
pub struct RecordingStore<S> {
    inner: S,
    pub seen: Seen,
    fail_cycles: Arc<AtomicBool>,
}

impl<S> RecordingStore<S> {
    pub fn over(inner: S) -> Self {
        Self {
            inner,
            seen: Seen::default(),
            fail_cycles: Arc::default(),
        }
    }

    pub fn fail_cycles(&self, fail: bool) {
        self.fail_cycles.store(fail, Ordering::SeqCst);
    }

    fn row(&self, key: &SessionKey, data: &SessionData) {
        self.seen.key(key);
        self.seen
            .bytes(rmp_serde::to_vec_named(data).expect("a row serialises"));
    }

    fn refused(&self) -> bool {
        self.fail_cycles.load(Ordering::SeqCst)
    }
}

impl<S: SessionStore> SessionStore for RecordingStore<S> {
    type Error = StoreFault<S::Error>;

    async fn load(&self, key: &SessionKey) -> Result<Option<SessionData>, Self::Error> {
        self.seen.key(key);
        let row = self.inner.load(key).await.map_err(StoreFault::Inner)?;
        if let Some(data) = &row {
            self.row(key, data);
        }
        Ok(row)
    }

    async fn save(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.row(key, data);
        self.inner
            .save(key, data, ttl)
            .await
            .map_err(StoreFault::Inner)
    }

    async fn delete(&self, key: &SessionKey) -> Result<(), Self::Error> {
        self.seen.key(key);
        self.inner.delete(key).await.map_err(StoreFault::Inner)
    }

    async fn update(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        self.row(key, data);
        self.inner
            .update(key, data, ttl)
            .await
            .map_err(StoreFault::Inner)
    }

    async fn update_if_revision(
        &self,
        key: &SessionKey,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        self.row(key, data);
        self.inner
            .update_if_revision(key, expected_revision, data, ttl)
            .await
            .map_err(StoreFault::Inner)
    }

    async fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        self.seen.key(old);
        self.row(new, data);
        if self.refused() {
            return Err(StoreFault::Refused);
        }
        self.inner
            .cycle(old, new, data, ttl, require_old)
            .await
            .map_err(StoreFault::Inner)
    }

    async fn cycle_if_revision(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
        expected_revision: u64,
    ) -> Result<CycleOutcome, Self::Error> {
        self.seen.key(old);
        self.row(new, data);
        if self.refused() {
            return Err(StoreFault::Refused);
        }
        self.inner
            .cycle_if_revision(old, new, data, ttl, require_old, expected_revision)
            .await
            .map_err(StoreFault::Inner)
    }

    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        self.inner.prune_expired().await.map_err(StoreFault::Inner)
    }

    async fn find_sessions_for_user(
        &self,
        user_id: &UserId,
        limit: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Self::Error> {
        let rows = self
            .inner
            .find_sessions_for_user(user_id, limit)
            .await
            .map_err(StoreFault::Inner)?;
        for (key, data) in &rows {
            self.row(key, data);
        }
        Ok(rows)
    }
}

// ── The sid store ────────────────────────────────────────────────────────────

/// A sid store that records every argument it is given and every answer it
/// gives, around another.
#[derive(Clone)]
pub struct RecordingSid {
    inner: Arc<dyn SidStore>,
    pub seen: Seen,
}

impl RecordingSid {
    pub fn over(inner: Arc<dyn SidStore>) -> Self {
        Self {
            inner,
            seen: Seen::default(),
        }
    }

    fn entry(&self, entry: &SidEntry) {
        self.seen.text(format!("{entry:?}"));
        self.seen.key(&entry.1);
    }

    fn displaced(&self, displaced: &DisplacedSid) {
        self.seen.text(format!("{displaced:?}"));
        self.seen.key(&displaced.session);
    }
}

impl SidStore for RecordingSid {
    fn insert_displacing<'a>(
        &'a self,
        key: SidKey,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionKey,
        inserted_at: Timestamp,
    ) -> SidFuture<'a, Option<DisplacedSid>> {
        self.seen
            .text(format!("{key:?} {subject} {tenant:?} {user} {inserted_at}"));
        self.seen.key(&session);
        Box::pin(async move {
            let displaced = self
                .inner
                .insert_displacing(key, subject, tenant, user, session, inserted_at)
                .await?;
            if let Some(displaced) = &displaced {
                self.displaced(displaced);
            }
            Ok(displaced)
        })
    }

    fn restore_if_vacant(&self, key: SidKey, displaced: DisplacedSid) -> SidFuture<'_, bool> {
        self.seen.text(format!("{key:?}"));
        self.displaced(&displaced);
        self.inner.restore_if_vacant(key, displaced)
    }

    fn get<'a>(
        &'a self,
        key: &'a SidKey,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Option<SidEntry>> {
        self.seen.text(format!("{key:?} {scope:?}"));
        Box::pin(async move {
            let entry = self.inner.get(key, scope).await?;
            if let Some(entry) = &entry {
                self.entry(entry);
            }
            Ok(entry)
        })
    }

    fn remove_if_session<'a>(
        &'a self,
        key: &'a SidKey,
        session: &'a SessionKey,
    ) -> SidFuture<'a, Option<SidEntry>> {
        self.seen.text(format!("{key:?}"));
        self.seen.key(session);
        Box::pin(async move {
            let entry = self.inner.remove_if_session(key, session).await?;
            if let Some(entry) = &entry {
                self.entry(entry);
            }
            Ok(entry)
        })
    }

    fn register_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionKey,
    ) -> SidFuture<'a, ()> {
        self.seen
            .text(format!("{issuer} {subject} {tenant:?} {user}"));
        self.seen.key(&session);
        self.inner
            .register_subject_session(issuer, subject, tenant, user, session)
    }

    fn forget_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        user: &'a UserId,
        session: &'a SessionKey,
    ) -> SidFuture<'a, bool> {
        self.seen.text(format!("{issuer} {user}"));
        self.seen.key(session);
        self.inner.forget_subject_session(issuer, user, session)
    }

    fn subject_sessions<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Vec<(UserId, SessionKey)>> {
        self.seen.text(format!("{issuer} {subject} {scope:?}"));
        Box::pin(async move {
            let sessions = self.inner.subject_sessions(issuer, subject, scope).await?;
            for (user, session) in &sessions {
                self.seen.text(user.to_string());
                self.seen.key(session);
            }
            Ok(sessions)
        })
    }

    fn sweep_subject_candidates(
        &self,
        max: usize,
    ) -> SidFuture<'_, Vec<(String, UserId, SessionKey)>> {
        Box::pin(async move {
            let candidates = self.inner.sweep_subject_candidates(max).await?;
            for (issuer, user, session) in &candidates {
                self.seen.text(format!("{issuer} {user}"));
                self.seen.key(session);
            }
            Ok(candidates)
        })
    }

    fn remove_session<'a>(&'a self, session: &'a SessionKey) -> SidFuture<'a, usize> {
        self.seen.key(session);
        self.inner.remove_session(session)
    }

    fn evict_inserted_before(
        &self,
        cutoff: Timestamp,
        max: usize,
    ) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        Box::pin(async move {
            let evicted = self.inner.evict_inserted_before(cutoff, max).await?;
            for (key, entry) in &evicted {
                self.seen.text(format!("{key:?}"));
                self.entry(entry);
            }
            Ok(evicted)
        })
    }

    fn evict_oldest(&self, max: usize) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        Box::pin(async move {
            let evicted = self.inner.evict_oldest(max).await?;
            for (key, entry) in &evicted {
                self.seen.text(format!("{key:?}"));
                self.entry(entry);
            }
            Ok(evicted)
        })
    }

    fn mapping_count(&self) -> SidFuture<'_, usize> {
        self.inner.mapping_count()
    }
}

// ── The audit sinks ──────────────────────────────────────────────────────────

/// The layer's session-end sink, recording the `Debug` text of every ending
/// it is told of and the key it names, around the service's own sink.
pub struct RecordingEnds {
    pub inner: Arc<dyn SessionEndAudit>,
    pub seen: Seen,
}

impl SessionEndAudit for RecordingEnds {
    fn session_ended<'a>(
        &'a self,
        ended: &'a LayerSessionEnded,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        self.seen.text(format!("{ended:?}"));
        self.seen.key(&ended.session_id);
        self.inner.session_ended(ended)
    }
}

/// The back-channel logout's sink, recording as [`RecordingEnds`] does.
pub struct RecordingLogouts {
    pub inner: Arc<dyn LogoutAudit>,
    pub seen: Seen,
}

impl LogoutAudit for RecordingLogouts {
    fn session_ended<'a>(
        &'a self,
        ended: &'a IdpSessionEnded,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        self.seen.text(format!("{ended:?}"));
        self.seen.key(&ended.session_id);
        self.inner.session_ended(ended)
    }
}
