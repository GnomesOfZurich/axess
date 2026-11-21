//! What the tests of the layer's session endings share: a sink that records
//! what it is told and what the store held at that moment, a store whose
//! operations can be made to fail, and the sessions the tests end.

use super::*;
use crate::authn::ids::UserId;
use crate::authn::ids::testing as ids;
use crate::session::data::SessionData;
use crate::session::id::SessionKey;
use crate::session::layer::audit::LayerSessionEnded;
use crate::session::store::{ConditionalUpdate, CycleOutcome, MemorySessionStore};
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A memory store that judges the lifetime of its rows on a clock at the
/// reference instant, so no test built on it reads the system's.
pub(super) fn memory_store() -> MemorySessionStore {
    MemorySessionStore::new().with_clock(Arc::new(MockClock::at_reference()))
}

pub(super) fn user() -> UserId {
    ids::user("u")
}

pub(super) fn admin() -> UserId {
    ids::user("admin")
}

/// A session of `user()` in tenant `t`, authenticated at the reference
/// instant.
pub(super) fn authenticated() -> SessionData {
    let mut data = SessionData::default();
    data.auth_state
        .set_authenticated(user(), ids::tenant("t"), MockClock::reference_time());
    data
}

/// [`authenticated`], impersonated by `admin()` since `after_secs` past the
/// reference instant.
pub(super) fn impersonated_since(after_secs: i64) -> SessionData {
    let mut data = authenticated();
    let since = MockClock::reference_time().plus(axess_clock::SignedDuration::seconds(after_secs));
    assert!(data.auth_state.set_impersonator(admin(), since));
    data
}

/// A row as it is stored, in a form two of them can be compared in: the
/// session record has no equality of its own.
pub(super) fn stored(row: &Option<SessionData>) -> serde_json::Value {
    serde_json::to_value(row).expect("a session record serialises")
}

/// One call of the sink: what it was told, and the row the store held under
/// the watched id at that moment.
#[derive(Debug, Clone)]
pub(super) struct Told {
    pub(super) ended: LayerSessionEnded,
    pub(super) row: Option<SessionData>,
}

/// A sink that records every call with the stored row it found, answers
/// `Err` while `failing` is set, and, when it has a gate, waits inside the
/// call until the test opens it.
pub(super) struct Sink {
    store: MemorySessionStore,
    /// The key whose row is read at each call; the ended session's own when
    /// `None`.
    watch: Option<SessionKey>,
    told: Mutex<Vec<Told>>,
    pub(super) failing: AtomicBool,
    /// Signalled each time the sink is entered.
    pub(super) entered: tokio::sync::Notify,
    gate: Option<tokio::sync::Semaphore>,
}

impl Sink {
    /// A sink that reads the ended session's row from `store` at each call.
    pub(super) fn on(store: &MemorySessionStore) -> Self {
        Self {
            store: store.clone(),
            watch: None,
            told: Mutex::new(Vec::new()),
            failing: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            gate: None,
        }
    }

    /// Read the row under `key` at each call instead of the ended session's.
    pub(super) fn watching(mut self, key: SessionKey) -> Self {
        self.watch = Some(key);
        self
    }

    /// Answer `Err` until `failing` is cleared.
    pub(super) fn failing(self) -> Self {
        self.failing.store(true, Ordering::SeqCst);
        self
    }

    /// Wait inside every call until [`open`](Self::open) lets it go on.
    pub(super) fn gated(mut self) -> Self {
        self.gate = Some(tokio::sync::Semaphore::new(0));
        self
    }

    /// Let one waiting call go on.
    pub(super) fn open(&self) {
        self.gate
            .as_ref()
            .expect("the sink has a gate")
            .add_permits(1);
    }

    pub(super) fn told(&self) -> Vec<Told> {
        self.told.lock().unwrap().clone()
    }

    /// The one call made.
    pub(super) fn the_call(&self) -> Told {
        let told = self.told();
        assert_eq!(told.len(), 1, "one call per ending: {told:?}");
        told[0].clone()
    }
}

impl SessionEndAudit for Sink {
    fn session_ended<'a>(
        &'a self,
        ended: &'a LayerSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let watched = self.watch.unwrap_or(ended.session_id);
            let Ok(row) = self.store.load(&watched).await;
            self.told.lock().unwrap().push(Told {
                ended: ended.clone(),
                row,
            });
            self.entered.notify_one();
            if let Some(gate) = &self.gate {
                gate.acquire().await.expect("the gate stays open").forget();
            }
            if self.failing.load(Ordering::SeqCst) {
                Err("sink down".to_string())
            } else {
                Ok(())
            }
        })
    }
}

/// Which operations of a [`Faulty`] store fail.
#[derive(Default)]
pub(super) struct Faults {
    /// How many of the next `delete` calls fail.
    pub(super) deletes: AtomicUsize,
    /// How many of the next `update_if_revision` calls succeed before every
    /// later one fails; `usize::MAX` for no failure.
    pub(super) swaps_before_failure: AtomicUsize,
    /// Every rotation fails.
    pub(super) cycles: AtomicBool,
    /// Every rotation answers `Conflict`.
    pub(super) conflicting_cycles: AtomicBool,
}

/// A memory store whose removals, compare-and-swaps and rotations fail on
/// request. Everything else, and every operation not made to fail, is the
/// memory store's.
#[derive(Clone)]
pub(super) struct Faulty {
    pub(super) inner: MemorySessionStore,
    pub(super) faults: Arc<Faults>,
}

impl Faulty {
    pub(super) fn over(inner: &MemorySessionStore) -> Self {
        let faults = Faults::default();
        faults
            .swaps_before_failure
            .store(usize::MAX, Ordering::SeqCst);
        Self {
            inner: inner.clone(),
            faults: Arc::new(faults),
        }
    }

    fn down() -> std::io::Error {
        std::io::Error::other("store unavailable")
    }

    /// The rotation's answer when it is made to fail or to conflict.
    fn cycle_fault(&self) -> Option<Result<CycleOutcome, std::io::Error>> {
        if self.faults.cycles.load(Ordering::SeqCst) {
            Some(Err(Self::down()))
        } else if self.faults.conflicting_cycles.load(Ordering::SeqCst) {
            Some(Ok(CycleOutcome::Conflict))
        } else {
            None
        }
    }
}

impl SessionStore for Faulty {
    type Error = std::io::Error;

    async fn load(&self, key: &SessionKey) -> Result<Option<SessionData>, Self::Error> {
        let Ok(row) = self.inner.load(key).await;
        Ok(row)
    }
    async fn save(
        &self,
        key: &SessionKey,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        let Ok(()) = self.inner.save(key, d, ttl).await;
        Ok(())
    }
    async fn delete(&self, key: &SessionKey) -> Result<(), Self::Error> {
        let failing = self
            .faults
            .deletes
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok();
        if failing {
            return Err(Self::down());
        }
        let Ok(()) = self.inner.delete(key).await;
        Ok(())
    }
    async fn update(
        &self,
        key: &SessionKey,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        let Ok(written) = self.inner.update(key, d, ttl).await;
        Ok(written)
    }
    async fn update_if_revision(
        &self,
        key: &SessionKey,
        expected: u64,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        let allowed = self
            .faults
            .swaps_before_failure
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| match left {
                usize::MAX => Some(usize::MAX),
                left => left.checked_sub(1),
            })
            .is_ok();
        if !allowed {
            return Err(Self::down());
        }
        let Ok(answer) = self.inner.update_if_revision(key, expected, d, ttl).await;
        Ok(answer)
    }
    async fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        d: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        if let Some(fault) = self.cycle_fault() {
            return fault;
        }
        let Ok(answer) = self.inner.cycle(old, new, d, ttl, require_old).await;
        Ok(answer)
    }
    async fn cycle_if_revision(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        d: &SessionData,
        ttl: Duration,
        require_old: bool,
        expected: u64,
    ) -> Result<CycleOutcome, Self::Error> {
        if let Some(fault) = self.cycle_fault() {
            return fault;
        }
        let Ok(answer) = self
            .inner
            .cycle_if_revision(old, new, d, ttl, require_old, expected)
            .await;
        Ok(answer)
    }
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    async fn find_sessions_for_user(
        &self,
        user: &UserId,
        limit: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Self::Error> {
        let Ok(found) = self.inner.find_sessions_for_user(user, limit).await;
        Ok(found)
    }
}
