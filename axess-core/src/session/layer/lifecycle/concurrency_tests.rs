//! A stored session written by two requests at once, a rotation that races
//! a concurrent write, and the rule that a cookie follows the stored state:
//! no `Set-Cookie` for a row that was not written.

use super::*;
use crate::authn::ids::testing as ids;
use crate::session::data::SessionData;
use crate::session::id::{SessionId, SessionKey};
use crate::session::layer::handle::{ConsumeTarget, SessionHandle, SessionInner};
use crate::session::store::{ConditionalUpdate, CycleOutcome, MemorySessionStore, SessionStore};
use crate::testing::mock_random::MockRng;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::RwLock;

pub(super) const TTL: Duration = Duration::from_secs(600);

fn authenticated() -> SessionData {
    let mut data = SessionData::default();
    data.auth_state.set_authenticated(
        ids::user("u"),
        ids::tenant("t"),
        axess_clock::testing::MockClock::reference_time(),
    );
    data
}

/// The in-memory state of a request that loaded `loaded` from `store`.
pub(super) fn request_holding(
    store: &MemorySessionStore,
    id: SessionId,
    loaded: &SessionData,
) -> SessionInner {
    SessionInner {
        session: CookieSession::of_id(id),
        data: loaded.clone(),
        // A loaded signed-in row is registered under the key it arrived with.
        registered: loaded
            .auth_state
            .signed_in()
            .map(|signed_in| (*signed_in.user_id, SessionKey::of(&id))),
        max_custom_bytes: 0,
        consume: Some(ConsumeTarget {
            store: Arc::new(store.clone()),
            ttl: TTL,
            loaded: Some(loaded.clone()),
        }),
        ..SessionInner::detached(Arc::new(MockRng::new(1)))
    }
}

async fn finalize<S>(store: &S, inner: SessionInner, existing: Option<SessionId>) -> FinalizeOutcome
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    finalize_telling(
        store,
        inner,
        existing,
        &crate::session::UnrecordedSessionEnds,
    )
    .await
}

/// The finalize stage of a request that ends with `inner`, telling `audit`
/// of a session it ends.
pub(super) async fn finalize_telling<S>(
    store: &S,
    inner: SessionInner,
    existing: Option<SessionId>,
    audit: &dyn SessionEndAudit,
) -> FinalizeOutcome
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let cfg = SessionConfig::builder().ttl(TTL).build();
    finalize_session(
        store,
        &cfg,
        Reporting {
            metrics: None,
            audit,
        },
        &axess_clock::testing::MockClock::at_reference(),
        &SessionHandle(Arc::new(RwLock::new(inner))),
        existing.is_some(),
        &MockRng::new(9),
    )
    .await
}

// ── the finalize write is a compare-and-swap ───────────────────────────────

/// Request B loaded the session and changed its cart while request A took
/// the one-shot ceremony value through the store. B's write must not put the
/// value back, and must keep the cart.
#[tokio::test]
async fn a_modified_session_does_not_write_a_consumed_value_back() {
    let store = MemorySessionStore::new();
    let id = SessionId::new(&MockRng::new(2));
    let loaded = SessionData {
        custom: serde_json::json!({"ceremony": "state", "cart": 0}),
        ..SessionData::default()
    };
    store
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut b = request_holding(&store, id, &loaded);
    b.data.custom["cart"] = serde_json::json!(1);
    b.modified = true;

    let mut by_a = loaded.clone();
    by_a.custom.as_object_mut().unwrap().remove("ceremony");
    by_a.revision = 1;
    assert_eq!(
        store
            .update_if_revision(&SessionKey::of(&id), 0, &by_a, TTL)
            .await
            .unwrap(),
        ConditionalUpdate::Written
    );

    let outcome = finalize(&store, b, Some(id)).await;

    let stored = store.load(&SessionKey::of(&id)).await.unwrap().unwrap();
    assert!(
        stored.custom.get("ceremony").is_none(),
        "a value taken by a concurrent request stays taken"
    );
    assert_eq!(
        stored.custom["cart"],
        serde_json::json!(1),
        "this request's own change is kept"
    );
    assert!(outcome.session_changed);
}

/// Request B rotates the session id while request A takes the one-shot
/// ceremony value. The row B writes under the new id must not bring the value
/// back, and keeps B's own change.
#[tokio::test]
async fn a_rotation_does_not_write_a_consumed_value_under_the_new_id() {
    let store = MemorySessionStore::new();
    let id = SessionId::new(&MockRng::new(30));
    let loaded = SessionData {
        custom: serde_json::json!({"ceremony": "state", "cart": 0}),
        ..SessionData::default()
    };
    store
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut b = request_holding(&store, id, &loaded);
    b.data.custom["cart"] = serde_json::json!(1);
    b.modified = true;
    b.rotate_id();
    let new_key = *b.session.key();

    let mut by_a = loaded.clone();
    by_a.custom.as_object_mut().unwrap().remove("ceremony");
    by_a.revision = 1;
    assert_eq!(
        store
            .update_if_revision(&SessionKey::of(&id), 0, &by_a, TTL)
            .await
            .unwrap(),
        ConditionalUpdate::Written
    );

    finalize(&store, b, Some(id)).await;

    let stored = store.load(&new_key).await.unwrap().unwrap();
    assert!(
        stored.custom.get("ceremony").is_none(),
        "a value taken by a concurrent request stays taken, got {}",
        stored.custom
    );
    assert_eq!(stored.custom["cart"], serde_json::json!(1));
}

/// Write `custom` over the row at `id` as a concurrent request would: a
/// compare-and-swap from the revision stored now.
async fn concurrent_write(store: &MemorySessionStore, key: &SessionKey, custom: serde_json::Value) {
    let mut row = store.load(key).await.unwrap().unwrap();
    let expected = row.revision;
    row.custom = custom;
    row.revision = expected + 1;
    assert_eq!(
        store
            .update_if_revision(key, expected, &row, TTL)
            .await
            .unwrap(),
        ConditionalUpdate::Written
    );
}

/// A login clears what the visitor held and rotates the id. A key a
/// concurrent request wrote to the old row meanwhile (planted before the
/// login) must not reappear in the authenticated session under the new id.
#[tokio::test]
async fn a_login_does_not_take_in_keys_a_concurrent_request_planted() {
    let store = MemorySessionStore::new();
    let id = SessionId::new(&MockRng::new(40));
    let loaded = SessionData {
        custom: serde_json::json!({"flow": "s", "old": 1}),
        ..SessionData::default()
    };
    store
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut login = request_holding(&store, id, &loaded);
    login.data = authenticated();
    login.data.custom = serde_json::json!({"flow": "s"});
    login.modified = true;
    login.rotate_id();
    let new_key = *login.session.key();
    concurrent_write(
        &store,
        &SessionKey::of(&id),
        serde_json::json!({"flow": "s", "old": 1, "planted": "x"}),
    )
    .await;

    finalize(&store, login, Some(id)).await;

    let stored = store.load(&new_key).await.unwrap().unwrap();
    assert!(
        stored.custom.get("planted").is_none(),
        "a key planted before the login must not enter the session, got {}",
        stored.custom
    );
    assert_eq!(stored.custom["flow"], "s");
}

/// Request C restarts a ceremony; this request takes another one-shot value
/// and so picks C's ceremony up through a merge; request E then takes the
/// ceremony. This request's finalize conflicts with E and must not write
/// the ceremony back: the value it carries came from C, not from itself.
#[tokio::test]
async fn a_value_merged_in_by_a_take_is_not_written_back_after_another_take() {
    let store = MemorySessionStore::new();
    let id = SessionId::new(&MockRng::new(20));
    let loaded = SessionData {
        custom: serde_json::json!({"ceremony": "s", "token": "t"}),
        ..SessionData::default()
    };
    store
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut a = request_holding(&store, id, &loaded);
    concurrent_write(
        &store,
        &SessionKey::of(&id),
        serde_json::json!({"ceremony": "new", "token": "t"}),
    )
    .await;
    assert_eq!(
        a.consume_custom("token").await,
        Some(serde_json::json!("t"))
    );
    assert_eq!(a.data.custom, serde_json::json!({"ceremony": "new"}));
    concurrent_write(&store, &SessionKey::of(&id), serde_json::json!({})).await;

    finalize(&store, a, Some(id)).await;

    let stored = store.load(&SessionKey::of(&id)).await.unwrap().unwrap();
    assert!(
        stored.custom.get("ceremony").is_none(),
        "the ceremony another request took stays taken, got {}",
        stored.custom
    );
}

/// A store that lets one concurrent write land right after the first read of
/// the row, as a request racing a retry would.
#[derive(Clone)]
struct WritesAfterFirstRead {
    inner: MemorySessionStore,
    then_write: Arc<Mutex<Option<serde_json::Value>>>,
}

impl SessionStore for WritesAfterFirstRead {
    type Error = std::convert::Infallible;
    async fn find_sessions_for_user(
        &self,
        _: &crate::authn::ids::UserId,
        _: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Self::Error> {
        Ok(Vec::new())
    }
    async fn load(&self, key: &SessionKey) -> Result<Option<SessionData>, Self::Error> {
        let row = self.inner.load(key).await?;
        let pending = self.then_write.lock().unwrap().take();
        if let Some(custom) = pending {
            concurrent_write(&self.inner, key, custom).await;
        }
        Ok(row)
    }
    async fn save(
        &self,
        key: &SessionKey,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.inner.save(key, d, ttl).await
    }
    async fn delete(&self, key: &SessionKey) -> Result<(), Self::Error> {
        self.inner.delete(key).await
    }
    async fn update(
        &self,
        key: &SessionKey,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        self.inner.update(key, d, ttl).await
    }
    async fn update_if_revision(
        &self,
        key: &SessionKey,
        expected: u64,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        self.inner.update_if_revision(key, expected, d, ttl).await
    }
    async fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        d: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        self.inner.cycle(old, new, d, ttl, require_old).await
    }
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        self.inner.prune_expired().await
    }
}

/// This request's finalize conflicts with request C, which restarted a
/// ceremony, and merges; before the retry, request E takes that ceremony.
/// The retry must not write the ceremony back: only the cart is this
/// request's own change.
#[tokio::test]
async fn a_retry_does_not_count_a_merged_in_value_as_this_requests_change() {
    let store = WritesAfterFirstRead {
        inner: MemorySessionStore::new(),
        then_write: Arc::new(Mutex::new(None)),
    };
    let id = SessionId::new(&MockRng::new(21));
    let loaded = SessionData {
        custom: serde_json::json!({"ceremony": "s"}),
        ..SessionData::default()
    };
    store
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut a = request_holding(&store.inner, id, &loaded);
    a.data.custom["cart"] = serde_json::json!(1);
    a.modified = true;
    concurrent_write(
        &store.inner,
        &SessionKey::of(&id),
        serde_json::json!({"ceremony": "new"}),
    )
    .await;
    *store.then_write.lock().unwrap() = Some(serde_json::json!({}));

    let outcome = finalize(&store, a, Some(id)).await;

    let stored = store.load(&SessionKey::of(&id)).await.unwrap().unwrap();
    assert!(outcome.session_changed);
    assert!(
        stored.custom.get("ceremony").is_none(),
        "the ceremony another request took stays taken, got {}",
        stored.custom
    );
    assert_eq!(stored.custom["cart"], serde_json::json!(1));
}

/// A store whose reads fail; its writes reach the wrapped store.
#[derive(Clone)]
struct FailingReads(MemorySessionStore);

impl SessionStore for FailingReads {
    type Error = std::io::Error;
    async fn find_sessions_for_user(
        &self,
        _: &crate::authn::ids::UserId,
        _: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Self::Error> {
        Ok(Vec::new())
    }
    async fn load(&self, _: &SessionKey) -> Result<Option<SessionData>, Self::Error> {
        Err(std::io::Error::other("store unavailable"))
    }
    async fn save(
        &self,
        key: &SessionKey,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.0.save(key, d, ttl).await.unwrap();
        Ok(())
    }
    async fn delete(&self, key: &SessionKey) -> Result<(), Self::Error> {
        self.0.delete(key).await.unwrap();
        Ok(())
    }
    async fn update(
        &self,
        key: &SessionKey,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        Ok(self.0.update(key, d, ttl).await.unwrap())
    }
    async fn update_if_revision(
        &self,
        key: &SessionKey,
        expected: u64,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        Ok(self
            .0
            .update_if_revision(key, expected, d, ttl)
            .await
            .unwrap())
    }
    async fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        d: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        Ok(self.0.cycle(old, new, d, ttl, require_old).await.unwrap())
    }
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        Ok(0)
    }
}

/// A rotation that cannot read the row it retires cannot tell whether a
/// concurrent request changed it, so it fails closed: the new id carries no
/// login and no rotation is reported.
#[tokio::test]
async fn a_rotation_that_cannot_read_the_old_row_fails_closed() {
    let store = FailingReads(MemorySessionStore::new());
    let id = SessionId::new(&MockRng::new(31));
    let loaded = SessionData {
        custom: serde_json::json!({"ceremony": "state"}),
        ..SessionData::default()
    };
    store
        .0
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut b = request_holding(&store.0, id, &loaded);
    b.data.auth_state.set_authenticated(
        ids::user("u"),
        ids::tenant("t"),
        axess_clock::testing::MockClock::reference_time(),
    );
    b.modified = true;
    b.rotate_id();
    let new_key = *b.session.key();

    let outcome = finalize(&store, b, Some(id)).await;

    assert!(outcome.rotation.is_none(), "no rotation is reported");
    let carried = store.0.load(&new_key).await.unwrap();
    assert!(
        carried.is_none_or(|row| !row.auth_state.is_authenticated()),
        "the login must not reach the new id"
    );
    assert!(
        store.0.load(&SessionKey::of(&id)).await.unwrap().is_none(),
        "the retired row is deleted"
    );
}

/// Without the loaded row to merge from, a request whose write finds the row
/// changed discards its changes rather than overwrite them.
#[tokio::test]
async fn a_conflicting_write_without_a_base_is_discarded() {
    let store = MemorySessionStore::new();
    let id = SessionId::new(&MockRng::new(3));
    let loaded = SessionData {
        custom: serde_json::json!({"ceremony": "state"}),
        ..SessionData::default()
    };
    store
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut b = request_holding(&store, id, &loaded);
    b.consume = None;
    b.data.custom["cart"] = serde_json::json!(1);
    b.modified = true;
    let mut by_a = loaded.clone();
    by_a.custom = serde_json::json!({});
    by_a.revision = 1;
    assert_eq!(
        store
            .update_if_revision(&SessionKey::of(&id), 0, &by_a, TTL)
            .await
            .unwrap(),
        ConditionalUpdate::Written
    );

    let outcome = finalize(&store, b, Some(id)).await;

    let stored = store.load(&SessionKey::of(&id)).await.unwrap().unwrap();
    assert_eq!(stored.custom, serde_json::json!({}));
    assert!(
        !outcome.session_changed,
        "nothing was written, so no cookie"
    );
}

// ── a rotation that races a revocation ─────────────────────────────────────

/// A store whose writes fail.
#[derive(Clone)]
struct FailingWrites(MemorySessionStore);

impl SessionStore for FailingWrites {
    type Error = std::io::Error;
    async fn find_sessions_for_user(
        &self,
        _: &crate::authn::ids::UserId,
        _: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Self::Error> {
        Ok(Vec::new())
    }
    async fn load(&self, key: &SessionKey) -> Result<Option<SessionData>, Self::Error> {
        Ok(self.0.load(key).await.unwrap())
    }
    async fn save(&self, _: &SessionKey, _: &SessionData, _: Duration) -> Result<(), Self::Error> {
        Err(std::io::Error::other("store unavailable"))
    }
    async fn delete(&self, key: &SessionKey) -> Result<(), Self::Error> {
        self.0.delete(key).await.unwrap();
        Ok(())
    }
    async fn update(
        &self,
        _: &SessionKey,
        _: &SessionData,
        _: Duration,
    ) -> Result<bool, Self::Error> {
        Err(std::io::Error::other("store unavailable"))
    }
    async fn update_if_revision(
        &self,
        _: &SessionKey,
        _: u64,
        _: &SessionData,
        _: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        Err(std::io::Error::other("store unavailable"))
    }
    async fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        Ok(self
            .0
            .cycle(old, new, data, ttl, require_old)
            .await
            .unwrap())
    }
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        Ok(0)
    }
}

/// A stored session whose update failed is not re-issued a cookie: the
/// client keeps the one it holds, and the row keeps what it had.
#[tokio::test]
async fn a_failed_update_issues_no_cookie() {
    let store = FailingWrites(MemorySessionStore::new());
    let id = SessionId::new(&MockRng::new(14));
    store
        .0
        .save(&SessionKey::of(&id), &SessionData::default(), TTL)
        .await
        .unwrap();
    let mut inner = request_holding(&store.0, id, &SessionData::default());
    inner.consume = None;
    inner.modified = true;

    let outcome = finalize(&store, inner, Some(id)).await;

    assert!(
        !outcome.session_changed,
        "no cookie for a write that failed"
    );
}

/// A fresh guest whose save failed has no row, so no cookie names it.
#[tokio::test]
async fn a_failed_save_issues_no_cookie() {
    let store = FailingWrites(MemorySessionStore::new());
    let id = SessionId::new(&MockRng::new(15));
    let mut inner = request_holding(&store.0, id, &SessionData::default());
    inner.consume = None;
    inner.modified = true;

    let outcome = finalize(&store, inner, None).await;

    assert!(
        !outcome.session_changed,
        "no cookie for a row that was not written"
    );
}

/// A rotation whose old row was ended meanwhile writes nothing under the new
/// id, so the response carries no cookie for it.
#[tokio::test]
async fn a_rotation_of_an_ended_session_issues_no_cookie() {
    let store = MemorySessionStore::new();
    let (old, new) = (
        SessionId::new(&MockRng::new(16)),
        SessionId::new(&MockRng::new(17)),
    );
    let mut inner = request_holding(&store, new, &SessionData::default());
    inner.consume = None;
    inner.regenerate = true;
    inner.pre_cycle = Some(SessionKey::of(&old));

    let outcome = finalize(&store, inner, Some(old)).await;

    assert_eq!(*outcome.session.key(), SessionKey::of(&new));
    assert!(store.load(&SessionKey::of(&new)).await.unwrap().is_none());
    assert!(
        !outcome.session_changed,
        "no cookie for a row that was not written"
    );
}

/// A store that lets one concurrent write land between the layer's read of
/// the old row and the rotation, the window a merge before the rotation
/// cannot close.
#[derive(Clone)]
struct WritesBeforeCycle {
    inner: MemorySessionStore,
    then_write: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl WritesBeforeCycle {
    async fn interpose(&self, key: &SessionKey) {
        let next = {
            let mut pending = self.then_write.lock().unwrap();
            (!pending.is_empty()).then(|| pending.remove(0))
        };
        if let Some(custom) = next {
            concurrent_write(&self.inner, key, custom).await;
        }
    }
}

impl SessionStore for WritesBeforeCycle {
    type Error = std::convert::Infallible;
    async fn load(&self, key: &SessionKey) -> Result<Option<SessionData>, Self::Error> {
        self.inner.load(key).await
    }
    async fn find_sessions_for_user(
        &self,
        user: &crate::authn::ids::UserId,
        limit: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Self::Error> {
        self.inner.find_sessions_for_user(user, limit).await
    }
    async fn save(
        &self,
        key: &SessionKey,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.inner.save(key, d, ttl).await
    }
    async fn delete(&self, key: &SessionKey) -> Result<(), Self::Error> {
        self.inner.delete(key).await
    }
    async fn update(
        &self,
        key: &SessionKey,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        self.inner.update(key, d, ttl).await
    }
    async fn update_if_revision(
        &self,
        key: &SessionKey,
        expected: u64,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        self.inner.update_if_revision(key, expected, d, ttl).await
    }
    async fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        d: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        self.interpose(old).await;
        self.inner.cycle(old, new, d, ttl, require_old).await
    }
    async fn cycle_if_revision(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        d: &SessionData,
        ttl: Duration,
        require_old: bool,
        expected_revision: u64,
    ) -> Result<CycleOutcome, Self::Error> {
        self.interpose(old).await;
        self.inner
            .cycle_if_revision(old, new, d, ttl, require_old, expected_revision)
            .await
    }
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        self.inner.prune_expired().await
    }
}

/// Another request takes the one-shot ceremony value after this rotation has
/// read the old row and before it rotates. The rotated row must not bring the
/// value back; the rotation is retried on what the other request wrote.
#[tokio::test]
async fn a_write_between_the_read_and_the_rotation_is_not_lost() {
    let store = WritesBeforeCycle {
        inner: MemorySessionStore::new(),
        then_write: Arc::new(Mutex::new(vec![serde_json::json!({"cart": 0})])),
    };
    let id = SessionId::new(&MockRng::new(41));
    let loaded = SessionData {
        custom: serde_json::json!({"ceremony": "state", "cart": 0}),
        ..SessionData::default()
    };
    store
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut b = request_holding(&store.inner, id, &loaded);
    b.data.custom["cart"] = serde_json::json!(1);
    b.modified = true;
    b.rotate_id();
    let new_key = *b.session.key();

    finalize(&store, b, Some(id)).await;

    let stored = store.load(&new_key).await.unwrap().unwrap();
    assert!(
        stored.custom.get("ceremony").is_none(),
        "a value taken by a concurrent request stays taken, got {}",
        stored.custom
    );
    assert_eq!(stored.custom["cart"], serde_json::json!(1));
}

/// A rotation of a session whose old row keeps being written to gives up and
/// fails closed rather than carry over a copy that lost a write.
#[tokio::test]
async fn a_rotation_that_keeps_conflicting_fails_closed() {
    let store = WritesBeforeCycle {
        inner: MemorySessionStore::new(),
        then_write: Arc::new(Mutex::new(
            (0..8).map(|n| serde_json::json!({"cart": n})).collect(),
        )),
    };
    let id = SessionId::new(&MockRng::new(42));
    let loaded = SessionData {
        custom: serde_json::json!({"cart": 0}),
        ..authenticated()
    };
    store
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut b = request_holding(&store.inner, id, &loaded);
    b.modified = true;
    b.rotate_id();
    let new_key = *b.session.key();

    finalize(&store, b, Some(id)).await;

    assert!(store.load(&new_key).await.unwrap().is_none());
    assert!(
        store.load(&SessionKey::of(&id)).await.unwrap().is_none(),
        "the old id is retired"
    );
}
