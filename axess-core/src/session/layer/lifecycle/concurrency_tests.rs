//! A stored session written by two requests at once, a rotation that races a
//! revocation, and the rule that a cookie follows the stored state: no
//! `Set-Cookie` for a row that was not written or a session the registry
//! refused.

use super::registry::move_registry_entry;
use super::*;
use crate::authn::ids::testing as ids;
use crate::session::data::SessionData;
use crate::session::layer::UnknownLiveness;
use crate::session::layer::handle::{ConsumeTarget, SessionHandle, SessionInner};
use crate::session::store::{
    ConditionalUpdate, CycleOutcome, MemorySessionRegistry, MemorySessionStore, RevocationError,
    SessionRegistryAdapter, SessionStore,
};
use crate::testing::mock_random::MockRng;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::RwLock;

const TTL: Duration = Duration::from_secs(600);

fn authenticated() -> SessionData {
    let mut data = SessionData::default();
    data.auth_state
        .set_authenticated(ids::user("u"), ids::tenant("t"), chrono::Utc::now());
    data
}

/// The in-memory state of a request that loaded `loaded` from `store`.
fn request_holding(
    store: &MemorySessionStore,
    id: SessionId,
    loaded: &SessionData,
) -> SessionInner {
    SessionInner {
        id,
        data: loaded.clone(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        pending_fingerprint: None,
        max_custom_bytes: 0,
        rng: Arc::new(MockRng::new(1)),
        consume: Some(ConsumeTarget {
            store: Arc::new(store.clone()),
            ttl: TTL,
            loaded: Some(loaded.clone()),
        }),
    }
}

async fn finalize<S>(store: &S, inner: SessionInner, existing: Option<SessionId>) -> FinalizeOutcome
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let cfg = SessionConfig::builder().ttl(TTL).build();
    finalize_session(
        store,
        &cfg,
        None,
        &axess_clock::SystemClock,
        &SessionHandle(Arc::new(RwLock::new(inner))),
        existing,
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
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut b = request_holding(&store, id, &loaded);
    b.data.custom["cart"] = serde_json::json!(1);
    b.modified = true;

    let mut by_a = loaded.clone();
    by_a.custom.as_object_mut().unwrap().remove("ceremony");
    by_a.revision = 1;
    assert_eq!(
        store.update_if_revision(&id, 0, &by_a, TTL).await.unwrap(),
        ConditionalUpdate::Written
    );

    let outcome = finalize(&store, b, Some(id)).await;

    let stored = store.load(&id).await.unwrap().unwrap();
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
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut b = request_holding(&store, id, &loaded);
    b.data.custom["cart"] = serde_json::json!(1);
    b.modified = true;
    b.rotate_id();
    let new_id = b.id;

    let mut by_a = loaded.clone();
    by_a.custom.as_object_mut().unwrap().remove("ceremony");
    by_a.revision = 1;
    assert_eq!(
        store.update_if_revision(&id, 0, &by_a, TTL).await.unwrap(),
        ConditionalUpdate::Written
    );

    finalize(&store, b, Some(id)).await;

    let stored = store.load(&new_id).await.unwrap().unwrap();
    assert!(
        stored.custom.get("ceremony").is_none(),
        "a value taken by a concurrent request stays taken, got {}",
        stored.custom
    );
    assert_eq!(stored.custom["cart"], serde_json::json!(1));
}

/// Write `custom` over the row at `id` as a concurrent request would: a
/// compare-and-swap from the revision stored now.
async fn concurrent_write(store: &MemorySessionStore, id: &SessionId, custom: serde_json::Value) {
    let mut row = store.load(id).await.unwrap().unwrap();
    let expected = row.revision;
    row.custom = custom;
    row.revision = expected + 1;
    assert_eq!(
        store
            .update_if_revision(id, expected, &row, TTL)
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
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut login = request_holding(&store, id, &loaded);
    login.data = authenticated();
    login.data.custom = serde_json::json!({"flow": "s"});
    login.modified = true;
    login.rotate_id();
    let new_id = login.id;
    concurrent_write(
        &store,
        &id,
        serde_json::json!({"flow": "s", "old": 1, "planted": "x"}),
    )
    .await;

    finalize(&store, login, Some(id)).await;

    let stored = store.load(&new_id).await.unwrap().unwrap();
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
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut a = request_holding(&store, id, &loaded);
    concurrent_write(
        &store,
        &id,
        serde_json::json!({"ceremony": "new", "token": "t"}),
    )
    .await;
    assert_eq!(
        a.consume_custom("token").await,
        Some(serde_json::json!("t"))
    );
    assert_eq!(a.data.custom, serde_json::json!({"ceremony": "new"}));
    concurrent_write(&store, &id, serde_json::json!({})).await;

    finalize(&store, a, Some(id)).await;

    let stored = store.load(&id).await.unwrap().unwrap();
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
    ) -> Result<Vec<(SessionId, SessionData)>, Self::Error> {
        Ok(Vec::new())
    }
    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        let row = self.inner.load(id).await?;
        let pending = self.then_write.lock().unwrap().take();
        if let Some(custom) = pending {
            concurrent_write(&self.inner, id, custom).await;
        }
        Ok(row)
    }
    async fn save(
        &self,
        id: &SessionId,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.inner.save(id, d, ttl).await
    }
    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.delete(id).await
    }
    async fn update(
        &self,
        id: &SessionId,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        self.inner.update(id, d, ttl).await
    }
    async fn update_if_revision(
        &self,
        id: &SessionId,
        expected: u64,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        self.inner.update_if_revision(id, expected, d, ttl).await
    }
    async fn cycle(
        &self,
        old: &SessionId,
        new: &SessionId,
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
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut a = request_holding(&store.inner, id, &loaded);
    a.data.custom["cart"] = serde_json::json!(1);
    a.modified = true;
    concurrent_write(&store.inner, &id, serde_json::json!({"ceremony": "new"})).await;
    *store.then_write.lock().unwrap() = Some(serde_json::json!({}));

    let outcome = finalize(&store, a, Some(id)).await;

    let stored = store.load(&id).await.unwrap().unwrap();
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
    ) -> Result<Vec<(SessionId, SessionData)>, Self::Error> {
        Ok(Vec::new())
    }
    async fn load(&self, _: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        Err(std::io::Error::other("store unavailable"))
    }
    async fn save(
        &self,
        id: &SessionId,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.0.save(id, d, ttl).await.unwrap();
        Ok(())
    }
    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.0.delete(id).await.unwrap();
        Ok(())
    }
    async fn update(
        &self,
        id: &SessionId,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        Ok(self.0.update(id, d, ttl).await.unwrap())
    }
    async fn update_if_revision(
        &self,
        id: &SessionId,
        expected: u64,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        Ok(self
            .0
            .update_if_revision(id, expected, d, ttl)
            .await
            .unwrap())
    }
    async fn cycle(
        &self,
        old: &SessionId,
        new: &SessionId,
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
    store.0.save(&id, &loaded, TTL).await.unwrap();
    let mut b = request_holding(&store.0, id, &loaded);
    b.data
        .auth_state
        .set_authenticated(ids::user("u"), ids::tenant("t"), chrono::Utc::now());
    b.modified = true;
    b.rotate_id();
    let new_id = b.id;

    let outcome = finalize(&store, b, Some(id)).await;

    assert!(outcome.rotation.is_none(), "no rotation is reported");
    let carried = store.0.load(&new_id).await.unwrap();
    assert!(
        carried.is_none_or(|row| !row.auth_state.is_authenticated()),
        "the login must not reach the new id"
    );
    assert!(
        store.0.load(&id).await.unwrap().is_none(),
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
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut b = request_holding(&store, id, &loaded);
    b.consume = None;
    b.data.custom["cart"] = serde_json::json!(1);
    b.modified = true;
    let mut by_a = loaded.clone();
    by_a.custom = serde_json::json!({});
    by_a.revision = 1;
    assert_eq!(
        store.update_if_revision(&id, 0, &by_a, TTL).await.unwrap(),
        ConditionalUpdate::Written
    );

    let outcome = finalize(&store, b, Some(id)).await;

    let stored = store.load(&id).await.unwrap().unwrap();
    assert_eq!(stored.custom, serde_json::json!({}));
    assert!(
        !outcome.session_changed,
        "nothing was written, so no cookie"
    );
}

// ── a rotation that races a revocation ─────────────────────────────────────

/// A registry whose answer for one id flips from Valid to Gone after the
/// first liveness check: a revocation landed right after the check.
struct RevokesAfterCheck {
    revoked: SessionId,
    answered: AtomicBool,
    first_answer: SessionLiveness,
    held: Mutex<Vec<SessionId>>,
}

impl RevokesAfterCheck {
    fn new(revoked: SessionId) -> Self {
        Self {
            revoked,
            answered: AtomicBool::new(false),
            first_answer: SessionLiveness::Valid,
            held: Mutex::new(Vec::new()),
        }
    }

    /// The registry's first answer for the revoked id is an error, not Valid.
    fn unanswering_first(revoked: SessionId) -> Self {
        Self {
            first_answer: SessionLiveness::Unknown,
            ..Self::new(revoked)
        }
    }

    fn holds(&self, id: &SessionId) -> bool {
        self.held.lock().unwrap().contains(id)
    }
}

impl crate::session::store::SessionRevoker for RevokesAfterCheck {
    fn invalidate_user<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        self.held.lock().unwrap().clear();
        Box::pin(async { Ok(()) })
    }
    fn invalidate_session<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        self.held.lock().unwrap().retain(|h| h != id);
        Box::pin(async { Ok(()) })
    }
}

impl SessionRegistryHandle for RevokesAfterCheck {
    fn is_valid<'a>(
        &'a self,
        user: &'a crate::authn::ids::UserId,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move { self.liveness(user, id).await == SessionLiveness::Valid })
    }
    fn liveness<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = SessionLiveness> + Send + 'a>> {
        let answer = if *id == self.revoked {
            if self.answered.swap(true, Ordering::SeqCst) {
                SessionLiveness::Gone
            } else {
                self.first_answer
            }
        } else if self.holds(id) {
            SessionLiveness::Valid
        } else {
            SessionLiveness::Gone
        };
        Box::pin(async move { answer })
    }
    fn register<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        self.held.lock().unwrap().push(*id);
        Box::pin(async { true })
    }
    fn held_sessions<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SessionId>, RevocationError>> + Send + 'a>> {
        let held = self.held.lock().unwrap().clone();
        Box::pin(async move { Ok(held) })
    }
}

fn rotation(old: SessionId, new: SessionId) -> Rotation {
    Rotation {
        was_authenticated: false,
        user_id: ids::user("u"),
        old_id: old,
        new_id: new,
    }
}

/// The row has moved to the new id when the registry entry is moved.
async fn moved_row(store: &MemorySessionStore, new: &SessionId) {
    store.save(new, &authenticated(), TTL).await.unwrap();
}

/// A revocation that lands between the liveness check of the old id and the
/// registration of the new one must end the session: the new id is not
/// valid, its row is gone and the response carries no cookie.
#[tokio::test]
async fn a_revocation_during_rotation_ends_the_session_under_its_new_id() {
    let store = MemorySessionStore::new();
    let (old, new) = (
        SessionId::new(&MockRng::new(4)),
        SessionId::new(&MockRng::new(5)),
    );
    moved_row(&store, &new).await;
    let registry = RevokesAfterCheck::new(old);
    assert_eq!(
        registry.liveness(&ids::user("u"), &old).await,
        SessionLiveness::Valid,
        "the old id is valid when the rotation starts"
    );
    let registry = RevokesAfterCheck::new(old);

    let cookie = move_registry_entry(
        &store,
        &registry,
        &rotation(old, new),
        UnknownLiveness::Reject,
    )
    .await;

    assert!(!cookie, "a revoked session gets no cookie");
    assert!(!registry.holds(&new), "the new id must not stay valid");
    assert!(
        store.load(&new).await.unwrap().is_none(),
        "the row under the new id is deleted"
    );
}

/// The registry could not answer for the old id, then registered the new one;
/// a revocation that landed meanwhile must still end the session. The old id
/// is read again after the registration whichever way the first read went.
#[tokio::test]
async fn a_revocation_after_an_unanswered_check_ends_the_session_under_its_new_id() {
    let store = MemorySessionStore::new();
    let (old, new) = (
        SessionId::new(&MockRng::new(4)),
        SessionId::new(&MockRng::new(5)),
    );
    moved_row(&store, &new).await;
    let registry = RevokesAfterCheck::unanswering_first(old);

    let cookie = move_registry_entry(
        &store,
        &registry,
        &rotation(old, new),
        UnknownLiveness::Accept,
    )
    .await;

    assert!(!cookie, "a revoked session gets no cookie");
    assert!(!registry.holds(&new), "the new id must not stay valid");
    assert!(
        store.load(&new).await.unwrap().is_none(),
        "the row under the new id is deleted"
    );
}

/// The registry holds the session under neither id: it was revoked while the
/// request ran and nothing registered the new id. No cookie, and the row
/// under the new id goes.
#[tokio::test]
async fn a_rotation_the_registry_holds_under_neither_id_gets_no_cookie() {
    let store = MemorySessionStore::new();
    let (old, new) = (
        SessionId::new(&MockRng::new(6)),
        SessionId::new(&MockRng::new(7)),
    );
    moved_row(&store, &new).await;
    let registry = SessionRegistryAdapter(MemorySessionRegistry::new());

    let cookie = move_registry_entry(
        &store,
        &registry,
        &rotation(old, new),
        UnknownLiveness::Reject,
    )
    .await;

    assert!(!cookie);
    assert!(store.load(&new).await.unwrap().is_none());
}

/// A login rotates a guest id that was never registered, and the handler
/// registers the new id itself: the cookie is issued and the row stays.
#[tokio::test]
async fn a_rotation_whose_new_id_the_handler_registered_keeps_its_cookie() {
    let store = MemorySessionStore::new();
    let (old, new) = (
        SessionId::new(&MockRng::new(8)),
        SessionId::new(&MockRng::new(9)),
    );
    moved_row(&store, &new).await;
    let registry = SessionRegistryAdapter(MemorySessionRegistry::new());
    assert!(registry.register(&ids::user("u"), &new).await);

    let cookie = move_registry_entry(
        &store,
        &registry,
        &rotation(old, new),
        UnknownLiveness::Reject,
    )
    .await;

    assert!(cookie);
    assert!(store.load(&new).await.unwrap().is_some());
    assert!(registry.is_valid(&ids::user("u"), &new).await);
}

/// An authenticated session revoked at the moment the handler registered the
/// new id itself: the old id is gone, and the new one must not outlive the
/// revocation.
#[tokio::test]
async fn a_revoked_authenticated_session_does_not_survive_the_handler_registering_its_new_id() {
    let store = MemorySessionStore::new();
    let (old, new) = (
        SessionId::new(&MockRng::new(12)),
        SessionId::new(&MockRng::new(13)),
    );
    moved_row(&store, &new).await;
    let registry = SessionRegistryAdapter(MemorySessionRegistry::new());
    assert!(registry.register(&ids::user("u"), &new).await);
    let mut rotated = rotation(old, new);
    rotated.was_authenticated = true;

    let cookie = move_registry_entry(&store, &registry, &rotated, UnknownLiveness::Reject).await;

    assert!(!cookie, "the revoked session got a cookie");
    assert!(store.load(&new).await.unwrap().is_none());
    assert!(!registry.is_valid(&ids::user("u"), &new).await);
}

/// A rotation the registry tracked from the old id moves the entry.
#[tokio::test]
async fn a_tracked_rotation_moves_the_registry_entry() {
    let store = MemorySessionStore::new();
    let (old, new) = (
        SessionId::new(&MockRng::new(10)),
        SessionId::new(&MockRng::new(11)),
    );
    moved_row(&store, &new).await;
    let registry = SessionRegistryAdapter(MemorySessionRegistry::new());
    assert!(registry.register(&ids::user("u"), &old).await);

    let cookie = move_registry_entry(
        &store,
        &registry,
        &rotation(old, new),
        UnknownLiveness::Reject,
    )
    .await;

    assert!(cookie);
    assert!(registry.is_valid(&ids::user("u"), &new).await);
    assert!(!registry.is_valid(&ids::user("u"), &old).await);
}

/// A registry that cannot answer and cannot register: the fail-closed policy
/// ends the session, the accepting one lets it go on untracked.
#[tokio::test]
async fn an_unanswering_registry_at_rotation_follows_the_unknown_liveness_policy() {
    for (policy, cookie_expected) in [
        (UnknownLiveness::Reject, false),
        (UnknownLiveness::Accept, true),
    ] {
        let store = MemorySessionStore::new();
        let (old, new) = (
            SessionId::new(&MockRng::new(12)),
            SessionId::new(&MockRng::new(13)),
        );
        moved_row(&store, &new).await;
        let registry = super::policy_tests::SilentRegistry;

        let cookie = move_registry_entry(&store, &registry, &rotation(old, new), policy).await;

        assert_eq!(cookie, cookie_expected, "{policy:?}");
        assert_eq!(
            store.load(&new).await.unwrap().is_some(),
            cookie_expected,
            "{policy:?}: the row goes with the cookie"
        );
    }
}

/// A registry that holds the old id but fails to register the new one.
struct RegisterFails {
    old: SessionId,
}

impl crate::session::store::SessionRevoker for RegisterFails {
    fn invalidate_user<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
    fn invalidate_session<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        _: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

impl SessionRegistryHandle for RegisterFails {
    fn is_valid<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        let held = *id == self.old;
        Box::pin(async move { held })
    }
    fn liveness<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = SessionLiveness> + Send + 'a>> {
        let answer = if *id == self.old {
            SessionLiveness::Valid
        } else {
            SessionLiveness::Gone
        };
        Box::pin(async move { answer })
    }
    fn register<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        _: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async { false })
    }
    fn held_sessions<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SessionId>, RevocationError>> + Send + 'a>> {
        let old = self.old;
        Box::pin(async move { Ok(vec![old]) })
    }
}

/// A failed registration of the rotated id is a registry that could not
/// answer, whether or not its liveness check of the old id answered: the
/// unknown-liveness policy decides in both cases.
#[tokio::test]
async fn a_failed_registration_after_a_valid_answer_follows_the_unknown_liveness_policy() {
    for (policy, cookie_expected) in [
        (UnknownLiveness::Reject, false),
        (UnknownLiveness::Accept, true),
    ] {
        let store = MemorySessionStore::new();
        let (old, new) = (
            SessionId::new(&MockRng::new(22)),
            SessionId::new(&MockRng::new(23)),
        );
        moved_row(&store, &new).await;
        let registry = RegisterFails { old };
        assert_eq!(
            registry.liveness(&ids::user("u"), &old).await,
            SessionLiveness::Valid,
            "the registry answers for the old id"
        );

        let cookie = move_registry_entry(&store, &registry, &rotation(old, new), policy).await;

        assert_eq!(cookie, cookie_expected, "{policy:?}");
        assert_eq!(
            store.load(&new).await.unwrap().is_some(),
            cookie_expected,
            "{policy:?}: the row goes with the cookie"
        );
    }
}

// ── a cookie follows the stored state ──────────────────────────────────────

/// A store whose writes fail.
#[derive(Clone)]
struct FailingWrites(MemorySessionStore);

impl SessionStore for FailingWrites {
    type Error = std::io::Error;
    async fn find_sessions_for_user(
        &self,
        _: &crate::authn::ids::UserId,
        _: usize,
    ) -> Result<Vec<(SessionId, SessionData)>, Self::Error> {
        Ok(Vec::new())
    }
    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        Ok(self.0.load(id).await.unwrap())
    }
    async fn save(&self, _: &SessionId, _: &SessionData, _: Duration) -> Result<(), Self::Error> {
        Err(std::io::Error::other("store unavailable"))
    }
    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.0.delete(id).await.unwrap();
        Ok(())
    }
    async fn update(
        &self,
        _: &SessionId,
        _: &SessionData,
        _: Duration,
    ) -> Result<bool, Self::Error> {
        Err(std::io::Error::other("store unavailable"))
    }
    async fn update_if_revision(
        &self,
        _: &SessionId,
        _: u64,
        _: &SessionData,
        _: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        Err(std::io::Error::other("store unavailable"))
    }
    async fn cycle(
        &self,
        old: &SessionId,
        new: &SessionId,
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
        .save(&id, &SessionData::default(), TTL)
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
    inner.pre_cycle_id = Some(old);

    let outcome = finalize(&store, inner, Some(old)).await;

    assert_eq!(outcome.final_id, new);
    assert!(store.load(&new).await.unwrap().is_none());
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
    async fn interpose(&self, id: &SessionId) {
        let next = {
            let mut pending = self.then_write.lock().unwrap();
            (!pending.is_empty()).then(|| pending.remove(0))
        };
        if let Some(custom) = next {
            concurrent_write(&self.inner, id, custom).await;
        }
    }
}

impl SessionStore for WritesBeforeCycle {
    type Error = std::convert::Infallible;
    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        self.inner.load(id).await
    }
    async fn find_sessions_for_user(
        &self,
        user: &crate::authn::ids::UserId,
        limit: usize,
    ) -> Result<Vec<(SessionId, SessionData)>, Self::Error> {
        self.inner.find_sessions_for_user(user, limit).await
    }
    async fn save(
        &self,
        id: &SessionId,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.inner.save(id, d, ttl).await
    }
    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.delete(id).await
    }
    async fn update(
        &self,
        id: &SessionId,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        self.inner.update(id, d, ttl).await
    }
    async fn update_if_revision(
        &self,
        id: &SessionId,
        expected: u64,
        d: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        self.inner.update_if_revision(id, expected, d, ttl).await
    }
    async fn cycle(
        &self,
        old: &SessionId,
        new: &SessionId,
        d: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        self.interpose(old).await;
        self.inner.cycle(old, new, d, ttl, require_old).await
    }
    async fn cycle_if_revision(
        &self,
        old: &SessionId,
        new: &SessionId,
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
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut b = request_holding(&store.inner, id, &loaded);
    b.data.custom["cart"] = serde_json::json!(1);
    b.modified = true;
    b.rotate_id();
    let new_id = b.id;

    finalize(&store, b, Some(id)).await;

    let stored = store.load(&new_id).await.unwrap().unwrap();
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
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut b = request_holding(&store.inner, id, &loaded);
    b.modified = true;
    b.rotate_id();
    let new_id = b.id;

    finalize(&store, b, Some(id)).await;

    assert!(store.load(&new_id).await.unwrap().is_none());
    assert!(
        store.load(&id).await.unwrap().is_none(),
        "the old id is retired"
    );
}
