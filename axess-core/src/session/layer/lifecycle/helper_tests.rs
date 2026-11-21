//! `helper_tests`: the unit tests of `lifecycle.rs`, kept beside it per the
//! 200-line inline-test rule in AGENTS.md.

use super::*;
use crate::session::data::SessionData;
use crate::session::id::{SessionId, SessionKey};
use crate::session::layer::handle::{SessionHandle, SessionInner};
use crate::session::store::{CycleOutcome, MemorySessionStore};
use crate::testing::mock_random::MockRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;

fn fresh_inner(id: SessionId) -> SessionInner {
    SessionInner {
        session: CookieSession::of_id(id),
        ..SessionInner::detached(std::sync::Arc::new(axess_rng::SystemRng))
    }
}

fn handle_from(inner: SessionInner) -> SessionHandle {
    SessionHandle(Arc::new(RwLock::new(inner)))
}

/// Test store that counts cycle vs save calls so we can discriminate
/// between the two finalize-session branches.
#[derive(Clone)]
struct CallCountingStore {
    inner: MemorySessionStore,
    cycle_calls: Arc<AtomicUsize>,
    save_calls: Arc<AtomicUsize>,
    update_calls: Arc<AtomicUsize>,
}

impl CallCountingStore {
    fn new() -> Self {
        Self {
            inner: MemorySessionStore::new(),
            cycle_calls: Arc::new(AtomicUsize::new(0)),
            save_calls: Arc::new(AtomicUsize::new(0)),
            update_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl crate::session::store::SessionStore for CallCountingStore {
    type Error = <MemorySessionStore as crate::session::store::SessionStore>::Error;
    async fn find_sessions_for_user(
        &self,
        _: &crate::authn::ids::UserId,
        _: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Self::Error> {
        Ok(Vec::new())
    }
    async fn load(&self, key: &SessionKey) -> Result<Option<SessionData>, Self::Error> {
        self.inner.load(key).await
    }
    async fn save(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.save_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.save(key, data, ttl).await
    }
    async fn delete(&self, key: &SessionKey) -> Result<(), Self::Error> {
        self.inner.delete(key).await
    }
    async fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        self.cycle_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.cycle(old, new, data, ttl, require_old).await
    }
    async fn update(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        self.update_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.update(key, data, ttl).await
    }
    async fn update_if_revision(
        &self,
        key: &SessionKey,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<crate::session::store::ConditionalUpdate, Self::Error> {
        self.update_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .update_if_revision(key, expected_revision, data, ttl)
            .await
    }
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        self.inner.prune_expired().await
    }
}

// ── build_set_cookie ────────────────────────────────────────────────

/// `build_set_cookie` must return `Some(HeaderValue)` for normal
/// inputs: kills `824:5 -> None`. The standard cookie-name +
/// base64-url id + `.` + base64-url MAC contents are all ASCII and
/// `HeaderValue::from_str` accepts them.
#[test]
fn build_set_cookie_returns_some_for_default_config() {
    let keys = SigningKeyRing::from_master(&[0x55; 32]);
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(11));
    let hv = build_set_cookie(&keys, &cfg, &CookieSession::of_id(id));
    assert!(
        hv.is_some(),
        "build_set_cookie must produce a Some(HeaderValue) for default config"
    );
    let s = hv.unwrap().to_str().unwrap().to_string();
    assert!(
        s.contains(cfg.cookie_name.as_ref()),
        "Set-Cookie header must carry the configured cookie name (got {s})"
    );
}

// ── finalize_session: max_custom_bytes cap ─────────────────────────

/// `max_custom_bytes == 0` disables the cap. Even with a huge
/// custom payload AND `modified=true`, the helper must NOT clear
/// `data.custom`. Kills the `> 0 → ==/</>= 0` family
/// and pins the "unlimited" semantic.
#[tokio::test]
async fn finalize_session_cap_disabled_when_max_custom_bytes_is_zero() {
    let store = CallCountingStore::new();
    let cfg = SessionConfig {
        max_custom_bytes: 0,
        ..Default::default()
    };
    let id = SessionId::new(&MockRng::new(1));
    store
        .inner
        .save(&SessionKey::of(&id), &SessionData::default(), cfg.ttl)
        .await
        .unwrap();
    let big = serde_json::json!({"k": "v".repeat(100_000)});
    let mut inner = fresh_inner(id);
    inner.data.custom = big.clone();
    inner.modified = true;
    inner.max_custom_bytes = 0;
    let handle = handle_from(inner);

    let _ = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        true,
        &MockRng::new(1),
    )
    .await;
    let guard = handle.0.read().await;
    assert_eq!(
        guard.data.custom, big,
        "custom must not be cleared when max_custom_bytes == 0"
    );
}

/// `&&`: the cap check requires BOTH a configured
/// max AND `guard.modified`. With `modified=false`, the helper
/// must NOT clear custom even with a huge payload. Kills
/// `&& → ||` there.
#[tokio::test]
async fn finalize_session_cap_skipped_when_session_not_modified() {
    let store = CallCountingStore::new();
    let cfg = SessionConfig {
        max_custom_bytes: 100,
        ..Default::default()
    };
    let id = SessionId::new(&MockRng::new(2));
    let big = serde_json::json!({"k": "v".repeat(5_000)});
    let mut inner = fresh_inner(id);
    inner.data.custom = big.clone();
    // Recently refreshed, so the idle-expiry refresh does not write it either.
    inner.data.touched_at = Some(axess_clock::testing::MockClock::reference_time());
    inner.modified = false;
    inner.regenerate = false;
    let handle = handle_from(inner);

    let _ = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        true,
        &MockRng::new(1),
    )
    .await;
    let guard = handle.0.read().await;
    assert_eq!(
        guard.data.custom, big,
        "custom must not be cleared when guard.modified == false \
             (kills `&& → ||` on the cap-check guard)"
    );
}

/// Strict-greater boundary: custom size EXACTLY equal
/// to the cap must NOT be cleared; one byte over the cap MUST be
/// cleared. Kills `> → ==`, `> → >=`, `> → <`.
#[tokio::test]
async fn finalize_session_cap_uses_strict_greater_at_exact_boundary() {
    // Construct a payload whose JSON-serialised form is exactly N bytes.
    // Strategy: a JSON string "x..." of `target - 2` ASCII bytes
    // (the two enclosing quotes contribute the remaining 2 bytes).
    let target = 64usize;
    let payload = serde_json::Value::String("x".repeat(target - 2));
    assert_eq!(
        serde_json::to_vec(&payload).unwrap().len(),
        target,
        "fixture: target-byte JSON serialization"
    );

    let store = CallCountingStore::new();
    let cfg = SessionConfig {
        max_custom_bytes: target,
        ..Default::default()
    };

    // Case A: custom_size == max → keep.
    {
        let id = SessionId::new(&MockRng::new(3));
        store
            .inner
            .save(&SessionKey::of(&id), &SessionData::default(), cfg.ttl)
            .await
            .unwrap();
        let mut inner = fresh_inner(id);
        inner.data.custom = payload.clone();
        inner.modified = true;
        let handle = handle_from(inner);
        let _ = finalize_session(
            &store,
            &cfg,
            Reporting::unrecorded(),
            &axess_clock::testing::MockClock::at_reference(),
            &handle,
            true,
            &MockRng::new(1),
        )
        .await;
        let guard = handle.0.read().await;
        assert_eq!(
            guard.data.custom, payload,
            "custom EXACTLY at the cap must be kept (kills `> → >=` and `> → ==` on line 754)"
        );
    }

    // Case B: custom_size > max → clear.
    let over = serde_json::Value::String("x".repeat(target));
    {
        let id = SessionId::new(&MockRng::new(4));
        store
            .inner
            .save(&SessionKey::of(&id), &SessionData::default(), cfg.ttl)
            .await
            .unwrap();
        let mut inner = fresh_inner(id);
        inner.data.custom = over.clone();
        inner.modified = true;
        let handle = handle_from(inner);
        let _ = finalize_session(
            &store,
            &cfg,
            Reporting::unrecorded(),
            &axess_clock::testing::MockClock::at_reference(),
            &handle,
            true,
            &MockRng::new(1),
        )
        .await;
        let guard = handle.0.read().await;
        assert_eq!(
            guard.data.custom,
            serde_json::Value::default(),
            "custom OVER the cap must be cleared (kills `> → <` and `-> false` on line 754)"
        );
    }
}

// ── finalize_session: session_changed boolean ──────────────────────

/// Line 764: `session_changed = guard.modified || guard.regenerate
/// || existing_id.is_none()`. The two `||`s, when mutated to `&&`,
/// would collapse all three flags to AND, breaking save-vs-cycle
/// for any single-flag-only request.
///
/// Discriminating fixture: `modified=true, regenerate=false,
/// existing_id=Some(id)`. Original: session_changed=true, hits save
/// path. Mutant `||→&&` (either): session_changed becomes false, no
/// store call.
#[tokio::test]
async fn finalize_session_session_changed_or_over_modified_alone() {
    let store = CallCountingStore::new();
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(5));
    store
        .inner
        .save(&SessionKey::of(&id), &SessionData::default(), cfg.ttl)
        .await
        .unwrap();
    let mut inner = fresh_inner(id);
    inner.modified = true;
    let handle = handle_from(inner);

    let outcome = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        true,
        &MockRng::new(1),
    )
    .await;
    assert!(
        outcome.session_changed,
        "modified=true alone must mark session_changed (kills `||→&&` on line 764)"
    );
    assert_eq!(
        store.update_calls.load(Ordering::SeqCst),
        1,
        "modified+existing must take the update branch"
    );
    assert_eq!(
        store.save_calls.load(Ordering::SeqCst),
        0,
        "a stored session is updated, never upserted"
    );
    assert_eq!(
        store.cycle_calls.load(Ordering::SeqCst),
        0,
        "modified-only must NOT cycle"
    );
}

/// A store whose `cycle` fails and whose `delete` is counted: the regenerate
/// path must fail closed in the STORE, not only in the response.
#[derive(Clone)]
struct FailingCycleStore {
    inner: MemorySessionStore,
    delete_calls: Arc<AtomicUsize>,
}

impl crate::session::store::SessionStore for FailingCycleStore {
    type Error = std::io::Error;
    async fn find_sessions_for_user(
        &self,
        _: &crate::authn::ids::UserId,
        _: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Self::Error> {
        Ok(Vec::new())
    }
    async fn load(&self, key: &SessionKey) -> Result<Option<SessionData>, Self::Error> {
        Ok(self.inner.load(key).await.unwrap())
    }
    async fn save(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.inner.save(key, data, ttl).await.unwrap();
        Ok(())
    }
    async fn delete(&self, key: &SessionKey) -> Result<(), Self::Error> {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.delete(key).await.unwrap();
        Ok(())
    }
    async fn cycle(
        &self,
        _: &SessionKey,
        _: &SessionKey,
        _: &SessionData,
        _: Duration,
        _: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        Err(std::io::Error::other("store unavailable"))
    }
    async fn update(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        Ok(self.inner.update(key, data, ttl).await.unwrap())
    }
    async fn update_if_revision(
        &self,
        key: &SessionKey,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<crate::session::store::ConditionalUpdate, Self::Error> {
        Ok(self
            .inner
            .update_if_revision(key, expected_revision, data, ttl)
            .await
            .unwrap())
    }
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        Ok(0)
    }
}

/// Logout (`regenerate`) while the store's cycle fails: the old id is deleted
/// from the store and is NOT the id the response carries, so the old cookie
/// does not authenticate and is not re-issued with its Authenticated row
/// still in the store. The new id is deleted as well: a
/// store that reports an error may have written it all the same.
#[tokio::test]
async fn finalize_session_failed_cycle_deletes_old_id_and_does_not_reissue_it() {
    let store = FailingCycleStore {
        inner: MemorySessionStore::new(),
        delete_calls: Arc::new(AtomicUsize::new(0)),
    };
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(21));
    let mut inner = fresh_inner(id);
    inner.regenerate = true;
    store
        .inner
        .save(&SessionKey::of(&id), &SessionData::default(), cfg.ttl)
        .await
        .expect("seed");
    let handle = handle_from(inner);

    let outcome = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        true,
        &MockRng::new(1),
    )
    .await;
    assert_ne!(
        *outcome.session.key(),
        SessionKey::of(&id),
        "the old id must never be re-issued after a failed cycle"
    );
    assert_eq!(
        store.delete_calls.load(Ordering::SeqCst),
        2,
        "the rows under both ids must be deleted from the store"
    );
    assert!(
        store
            .inner
            .load(outcome.session.key())
            .await
            .unwrap()
            .is_none(),
        "no row backs the id the response carries"
    );
    assert!(
        store
            .inner
            .load(&SessionKey::of(&id))
            .await
            .unwrap()
            .is_none(),
        "the old id's row must be gone so the old cookie is a guest"
    );
}

/// `regenerate=true` alone (no `modified`, `existing_id=Some`) is
/// the binding-mismatch / forced-rotation case: the layer must
/// still treat session_changed=true and take the cycle path.
///
/// Discriminating fixture: `modified=false, regenerate=true,
/// existing_id=Some(id)`. As written:
/// `false || true || false = true` → cycle.
/// With the second `||` written `&&`:
/// `false || (true && false) = false` → no store call. Kills it.
#[tokio::test]
async fn finalize_session_session_changed_or_over_regenerate_alone() {
    let store = CallCountingStore::new();
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(8));
    let mut inner = fresh_inner(id);
    inner.modified = false;
    inner.regenerate = true;
    // Pre-seed the store with `id` so cycle's "delete old" finds a row.
    store
        .inner
        .save(&SessionKey::of(&id), &SessionData::default(), cfg.ttl)
        .await
        .expect("seed");
    let handle = handle_from(inner);

    let outcome = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        true,
        &MockRng::new(1),
    )
    .await;
    assert!(
        outcome.session_changed,
        "regenerate=true alone must mark session_changed (kills 764:62 `||→&&` on second OR)"
    );
    assert_eq!(
        store.cycle_calls.load(Ordering::SeqCst),
        1,
        "regenerate-only must take cycle path"
    );
    assert_eq!(store.save_calls.load(Ordering::SeqCst), 0);
}

/// Metrics-emission gate: `if session_changed &&
/// (guard.regenerate || existing_id.is_none())`. The inner `||`
/// drives the `session_created` emission.
///
/// Fixture: `regenerate=true, existing_id=Some(id)`. As written:
/// `true && (true || false) = true` → emit. With the inner `||` written `&&`:
/// `true && (true && false) = false` → no emit. Discriminate via
/// a `SessionMetrics` recorder that counts `session_created` calls.
#[tokio::test]
async fn finalize_session_emits_session_created_on_regenerate() {
    #[derive(Default)]
    struct CountingMetrics {
        session_created_calls: AtomicUsize,
    }
    impl crate::metrics::SessionMetrics for CountingMetrics {
        fn session_created(&self) {
            self.session_created_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    let recorder = Arc::new(CountingMetrics::default());
    let metrics = crate::metrics::MetricSinks::noop().with_session(recorder.clone());
    let store = CallCountingStore::new();
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(9));
    let mut inner = fresh_inner(id);
    inner.modified = false;
    inner.regenerate = true;
    store
        .inner
        .save(&SessionKey::of(&id), &SessionData::default(), cfg.ttl)
        .await
        .expect("seed");
    let handle = handle_from(inner);

    let _ = finalize_session(
        &store,
        &cfg,
        Reporting {
            metrics: Some(&metrics),
            ..Reporting::unrecorded()
        },
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        true,
        &MockRng::new(1),
    )
    .await;
    assert_eq!(
        recorder.session_created_calls.load(Ordering::SeqCst),
        1,
        "regenerate=true must trigger session_created (kills 766:30 `||→&&`)"
    );
}

/// A fresh guest (`existing_id=None`, no `regenerate`) is *saved* under
/// the id the request already ran under, it is NOT cycled to a second,
/// different id. The id `load_session` minted is already fixation-safe
/// (never the client's cookie id), so keeping it costs nothing in security
/// and is load-bearing for CSRF: a token minted during this request is
/// HMAC-bound to this id, so re-minting a different id for the response
/// cookie here would 403 the client's next state-changing request (the
/// login POST). Only `regenerate` (privilege change / binding-mismatch)
/// cycles to a new id: covered by the regenerate-alone test above.
#[tokio::test]
async fn finalize_session_fresh_guest_saves_under_load_minted_id() {
    let store = CallCountingStore::new();
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(6));
    let mut inner = fresh_inner(id);
    inner.modified = true;
    inner.regenerate = false;
    let handle = handle_from(inner);

    let outcome = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        false,
        &MockRng::new(1),
    )
    .await;
    assert_eq!(
        store.save_calls.load(Ordering::SeqCst),
        1,
        "fresh guest must be persisted under its load-minted id"
    );
    assert_eq!(
        store.cycle_calls.load(Ordering::SeqCst),
        0,
        "fresh guest must NOT mint a second id (would invalidate this request's CSRF token)"
    );
    assert_eq!(
        *outcome.session.key(),
        SessionKey::of(&id),
        "the response cookie must carry the same id the request ran under, \
             so a CSRF token bound to it validates on the next request"
    );
}

// ── load_session: fingerprint binding ──────────────────────────────

/// `load_session`'s `&& !ct_eq(stored, current)`. The `!`
/// must remain: invalidate ONLY when the fingerprints DIFFER.
/// Kills `delete !` (which would invert the check and invalidate
/// every legitimately matching session, i.e., logging out every
/// authenticated user every request).
#[tokio::test]
async fn load_session_keeps_session_when_fingerprint_matches() {
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master(&[0xCC; 32]);
    let cfg = SessionConfig::default();

    let stored_fp = "match-me".to_string();
    let id = SessionId::new(&MockRng::new(7));
    let data = SessionData {
        fingerprint: Some(stored_fp.clone()),
        ..SessionData::default()
    };
    store
        .save(&SessionKey::of(&id), &data, cfg.ttl)
        .await
        .expect("seed store");

    // Build a cookie carrying the seed id, signed under the ring's
    // current key: mirrors what `build_set_cookie` produces in
    // production so `load_session` sees a real-shaped input.
    let cookie_value = keys.sign_cookie(&CookieSession::of_id(id));
    let mut headers = axum::http::HeaderMap::new();
    let header = format!("{}={}", cfg.cookie_name.as_ref(), cookie_value);
    headers.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&header).unwrap(),
    );

    let outcome = load_session(
        &store,
        &keys,
        &cfg,
        &headers,
        Fingerprints {
            current: Some(stored_fp.as_str()),
            previous: None,
        },
        &MockRng::new(1),
        &LoadPolicy::bare(),
    )
    .await;

    assert!(
        !outcome.binding_invalidated,
        "matching fingerprint must NOT invalidate binding (kills `delete !` on line 690)"
    );
    assert!(
        outcome.stored && *outcome.session.key() == SessionKey::of(&id),
        "trusted id must survive a matching-fingerprint load"
    );
    assert_eq!(
        outcome.data.fingerprint,
        Some(stored_fp),
        "session data must NOT be reset to default when fingerprints match"
    );
}

/// A bound session presented WITHOUT binding material is a mismatch, not a
/// skipped check: leaving the material out was the one way a stolen bound
/// session still authenticated.
#[tokio::test]
async fn load_session_invalidates_a_bound_session_presented_without_a_fingerprint() {
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master(&[0xCC; 32]);
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(31));
    let data = SessionData {
        fingerprint: Some("bound-to-a-device".to_string()),
        ..SessionData::default()
    };
    store
        .save(&SessionKey::of(&id), &data, cfg.ttl)
        .await
        .expect("seed store");
    let cookie_value = keys.sign_cookie(&CookieSession::of_id(id));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!(
            "{}={}",
            cfg.cookie_name.as_ref(),
            cookie_value
        ))
        .unwrap(),
    );

    let outcome = load_session(
        &store,
        &keys,
        &cfg,
        &headers,
        Fingerprints::default(),
        &MockRng::new(1),
        &LoadPolicy::bare(),
    )
    .await;
    assert!(
        outcome.binding_invalidated,
        "no binding material against a bound session must invalidate it"
    );
    assert!(
        !outcome.stored && *outcome.session.key() != SessionKey::of(&id),
        "the bound id must not be kept"
    );
}

// ── injected RNG ───────────────────────────────────────────────────

/// A request with no cookie runs under the id the supplied RNG yields first.
#[tokio::test]
async fn load_session_mints_the_fresh_id_from_the_supplied_rng() {
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master(&[0xCC; 32]);
    let cfg = SessionConfig::default();
    let headers = axum::http::HeaderMap::new();

    let outcome = load_session(
        &store,
        &keys,
        &cfg,
        &headers,
        Fingerprints::default(),
        &MockRng::new(77),
        &LoadPolicy::bare(),
    )
    .await;

    assert_eq!(
        *outcome.session.key(),
        SessionKey::of(&SessionId::new(&MockRng::new(77)))
    );
    assert!(!outcome.stored);
}

/// A valid cookie whose row the store does not hold (expired, deleted, or a
/// fixation attempt with a cookie from elsewhere) names nothing: the request
/// runs under a freshly minted session, and what it stores goes under that
/// session's key, never under the cookie's.
#[tokio::test]
async fn a_cookie_without_a_row_runs_under_a_fresh_session_and_stores_nothing_under_its_key() {
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master(&[0xCC; 32]);
    let cfg = SessionConfig::default();
    let cookie = CookieSession::of_id(SessionId::new(&MockRng::new(41)));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!(
            "{}={}",
            cfg.cookie_name.as_ref(),
            keys.sign_cookie(&cookie)
        ))
        .unwrap(),
    );

    let outcome = load_session(
        &store,
        &keys,
        &cfg,
        &headers,
        Fingerprints::default(),
        &MockRng::new(42),
        &LoadPolicy::bare(),
    )
    .await;

    assert!(!outcome.stored);
    assert!(outcome.loaded_row.is_none());
    let session = outcome.session;
    assert_eq!(
        *session.key(),
        SessionKey::of(&SessionId::new(&MockRng::new(42)))
    );
    assert_ne!(session.key(), cookie.key());

    // The handler changes the session, and the finish stores it.
    let handle = handle_from(SessionInner {
        session,
        data: outcome.data,
        modified: true,
        ..SessionInner::detached(Arc::new(MockRng::new(43)))
    });
    let finalized = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        outcome.stored,
        &MockRng::new(44),
    )
    .await;

    assert!(finalized.session_changed);
    assert_eq!(finalized.session.key(), session.key());
    assert!(store.load(session.key()).await.unwrap().is_some());
    assert!(
        store.load(cookie.key()).await.unwrap().is_none(),
        "nothing is stored under the key of a cookie that named no row"
    );
}

/// A regenerate with no stashed pre-rotation id replaces the id from the
/// supplied RNG and cycles from the id the session held.
#[tokio::test]
async fn finalize_session_replacement_id_comes_from_the_supplied_rng() {
    let store = MemorySessionStore::new();
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(1));
    let mut inner = fresh_inner(id);
    inner.regenerate = true;
    let handle = handle_from(inner);

    let outcome = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        true,
        &MockRng::new(78),
    )
    .await;

    assert_eq!(
        *outcome.session.key(),
        SessionKey::of(&SessionId::new(&MockRng::new(78)))
    );
}

/// The id a handler-side rotation mints is the layer RNG's next draw.
#[tokio::test]
async fn rotate_id_draws_from_the_inner_rng() {
    let id = SessionId::new(&MockRng::new(1));
    let mut inner = fresh_inner(id);
    inner.rng = Arc::new(MockRng::new(79));

    inner.rotate_id();

    assert_eq!(
        *inner.session.key(),
        SessionKey::of(&SessionId::new(&MockRng::new(79)))
    );
    assert_eq!(inner.pre_cycle, Some(SessionKey::of(&id)));
}

/// A request that ran under a stored session and modified it, while the
/// session was deleted (logout elsewhere): the save path must not write the
/// row back, and the response must not re-issue a cookie for it.
#[tokio::test]
async fn finalize_session_does_not_revive_a_session_deleted_mid_request() {
    let store = MemorySessionStore::new();
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(31));
    store
        .save(&SessionKey::of(&id), &SessionData::default(), cfg.ttl)
        .await
        .unwrap();
    let mut inner = fresh_inner(id);
    inner.modified = true;
    inner.data.custom = serde_json::json!({"cart": 1});
    let handle = handle_from(inner);

    store.delete(&SessionKey::of(&id)).await.unwrap();
    let outcome = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        true,
        &MockRng::new(1),
    )
    .await;

    assert!(
        store.load(&SessionKey::of(&id)).await.unwrap().is_none(),
        "a deleted session must stay deleted"
    );
    assert!(
        !outcome.session_changed,
        "no cookie is re-issued for an ended session"
    );
    assert_eq!(
        handle.0.read().await.data.custom,
        SessionData::default().custom
    );
}

/// A rotation (login) whose old session was deleted mid-request must not
/// carry the authenticated data to the new id.
#[tokio::test]
async fn finalize_session_rotation_of_a_deleted_session_yields_a_guest() {
    let store = MemorySessionStore::new();
    let cfg = SessionConfig::default();
    let old = SessionId::new(&MockRng::new(41));
    let new = SessionId::new(&MockRng::new(42));
    store
        .save(&SessionKey::of(&old), &SessionData::default(), cfg.ttl)
        .await
        .unwrap();
    let mut inner = fresh_inner(new);
    inner.regenerate = true;
    inner.pre_cycle = Some(SessionKey::of(&old));
    inner.data.custom = serde_json::json!({"authenticated": true});
    let handle = handle_from(inner);

    store.delete(&SessionKey::of(&old)).await.unwrap();
    let outcome = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        true,
        &MockRng::new(1),
    )
    .await;

    assert_eq!(*outcome.session.key(), SessionKey::of(&new));
    assert!(
        store.load(&SessionKey::of(&new)).await.unwrap().is_none(),
        "the rotated id must not hold the data of an ended session"
    );
    assert_eq!(
        handle.0.read().await.data.custom,
        SessionData::default().custom
    );
}

/// A login on a fresh guest (`existing_id` is `None`, the old id was never
/// stored) still rotates.
#[tokio::test]
async fn finalize_session_rotation_without_a_stored_session_still_writes() {
    let store = MemorySessionStore::new();
    let cfg = SessionConfig::default();
    let old = SessionId::new(&MockRng::new(51));
    let new = SessionId::new(&MockRng::new(52));
    let mut inner = fresh_inner(new);
    inner.regenerate = true;
    inner.pre_cycle = Some(SessionKey::of(&old));
    inner.data.custom = serde_json::json!({"authenticated": true});
    let handle = handle_from(inner);

    let outcome = finalize_session(
        &store,
        &cfg,
        Reporting::unrecorded(),
        &axess_clock::testing::MockClock::at_reference(),
        &handle,
        false,
        &MockRng::new(1),
    )
    .await;

    assert_eq!(*outcome.session.key(), SessionKey::of(&new));
    assert!(store.load(&SessionKey::of(&new)).await.unwrap().is_some());
}

fn cache_control_after_marking(handler_set: &[&'static str]) -> Vec<String> {
    use axum::http::{HeaderValue, header};
    let mut headers = axum::http::HeaderMap::new();
    for value in handler_set {
        headers.append(header::CACHE_CONTROL, HeaderValue::from_static(value));
    }
    mark_cookie_response(&mut headers);
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

/// A response that sets a session cookie is never left cacheable by a shared
/// cache, whatever policy the handler chose.
#[test]
fn a_cookie_response_overrides_a_cacheable_policy_with_no_store() {
    for cacheable in [
        "public, max-age=600",
        "max-age=600",
        "s-maxage=60",
        "public",
        "no-cache",
    ] {
        assert_eq!(
            cache_control_after_marking(&[cacheable]),
            vec!["no-store".to_string()],
            "handler policy `{cacheable}` survived next to a session cookie"
        );
    }
    assert_eq!(
        cache_control_after_marking(&["public, max-age=60", "max-age=5"]),
        vec!["no-store".to_string()],
        "every Cache-Control header is replaced"
    );
}

/// A policy that already keeps the response out of shared caches is the
/// handler's own choice and stays.
#[test]
fn a_cookie_response_keeps_a_policy_shared_caches_already_refuse() {
    for refusing in ["no-store", "private, max-age=60", "No-Store, max-age=0"] {
        assert_eq!(
            cache_control_after_marking(&[refusing]),
            vec![refusing.to_string()]
        );
    }
    assert_eq!(
        cache_control_after_marking(&[]),
        vec!["no-store".to_string()]
    );
}
