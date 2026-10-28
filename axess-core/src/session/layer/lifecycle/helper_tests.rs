//! `helper_tests`: extracted from `lifecycle.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use crate::session::data::SessionData;
use crate::session::layer::handle::SessionInner;
use crate::session::store::MemorySessionStore;
use crate::testing::mock_random::MockRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;

fn fresh_inner(id: SessionId) -> SessionInner {
    SessionInner {
        id,
        data: SessionData::default(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        rng: std::sync::Arc::new(axess_rng::SystemRng),
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
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
    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        self.inner.load(id).await
    }
    async fn save(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.save_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.save(id, data, ttl).await
    }
    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.delete(id).await
    }
    async fn cycle(
        &self,
        old_id: &SessionId,
        new_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        self.cycle_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .cycle(old_id, new_id, data, ttl, require_old)
            .await
    }
    async fn update(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        self.update_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.update(id, data, ttl).await
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
    let keys = SigningKeyRing::from_master([0x55; 32]);
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(11));
    let hv = build_set_cookie(&keys, &cfg, id);
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
/// `data.custom`. Kills the `> 0 → ==/</>= 0` family on line 750
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
        .save(&id, &SessionData::default(), cfg.ttl)
        .await
        .unwrap();
    let big = serde_json::json!({"k": "v".repeat(100_000)});
    let mut inner = fresh_inner(id);
    inner.data.custom = big.clone();
    inner.modified = true;
    inner.max_custom_bytes = 0;
    let handle = handle_from(inner);

    let _ = finalize_session(&store, &cfg, None, &handle, Some(id), &MockRng::new(1)).await;
    let guard = handle.0.read().await;
    assert_eq!(
        guard.data.custom, big,
        "custom must not be cleared when max_custom_bytes == 0"
    );
}

/// `&&` on line 750: the cap check requires BOTH a configured
/// max AND `guard.modified`. With `modified=false`, the helper
/// must NOT clear custom even with a huge payload. Kills
/// `750:36 && → ||`.
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
    inner.modified = false;
    inner.regenerate = false;
    let handle = handle_from(inner);

    let _ = finalize_session(&store, &cfg, None, &handle, Some(id), &MockRng::new(1)).await;
    let guard = handle.0.read().await;
    assert_eq!(
        guard.data.custom, big,
        "custom must not be cleared when guard.modified == false \
             (kills `&& → ||` on the cap-check guard)"
    );
}

/// Strict-greater boundary on line 754: custom size EXACTLY equal
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
            .save(&id, &SessionData::default(), cfg.ttl)
            .await
            .unwrap();
        let mut inner = fresh_inner(id);
        inner.data.custom = payload.clone();
        inner.modified = true;
        let handle = handle_from(inner);
        let _ = finalize_session(&store, &cfg, None, &handle, Some(id), &MockRng::new(1)).await;
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
            .save(&id, &SessionData::default(), cfg.ttl)
            .await
            .unwrap();
        let mut inner = fresh_inner(id);
        inner.data.custom = over.clone();
        inner.modified = true;
        let handle = handle_from(inner);
        let _ = finalize_session(&store, &cfg, None, &handle, Some(id), &MockRng::new(1)).await;
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
        .save(&id, &SessionData::default(), cfg.ttl)
        .await
        .unwrap();
    let mut inner = fresh_inner(id);
    inner.modified = true;
    let handle = handle_from(inner);

    let outcome = finalize_session(&store, &cfg, None, &handle, Some(id), &MockRng::new(1)).await;
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
    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        Ok(self.inner.load(id).await.unwrap())
    }
    async fn save(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.inner.save(id, data, ttl).await.unwrap();
        Ok(())
    }
    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.delete(id).await.unwrap();
        Ok(())
    }
    async fn cycle(
        &self,
        _old_id: &SessionId,
        _new_id: &SessionId,
        _data: &SessionData,
        _ttl: Duration,
        _require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        Err(std::io::Error::other("store unavailable"))
    }
    async fn update(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        Ok(self.inner.update(id, data, ttl).await.unwrap())
    }
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        Ok(0)
    }
}

/// Logout (`regenerate`) while the store's cycle fails: the old id is deleted
/// from the store and is NOT the id the response carries, so the old cookie
/// no longer authenticates. Before this, the old id was re-issued with its
/// Authenticated row still in the store.
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
        .save(&id, &SessionData::default(), cfg.ttl)
        .await
        .expect("seed");
    let handle = handle_from(inner);

    let outcome = finalize_session(&store, &cfg, None, &handle, Some(id), &MockRng::new(1)).await;
    assert_ne!(
        outcome.final_id, id,
        "the old id must never be re-issued after a failed cycle"
    );
    assert_eq!(
        store.delete_calls.load(Ordering::SeqCst),
        1,
        "the old id must be deleted from the store"
    );
    assert!(
        store.inner.load(&id).await.unwrap().is_none(),
        "the old id's row must be gone so the old cookie is a guest"
    );
}

/// `regenerate=true` alone (no `modified`, `existing_id=Some`) is
/// the binding-mismatch / forced-rotation case: the layer must
/// still treat session_changed=true and take the cycle path.
///
/// Discriminating fixture: `modified=false, regenerate=true,
/// existing_id=Some(id)`. Original line 764:
/// `false || true || false = true` → cycle.
/// Mutant 764:62 (`||→&&` on second `||`):
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
        .save(&id, &SessionData::default(), cfg.ttl)
        .await
        .expect("seed");
    let handle = handle_from(inner);

    let outcome = finalize_session(&store, &cfg, None, &handle, Some(id), &MockRng::new(1)).await;
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

/// Metrics-emission gate on line 766: `if session_changed &&
/// (guard.regenerate || existing_id.is_none())`. The inner `||`
/// drives the `session_created` emission.
///
/// Fixture: `regenerate=true, existing_id=Some(id)`. Original:
/// `true && (true || false) = true` → emit. Mutant 766:30 (`||→&&`):
/// `true && (true && false) = false` → no emit. Discriminate via
/// an `AuthnMetrics` recorder that counts `session_created` calls.
#[tokio::test]
async fn finalize_session_emits_session_created_on_regenerate() {
    #[derive(Default)]
    struct CountingMetrics {
        session_created_calls: AtomicUsize,
    }
    impl crate::metrics::AuthnMetrics for CountingMetrics {
        fn session_created(&self) {
            self.session_created_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    let metrics = CountingMetrics::default();
    let store = CallCountingStore::new();
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(9));
    let mut inner = fresh_inner(id);
    inner.modified = false;
    inner.regenerate = true;
    store
        .inner
        .save(&id, &SessionData::default(), cfg.ttl)
        .await
        .expect("seed");
    let handle = handle_from(inner);

    let _ = finalize_session(
        &store,
        &cfg,
        Some(&metrics),
        &handle,
        Some(id),
        &MockRng::new(1),
    )
    .await;
    assert_eq!(
        metrics.session_created_calls.load(Ordering::SeqCst),
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

    let outcome = finalize_session(&store, &cfg, None, &handle, None, &MockRng::new(1)).await;
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
        outcome.final_id, id,
        "the response cookie must carry the same id the request ran under, \
             so a CSRF token bound to it validates on the next request"
    );
}

// ── load_session: fingerprint binding ──────────────────────────────

/// `load_session` line 690: `&& !ct_eq(stored, current)`. The `!`
/// must remain: invalidate ONLY when the fingerprints DIFFER.
/// Kills `delete !` (which would invert the check and invalidate
/// every legitimately matching session, i.e., logging out every
/// authenticated user every request).
#[tokio::test]
async fn load_session_keeps_session_when_fingerprint_matches() {
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master([0xCC; 32]);
    let cfg = SessionConfig::default();

    let stored_fp = "match-me".to_string();
    let id = SessionId::new(&MockRng::new(7));
    let data = SessionData {
        fingerprint: Some(stored_fp.clone()),
        ..SessionData::default()
    };
    // Mutate so migrate() doesn't bump the version inside load_session.
    store.save(&id, &data, cfg.ttl).await.expect("seed store");

    // Build a cookie carrying the seed id, signed under the ring's
    // current key: mirrors what `build_set_cookie` produces in
    // production so `load_session` sees a real-shaped input.
    let cookie_value = keys.sign_cookie(id);
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
        None,
        &headers,
        Fingerprints {
            current: Some(stored_fp.as_str()),
            previous: None,
        },
        &MockRng::new(1),
    )
    .await;

    assert!(
        !outcome.binding_invalidated,
        "matching fingerprint must NOT invalidate binding (kills `delete !` on line 690)"
    );
    assert_eq!(
        outcome.existing_id,
        Some(id),
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
    let keys = SigningKeyRing::from_master([0xCC; 32]);
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(31));
    let data = SessionData {
        fingerprint: Some("bound-to-a-device".to_string()),
        ..SessionData::default()
    };
    store.save(&id, &data, cfg.ttl).await.expect("seed store");
    let cookie_value = keys.sign_cookie(id);
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
        None,
        &headers,
        Fingerprints::default(),
        &MockRng::new(1),
    )
    .await;
    assert!(
        outcome.binding_invalidated,
        "no binding material against a bound session must invalidate it"
    );
    assert_ne!(
        outcome.existing_id,
        Some(id),
        "the bound id must not be kept"
    );
}

// ── injected RNG ───────────────────────────────────────────────────

/// A request with no cookie runs under the id the supplied RNG yields first.
#[tokio::test]
async fn load_session_mints_the_fresh_id_from_the_supplied_rng() {
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master([0xCC; 32]);
    let cfg = SessionConfig::default();
    let headers = axum::http::HeaderMap::new();

    let outcome = load_session(
        &store,
        &keys,
        &cfg,
        None,
        &headers,
        Fingerprints::default(),
        &MockRng::new(77),
    )
    .await;

    assert_eq!(outcome.id, SessionId::new(&MockRng::new(77)));
    assert_eq!(outcome.existing_id, None);
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

    let outcome = finalize_session(&store, &cfg, None, &handle, Some(id), &MockRng::new(78)).await;

    assert_eq!(outcome.final_id, SessionId::new(&MockRng::new(78)));
}

/// The id a handler-side rotation mints is the layer RNG's next draw.
#[tokio::test]
async fn rotate_id_draws_from_the_inner_rng() {
    let id = SessionId::new(&MockRng::new(1));
    let mut inner = fresh_inner(id);
    inner.rng = Arc::new(MockRng::new(79));

    inner.rotate_id();

    assert_eq!(inner.id, SessionId::new(&MockRng::new(79)));
    assert_eq!(inner.pre_cycle_id, Some(id));
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
        .save(&id, &SessionData::default(), cfg.ttl)
        .await
        .unwrap();
    let mut inner = fresh_inner(id);
    inner.modified = true;
    inner.data.custom = serde_json::json!({"cart": 1});
    let handle = handle_from(inner);

    store.delete(&id).await.unwrap();
    let outcome = finalize_session(&store, &cfg, None, &handle, Some(id), &MockRng::new(1)).await;

    assert!(
        store.load(&id).await.unwrap().is_none(),
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
        .save(&old, &SessionData::default(), cfg.ttl)
        .await
        .unwrap();
    let mut inner = fresh_inner(new);
    inner.regenerate = true;
    inner.pre_cycle_id = Some(old);
    inner.data.custom = serde_json::json!({"authenticated": true});
    let handle = handle_from(inner);

    store.delete(&old).await.unwrap();
    let outcome = finalize_session(&store, &cfg, None, &handle, Some(old), &MockRng::new(1)).await;

    assert_eq!(outcome.final_id, new);
    assert!(
        store.load(&new).await.unwrap().is_none(),
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
    inner.pre_cycle_id = Some(old);
    inner.data.custom = serde_json::json!({"authenticated": true});
    let handle = handle_from(inner);

    let outcome = finalize_session(&store, &cfg, None, &handle, None, &MockRng::new(1)).await;

    assert_eq!(outcome.final_id, new);
    assert!(store.load(&new).await.unwrap().is_some());
}
