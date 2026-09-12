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
        regenerate: false,
        pre_cycle_id: None,
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
}

impl CallCountingStore {
    fn new() -> Self {
        Self {
            inner: MemorySessionStore::new(),
            cycle_calls: Arc::new(AtomicUsize::new(0)),
            save_calls: Arc::new(AtomicUsize::new(0)),
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
    ) -> Result<(), Self::Error> {
        self.cycle_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.cycle(old_id, new_id, data, ttl).await
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
    let big = serde_json::json!({"k": "v".repeat(100_000)});
    let mut inner = fresh_inner(id);
    inner.data.custom = big.clone();
    inner.modified = true;
    inner.max_custom_bytes = 0;
    let handle = handle_from(inner);

    let _ = finalize_session(&store, &cfg, None, &handle, Some(id)).await;
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

    let _ = finalize_session(&store, &cfg, None, &handle, Some(id)).await;
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
        let mut inner = fresh_inner(id);
        inner.data.custom = payload.clone();
        inner.modified = true;
        let handle = handle_from(inner);
        let _ = finalize_session(&store, &cfg, None, &handle, Some(id)).await;
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
        let mut inner = fresh_inner(id);
        inner.data.custom = over.clone();
        inner.modified = true;
        let handle = handle_from(inner);
        let _ = finalize_session(&store, &cfg, None, &handle, Some(id)).await;
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
    let mut inner = fresh_inner(id);
    inner.modified = true;
    let handle = handle_from(inner);

    let outcome = finalize_session(&store, &cfg, None, &handle, Some(id)).await;
    assert!(
        outcome.session_changed,
        "modified=true alone must mark session_changed (kills `||→&&` on line 764)"
    );
    assert_eq!(
        store.save_calls.load(Ordering::SeqCst),
        1,
        "modified+existing must take the save branch"
    );
    assert_eq!(
        store.cycle_calls.load(Ordering::SeqCst),
        0,
        "modified-only must NOT cycle"
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

    let outcome = finalize_session(&store, &cfg, None, &handle, Some(id)).await;
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

    let _ = finalize_session(&store, &cfg, Some(&metrics), &handle, Some(id)).await;
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

    let outcome = finalize_session(&store, &cfg, None, &handle, None).await;
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
        Some(stored_fp.as_str()),
        None,
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
