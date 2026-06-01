//! Per-request session lifecycle helpers.
//!
//! Three `pub(crate)` free helpers that name the load / finalize /
//! cookie-write stages of `SessionService::call`, taking narrow inputs
//! (`HeaderMap`, fingerprint `Option<&str>`, and `&SessionService` deps
//! by reference) so the `call` body shrinks to a coordinator and each
//! stage is individually testable without axum.
//!
//! Load invariant: fresh-mint absorbs every failure mode, so the
//! handler never runs under a client-supplied id we don't trust the
//! data behind.

use crate::cookies::MAX_COOKIE_VALUE_BYTES;
use crate::session::config::SessionConfig;
use crate::session::data::SessionData;
use crate::session::id::SessionId;
use crate::session::layer::handle::SessionHandle;
use crate::session::layer::signing::{SigningKeys, signing_decode_cookie, signing_sign_bytes};
use crate::session::store::SessionStore;
use axess_rng::SystemRng;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use subtle::ConstantTimeEq;
use tower_cookies::cookie::Cookie;

/// Outcome of [`load_session`].
///
/// `id` is always the id this request will run under (existing-and-trusted
/// or freshly-minted). `existing_id` is `Some` only when the cookie's
/// signature verified, the store had live data, and the fingerprint check
/// passed: i.e. when the load was fully trusted. `binding_invalidated`
/// is `true` when the fingerprint check actively reset the session
/// (separate signal from "no cookie at all" because the response must
/// cycle the id and emit metrics distinctly).
pub(crate) struct LoadOutcome {
    pub(crate) id: SessionId,
    pub(crate) data: SessionData,
    pub(crate) existing_id: Option<SessionId>,
    pub(crate) binding_invalidated: bool,
}

/// Outcome of [`finalize_session`].
///
/// `final_id` is the id the response cookie should carry.
/// `session_changed` toggles whether a `Set-Cookie` header is emitted.
pub(crate) struct FinalizeOutcome {
    pub(crate) final_id: SessionId,
    pub(crate) session_changed: bool,
}

/// Extract + verify the session cookie, load (and migrate) the stored
/// session, check the binding fingerprint, and mint a fresh id when
/// any of those steps fails closed.
///
/// **Invariant:** the handler never runs under a client-supplied id we
/// do not trust the data behind. If the cookie verifies but the store
/// has no record (expired, evicted, attempted fixation), if the store
/// errors, or if the fingerprint mismatches, the load returns
/// `existing_id = None` and `id` is a freshly-minted value: the
/// in-flight request executes under that id, the response cycles to it.
pub(crate) async fn load_session<S>(
    store: &S,
    signing_keys: &SigningKeys,
    config: &SessionConfig,
    metrics: Option<&dyn crate::metrics::AuthnMetrics>,
    headers: &axum::http::HeaderMap,
    current_fingerprint: Option<&str>,
) -> LoadOutcome
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    // Shared cookie-extraction helper. Caps value length at
    // `MAX_COOKIE_VALUE_BYTES` (mandatory DoS cap) so the session
    // middleware cannot be tricked into clone'ing an arbitrarily long
    // cookie value. Borrow-based so the legitimate hot path keeps its
    // zero-alloc property.
    let cookie_value = crate::cookies::extract_named_cookie(
        headers,
        config.cookie_name.as_ref(),
        MAX_COOKIE_VALUE_BYTES,
    );

    // Cookie verification uses the dedicated cookie sub-key; distinct
    // from the fingerprint key.
    let verified_id = cookie_value
        .as_deref()
        .and_then(|v| signing_decode_cookie(v, &signing_keys.cookie));

    let (mut existing_id, mut session_data) = if let Some(id) = verified_id {
        match store.load(&id).await {
            Ok(Some(mut data)) => {
                if data.migrate() {
                    tracing::debug!(
                        new_version = data.version,
                        "session data migrated to newer schema version"
                    );
                }
                (Some(id), data)
            }
            Ok(None) => (None, SessionData::default()),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "session store load failed; falling back to empty session"
                );
                (None, SessionData::default())
            }
        }
    } else {
        (None, SessionData::default())
    };

    // Session binding check; invalidate on mismatch. Constant-time
    // comparison prevents timing side-channels that could leak whether
    // a fingerprint is valid.
    let mut binding_invalidated = false;
    if let (Some(stored_hash), Some(current_hash)) =
        (&session_data.fingerprint, current_fingerprint)
        && !bool::from(stored_hash.as_bytes().ct_eq(current_hash.as_bytes()))
    {
        tracing::warn!("session fingerprint mismatch; invalidating session (possible hijacking)");
        if let Some(m) = metrics {
            m.session_binding_mismatch();
        }
        session_data = SessionData::default();
        binding_invalidated = true;
        // The cookie's id is now untrusted; clear it so a fresh id is
        // minted below before the inner handler runs. Without this the
        // in-flight request would still execute under the
        // attacker-plantable id (the response cookie would only rotate
        // it on the way out).
        existing_id = None;
    }

    let rng = SystemRng;
    let id = existing_id.unwrap_or_else(|| SessionId::new(&rng));

    LoadOutcome {
        id,
        data: session_data,
        existing_id,
        binding_invalidated,
    }
}

/// Enforce the custom-data size cap, then decide save vs cycle vs
/// fail-closed for the response.
///
/// `existing_id` is the trusted id from [`load_session`]'s outcome:
/// `None` means "no trusted prior session, the response must cycle to
/// the current id." `guard.regenerate` (set by handler-side
/// `rotate_id` calls or by binding invalidation) also forces cycle.
///
/// Cycle order matters: the handler-side state-transition methods
/// already minted the new id and stashed the old one in
/// `pre_cycle_id` (see
/// [`SessionInner::rotate_id`](super::handle::SessionInner::rotate_id)).
/// The store's `cycle` then takes `(old, new, data)` so handler code
/// that registered with the new id keys the registry against the
/// post-rotation value. Fallback path for `regenerate` without a
/// stashed `pre_cycle_id` (binding-mismatch reset) mints fresh here.
///
/// Cycle failure: fail closed by clearing the session to Guest and
/// keeping the old id. Keeping the old id + new data would bypass
/// session fixation prevention.
pub(crate) async fn finalize_session<S>(
    store: &S,
    config: &SessionConfig,
    metrics: Option<&dyn crate::metrics::AuthnMetrics>,
    handle: &SessionHandle,
    existing_id: Option<SessionId>,
) -> FinalizeOutcome
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut guard = handle.0.write().await;

    // Enforce custom data size limit to prevent session-bloat DoS.
    if config.max_custom_bytes > 0 && guard.modified {
        let custom_size = serde_json::to_vec(&guard.data.custom)
            .map(|v| v.len())
            .unwrap_or(0);
        if custom_size > config.max_custom_bytes {
            tracing::warn!(
                custom_size,
                max = config.max_custom_bytes,
                "session custom data exceeds size limit; clearing custom data"
            );
            guard.data.custom = serde_json::Value::default();
        }
    }

    let session_changed = guard.modified || guard.regenerate || existing_id.is_none();
    if session_changed
        && (guard.regenerate || existing_id.is_none())
        && let Some(m) = metrics
    {
        m.session_created();
    }

    let final_id = if session_changed {
        if guard.regenerate || existing_id.is_none() {
            let rng = SystemRng;
            let old_id = guard.pre_cycle_id.take().unwrap_or_else(|| {
                let prev = guard.id;
                guard.id = SessionId::new(&rng);
                prev
            });
            let new_id = guard.id;
            match store.cycle(&old_id, &new_id, &guard.data, config.ttl).await {
                Ok(()) => new_id,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "session store cycle failed; clearing session (fail closed)"
                    );
                    guard.data = SessionData::default();
                    guard.id = old_id;
                    old_id
                }
            }
        } else {
            if let Err(e) = store.save(&guard.id, &guard.data, config.ttl).await {
                tracing::warn!(
                    error = %e,
                    "session store save failed; session changes may be lost"
                );
            }
            guard.id
        }
    } else {
        guard.id
    };

    FinalizeOutcome {
        final_id,
        session_changed,
    }
}

/// Build the `Set-Cookie` header value for the response.
///
/// Returns `None` only if `HeaderValue::from_str` fails on the
/// constructed cookie string; should not happen in practice (the
/// cookie value is base64-url + `.` + base64-url, all ASCII), but the
/// caller treats `None` as "skip the header" to avoid a panic on a
/// pathological config.
pub(crate) fn build_set_cookie(
    signing_keys: &SigningKeys,
    config: &SessionConfig,
    id: SessionId,
) -> Option<axum::http::HeaderValue> {
    let cookie_value = {
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());
        let mac = signing_sign_bytes(id.as_bytes(), &signing_keys.cookie);
        format!("{}.{}", id_enc, mac)
    };

    let mut cookie = Cookie::new(config.cookie_name.as_ref().to_string(), cookie_value);
    cookie.set_http_only(config.http_only);
    cookie.set_secure(config.secure);
    cookie.set_same_site(config.same_site);
    cookie.set_path(config.path.as_ref().to_string());
    cookie.set_max_age(tower_cookies::cookie::time::Duration::seconds(
        config.ttl.as_secs().min(i64::MAX as u64) as i64,
    ));

    axum::http::HeaderValue::from_str(&cookie.to_string()).ok()
}

/// Direct unit tests on the `pub(crate)` lifecycle helpers extracted
/// from `SessionService::call`. The Tower-service integration tests
/// don't exercise the boolean/relational boundaries inside these
/// helpers; cargo-mutants flagged them as missed. Each test below pins
/// a specific mutation by feeding the helper a constructed input the
/// real call site never produces.
#[cfg(test)]
mod helper_tests {
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
        let keys = SigningKeys::from_master([0x55; 32]);
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

    /// Line 766 / 773: `(guard.regenerate || existing_id.is_none())`
    /// drives the cycle-vs-save decision. With `existing_id=None`
    /// alone (no regenerate, but no prior id), the helper must take
    /// the cycle path. Kills `||→&&` on lines 766 and 773.
    #[tokio::test]
    async fn finalize_session_no_existing_id_takes_cycle_path() {
        let store = CallCountingStore::new();
        let cfg = SessionConfig::default();
        let id = SessionId::new(&MockRng::new(6));
        let mut inner = fresh_inner(id);
        inner.modified = true;
        inner.regenerate = false;
        let handle = handle_from(inner);

        let _ = finalize_session(&store, &cfg, None, &handle, None).await;
        assert_eq!(
            store.cycle_calls.load(Ordering::SeqCst),
            1,
            "existing_id=None must cycle (kills `||→&&` on lines 766/773)"
        );
        assert_eq!(store.save_calls.load(Ordering::SeqCst), 0);
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
        let keys = SigningKeys::from_master([0xCC; 32]);
        let cfg = SessionConfig::default();

        let stored_fp = "match-me".to_string();
        let id = SessionId::new(&MockRng::new(7));
        let data = SessionData {
            fingerprint: Some(stored_fp.clone()),
            ..SessionData::default()
        };
        // Mutate so migrate() doesn't bump the version inside load_session.
        store.save(&id, &data, cfg.ttl).await.expect("seed store");

        // Build a cookie carrying the seed id, signed by `keys.cookie`.
        let id_enc = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            id.as_bytes(),
        );
        let mac = signing_sign_bytes(id.as_bytes(), &keys.cookie);
        let cookie_value = format!("{id_enc}.{mac}");
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
}
