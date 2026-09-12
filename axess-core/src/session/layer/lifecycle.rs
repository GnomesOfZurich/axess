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
use crate::session::layer::signing::SigningKeyRing;
use crate::session::store::SessionStore;
use axess_rng::SystemRng;
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
///
/// `rotation_fallback_used` is `true` when either the cookie or the
/// fingerprint verified only against the PREVIOUS signing key (see
/// [`SigningKeyRing`]). The session is trusted, but the response MUST
/// emit a fresh `Set-Cookie` under the current key AND any stored
/// fingerprint value must be re-computed under the current key so
/// subsequent requests verify without falling back.
pub(crate) struct LoadOutcome {
    pub(crate) id: SessionId,
    pub(crate) data: SessionData,
    pub(crate) existing_id: Option<SessionId>,
    pub(crate) binding_invalidated: bool,
    pub(crate) rotation_fallback_used: bool,
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
    signing_keys: &SigningKeyRing,
    config: &SessionConfig,
    metrics: Option<&dyn crate::metrics::AuthnMetrics>,
    headers: &axum::http::HeaderMap,
    current_fingerprint: Option<&str>,
    previous_fingerprint: Option<&str>,
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

    // Rotation-aware cookie verification: tries the current cookie
    // sub-key first, falls back to the previous sub-key if configured.
    // `verified.verified_by_previous` signals whether the response
    // must re-issue the cookie under the current key.
    let verified = cookie_value
        .as_deref()
        .and_then(|v| signing_keys.decode_cookie(v));
    let mut rotation_fallback_used = verified
        .as_ref()
        .map(|v| v.verified_by_previous)
        .unwrap_or(false);

    let (mut existing_id, mut session_data) = if let Some(verified) = verified {
        match store.load(&verified.id).await {
            Ok(Some(mut data)) => {
                if data.migrate() {
                    tracing::debug!(
                        new_version = data.version,
                        "session data migrated to newer schema version"
                    );
                }
                (Some(verified.id), data)
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

    // Session binding check with rotation fallback. Constant-time
    // comparison prevents timing side-channels; the previous-key
    // comparison runs only on current-key mismatch, and only if a
    // rotated fingerprint was precomputed by the caller.
    //
    // On previous-key match, the stored fingerprint is REPLACED with
    // the current-key value so subsequent requests match on the fast
    // path without falling back. The session data is thereby marked
    // for persistence via the modified/rotation_fallback_used signal
    // read at the finalize + response-cookie stages.
    let mut binding_invalidated = false;
    if let (Some(stored_hash), Some(current_hash)) =
        (session_data.fingerprint.clone(), current_fingerprint)
    {
        if bool::from(stored_hash.as_bytes().ct_eq(current_hash.as_bytes())) {
            // Fast path: current-key fingerprint matches. No action.
        } else if let Some(previous_hash) = previous_fingerprint
            && bool::from(stored_hash.as_bytes().ct_eq(previous_hash.as_bytes()))
        {
            // Fallback: stored fingerprint was computed under the
            // previous fingerprint sub-key. Re-store under the current
            // key so the next request hits the fast path.
            tracing::debug!(
                "session fingerprint verified with previous (rotated) signing key; \
                 re-storing under current key"
            );
            session_data.fingerprint = Some(current_hash.to_string());
            rotation_fallback_used = true;
        } else {
            tracing::warn!(
                "session fingerprint mismatch; invalidating session (possible hijacking)"
            );
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
    }

    let rng = SystemRng;
    let id = existing_id.unwrap_or_else(|| SessionId::new(&rng));

    LoadOutcome {
        id,
        data: session_data,
        existing_id,
        binding_invalidated,
        rotation_fallback_used,
    }
}

/// Enforce the custom-data size cap, then decide save vs cycle vs
/// fail-closed for the response.
///
/// `existing_id` is the trusted id from [`load_session`]'s outcome:
/// `None` means "no trusted prior session", a fresh guest whose id was
/// already minted safely by `load_session` (never the client's cookie
/// id). Its data is *saved* under that same id; the response cookie
/// carries it unchanged. This is deliberate: a CSRF token minted during
/// the request is HMAC-bound to this id, so minting a *second*, different
/// id for the response cookie here would invalidate that token and 403
/// the next state-changing request (the login POST). Only `guard.regenerate`
/// (handler-side `rotate_id`, or binding invalidation) forces an id change.
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
        if guard.regenerate {
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
            // Persist under the id the request already ran under. For a fresh
            // guest (`existing_id.is_none()`) that id was minted safely by
            // `load_session` (never the client-supplied cookie id: session
            // fixation is prevented there and, on privilege change, by the
            // `regenerate` branch above). Keeping it: rather than minting a
            // second, different id for the response cookie, is what lets a
            // CSRF token minted *during* this request (bound to the same id)
            // still validate on the client's next request. Minting a fresh id
            // here would orphan both the token and any handler-time work keyed
            // to `guard.id`, and every subsequent state-changing request would
            // 403 until the cookie expired.
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
    signing_keys: &SigningKeyRing,
    config: &SessionConfig,
    id: SessionId,
) -> Option<axum::http::HeaderValue> {
    // Always sign new/re-issued cookies under the CURRENT sub-key.
    // Previous-key signing only exists on the verify side (fallback).
    let cookie_value = signing_keys.sign_cookie(id);

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
mod helper_tests;
