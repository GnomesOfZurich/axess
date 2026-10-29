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
use crate::session::store::{
    ConditionalUpdate, CycleOutcome, SessionLiveness, SessionRegistryHandle, SessionStore,
    note_revocation,
};
use axess_clock::Clock;
use axess_rng::SecureRng;
use subtle::ConstantTimeEq;
use tower_cookies::cookie::Cookie;

/// The binding fingerprints computed from a request: the one under the
/// current signing key, and the one under the previous key while a rotation
/// window is open.
#[derive(Clone, Copy, Default)]
pub(crate) struct Fingerprints<'a> {
    pub(crate) current: Option<&'a str>,
    pub(crate) previous: Option<&'a str>,
}

/// What a stored session may be asked beyond its cookie and its fingerprint:
/// whether the registry still holds it, and whether it has outlived the
/// configured absolute age. Both apply to `Authenticated` records only.
#[derive(Clone, Copy)]
pub(crate) struct LoadPolicy<'a> {
    /// Registry consulted for every authenticated record, when configured.
    pub(crate) registry: Option<&'a dyn SessionRegistryHandle>,
    /// What to do when the registry cannot answer.
    pub(crate) unknown: crate::session::layer::UnknownLiveness,
    /// Source of "now" for the absolute-age check.
    pub(crate) clock: &'a dyn Clock,
    /// Metrics hook for the binding-mismatch counter.
    pub(crate) metrics: Option<&'a dyn crate::metrics::AuthnMetrics>,
}

#[cfg(test)]
impl LoadPolicy<'static> {
    /// No registry, no extra checks beyond the age cap in the config.
    pub(crate) fn bare() -> Self {
        static CLOCK: axess_clock::SystemClock = axess_clock::SystemClock;
        Self {
            registry: None,
            unknown: crate::session::layer::UnknownLiveness::Reject,
            clock: &CLOCK,
            metrics: None,
        }
    }
}

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
    /// `true` when a stored authenticated session was refused because the
    /// registry no longer holds it or it outlived the absolute age cap. Its
    /// row has been deleted; the response replaces the client's cookie with
    /// one for the fresh guest.
    pub(crate) session_ended: bool,
}

/// Outcome of [`finalize_session`].
///
/// `final_id` is the id the response cookie should carry.
/// `session_changed` toggles whether the session is persisted and a
/// `Set-Cookie` header is emitted.
pub(crate) struct FinalizeOutcome {
    pub(crate) final_id: SessionId,
    pub(crate) session_changed: bool,
    /// Set when an authenticated session's id was rotated and its row moved:
    /// the registry still holds the session under the old id, and the layer
    /// (when it has a registry) must move the entry.
    pub(crate) rotation: Option<Rotation>,
}

/// An authenticated session whose id changed during a request.
pub(crate) struct Rotation {
    pub(crate) user_id: crate::authn::ids::UserId,
    pub(crate) old_id: SessionId,
    pub(crate) new_id: SessionId,
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
    headers: &axum::http::HeaderMap,
    fingerprints: Fingerprints<'_>,
    rng: &dyn SecureRng,
    policy: &LoadPolicy<'_>,
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

    let mut session_ended = false;
    let (mut existing_id, mut session_data) = if let Some(verified) = verified {
        match store.load(&verified.id).await {
            Ok(Some(mut data)) => {
                if data.migrate() {
                    tracing::debug!(
                        new_version = data.version,
                        "session data migrated to newer schema version"
                    );
                }
                match authenticated_session_verdict(&data, config, policy, &verified.id).await {
                    SessionVerdict::Keep => (Some(verified.id), data),
                    SessionVerdict::End => {
                        // Revoked or too old: the row must not stay
                        // Authenticated, so it goes now (best effort), and the
                        // request runs as a fresh guest.
                        if let Err(e) = store.delete(&verified.id).await {
                            tracing::error!(
                                error = %e,
                                "deleting an ended session failed; the row may remain until its TTL"
                            );
                        }
                        session_ended = true;
                        (None, SessionData::default())
                    }
                    SessionVerdict::Distrust => (None, SessionData::default()),
                }
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
    let Fingerprints {
        current: current_fingerprint,
        previous: previous_fingerprint,
    } = fingerprints;
    let mut binding_invalidated = false;
    // A session that was BOUND (it stores a fingerprint) and a request that
    // presents no binding material is a mismatch, not a skip: leaving the
    // material out was the one way a stolen bound session still passed.
    if let Some(stored_hash) = session_data.fingerprint.clone() {
        if let Some(current_hash) = current_fingerprint
            && bool::from(stored_hash.as_bytes().ct_eq(current_hash.as_bytes()))
        {
            // Fast path: current-key fingerprint matches. No action.
        } else if let Some(previous_hash) = previous_fingerprint
            && let Some(current_hash) = current_fingerprint
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
            if let Some(m) = policy.metrics {
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

    let id = existing_id.unwrap_or_else(|| SessionId::new(rng));

    LoadOutcome {
        id,
        data: session_data,
        existing_id,
        binding_invalidated,
        rotation_fallback_used,
        session_ended,
    }
}

/// What to do with a stored session after it loaded.
enum SessionVerdict {
    /// Trust it.
    Keep,
    /// Refuse it and delete its row: the registry says it is gone, or it
    /// outlived the absolute age cap.
    End,
    /// Refuse it for this request without touching the row: the registry
    /// could not answer and the policy fails closed.
    Distrust,
}

/// Apply the absolute-age cap and the registry to an authenticated record.
/// Guests and part-way logins are never checked: neither is registered yet.
async fn authenticated_session_verdict(
    data: &SessionData,
    config: &SessionConfig,
    policy: &LoadPolicy<'_>,
    id: &SessionId,
) -> SessionVerdict {
    let crate::session::data::AuthState::Authenticated {
        user_id,
        authn_time,
        ..
    } = &data.auth_state
    else {
        return SessionVerdict::Keep;
    };
    if let Some(max_age) = config.max_authenticated_age
        && let Ok(max_age) = chrono::Duration::from_std(max_age)
        && policy.clock.now().signed_duration_since(*authn_time) > max_age
    {
        tracing::info!("authenticated session outlived its absolute age cap; ending it");
        return SessionVerdict::End;
    }
    let Some(registry) = policy.registry else {
        return SessionVerdict::Keep;
    };
    match registry.liveness(user_id, id).await {
        SessionLiveness::Valid => SessionVerdict::Keep,
        SessionLiveness::Gone => {
            tracing::info!("session is no longer held by the registry; ending it");
            SessionVerdict::End
        }
        SessionLiveness::Unknown => match policy.unknown {
            crate::session::layer::UnknownLiveness::Reject => SessionVerdict::Distrust,
            crate::session::layer::UnknownLiveness::Accept => SessionVerdict::Keep,
        },
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
    clock: &dyn Clock,
    handle: &SessionHandle,
    existing_id: Option<SessionId>,
    rng: &dyn SecureRng,
) -> FinalizeOutcome
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut guard = handle.0.write().await;

    enforce_custom_cap(&mut guard, config, existing_id.is_none());

    // A request without a trusted session persists the fresh guest and sets a
    // cookie only when something needs it (a modification, a CSRF token bound
    // to the id, a handler that read the id); an untouched cookieless request
    // leaves the store empty and the response without `Set-Cookie`.
    let fresh_needed = existing_id.is_none() && (guard.modified || guard.needs_persist);
    // A stored session that only read, and whose row has not been re-armed
    // for half its lifetime, is refreshed so that activity keeps it alive.
    let now = clock.now();
    let touch_due = existing_id.is_some()
        && !guard.modified
        && !guard.regenerate
        && touch_is_due(guard.data.touched_at, now, config.ttl);
    let mut session_changed = guard.modified || guard.regenerate || fresh_needed || touch_due;
    let loaded_revision = guard.data.revision;
    if session_changed {
        // Every write moves the revision and the refresh stamp, so a
        // compare-and-swap on the revision sees any intervening write.
        guard.data.revision = guard.data.revision.wrapping_add(1);
        guard.data.touched_at = Some(now);
    }
    if session_changed
        && (guard.regenerate || existing_id.is_none())
        && let Some(m) = metrics
    {
        m.session_created();
    }

    let mut rotation = None;
    let final_id = if session_changed {
        if guard.regenerate {
            let (new_id, moved) = cycle_session(store, config, &mut guard, existing_id, rng).await;
            rotation = moved;
            new_id
        } else if existing_id.is_some() {
            // The request ran under a stored session: replace it only while
            // it is still stored. A delete that landed while the request ran
            // (logout, administrator revocation) is final, and the response
            // does not re-issue a cookie for the ended session.
            let written = if touch_due {
                refresh_idle_expiry(store, &guard, loaded_revision, config.ttl).await
            } else {
                store.update(&guard.id, &guard.data, config.ttl).await
            };
            match written {
                Ok(true) => {}
                Ok(false) => {
                    tracing::info!("session was ended while its request ran; changes discarded");
                    guard.data = SessionData::default();
                    session_changed = false;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "session store update failed; session changes may be lost"
                    );
                }
            }
            guard.id
        } else {
            // A fresh guest: `existing_id` is `None`, so its id was minted
            // safely by `load_session` (never the client-supplied cookie id:
            // session fixation is prevented there and, on privilege change, by
            // the `regenerate` branch above). Keeping it, rather than minting
            // a second, different id for the response cookie, is what lets a
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
        rotation,
    }
}

/// Write a rotated session under its new id and retire the old row, failing
/// closed. Returns the id the response cookie carries and, for a session
/// that stayed authenticated, the registry entry to move.
async fn cycle_session<S>(
    store: &S,
    config: &SessionConfig,
    guard: &mut tokio::sync::RwLockWriteGuard<'_, super::handle::SessionInner>,
    existing_id: Option<SessionId>,
    rng: &dyn SecureRng,
) -> (SessionId, Option<Rotation>)
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut rotation = None;
    let old_id = guard.pre_cycle_id.take().unwrap_or_else(|| {
        let prev = guard.id;
        guard.id = SessionId::new(rng);
        prev
    });
    let new_id = guard.id;
    // A request that ran under a stored session requires that row to
    // still be live: a logout that removed it while the request ran
    // must not be undone by moving the data to the new id.
    let require_old = existing_id.is_some();
    match store
        .cycle(&old_id, &new_id, &guard.data, config.ttl, require_old)
        .await
    {
        Ok(CycleOutcome::Rotated) => {
            if guard.data.auth_state.is_authenticated()
                && let Some(user_id) = guard.data.auth_state.user_id()
                && old_id != new_id
            {
                rotation = Some(Rotation {
                    user_id: *user_id,
                    old_id,
                    new_id,
                });
            }
            (new_id, rotation)
        }
        Ok(CycleOutcome::SessionGone) => {
            tracing::info!(
                "session was ended while its request ran; \
                     not carrying it over to the rotated id"
            );
            guard.data = SessionData::default();
            (new_id, None)
        }
        Err(e) => {
            // Fail closed in the STORE as well as in this response: the
            // row under `old_id` may still say Authenticated, so the old
            // id is deleted (best effort) and never re-issued; the cookie
            // carries the new id, which no row backs, so the next request
            // is a guest.
            tracing::error!(
                error = %e,
                "session store cycle failed; clearing session (fail closed)"
            );
            if let Err(e) = store.delete(&old_id).await {
                tracing::error!(
                    error = %e,
                    "session store delete after a failed cycle also failed; \
                     the old session id may authenticate until its TTL"
                );
            }
            guard.data = SessionData::default();
            (new_id, None)
        }
    }
}

/// Whether a stored session that only read has gone half its lifetime
/// without its row being re-armed. A session that carries no stamp (stored
/// before the stamp existed) is due at once; a stamp in the future (a clock
/// step) is not.
fn touch_is_due(
    touched_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    ttl: std::time::Duration,
) -> bool {
    let Some(touched_at) = touched_at else {
        return true;
    };
    let Ok(half) = chrono::Duration::from_std(ttl / 2) else {
        return false;
    };
    now.signed_duration_since(touched_at) >= half
}

/// Re-arm the row of a session that did not change, without clobbering a
/// concurrent request's write: the write is a compare-and-swap on the
/// revision the request loaded, so when another request wrote meanwhile
/// (and re-armed the row itself) this one writes nothing. `Ok(false)` when
/// the row is gone.
async fn refresh_idle_expiry<S>(
    store: &S,
    guard: &tokio::sync::RwLockWriteGuard<'_, super::handle::SessionInner>,
    loaded_revision: u64,
    ttl: std::time::Duration,
) -> Result<bool, S::Error>
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    Ok(
        match store
            .update_if_revision(&guard.id, loaded_revision, &guard.data, ttl)
            .await?
        {
            ConditionalUpdate::Written | ConditionalUpdate::Conflict => true,
            ConditionalUpdate::Gone => false,
        },
    )
}

/// Keep a response that sets a session or CSRF cookie out of shared caches.
///
/// Adds `Cache-Control: no-store` when the handler set none (a handler's own
/// choice is left alone) and names `Cookie` in `Vary` unless it is already
/// there, so a cache that stores the response anyway does not serve one
/// client's cookie to another.
pub(crate) fn mark_cookie_response(headers: &mut axum::http::HeaderMap) {
    use axum::http::{HeaderValue, header};
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    let varies_on_cookie = headers.get_all(header::VARY).iter().any(|v| {
        v.to_str().is_ok_and(|v| {
            v.split(',')
                .map(str::trim)
                .any(|t| t == "*" || t.eq_ignore_ascii_case("cookie"))
        })
    });
    if !varies_on_cookie {
        headers.append(header::VARY, HeaderValue::from_static("Cookie"));
    }
}

/// Enforce the custom-data size cap on every path that writes the session.
///
/// Every write path is covered, not only a handler's own modification: data
/// loaded from the store or migrated can be oversized too, and a session
/// saved because it was regenerated or must persist writes it back.
fn enforce_custom_cap(
    guard: &mut tokio::sync::RwLockWriteGuard<'_, super::handle::SessionInner>,
    config: &SessionConfig,
    fresh: bool,
) {
    let will_write = guard.modified || guard.regenerate || (fresh && guard.needs_persist);
    if config.max_custom_bytes > 0 && will_write {
        let custom_size = crate::session::data::json_byte_len(&guard.data.custom);
        if custom_size > config.max_custom_bytes {
            tracing::warn!(
                custom_size,
                max = config.max_custom_bytes,
                "session custom data exceeds size limit; clearing custom data"
            );
            guard.data.custom = serde_json::Value::default();
        }
    }
}

/// Move the registry entry of a rotated, still-authenticated session from
/// its old id to its new one. Returns `false` when the registry could not
/// track the new id: the session has then been deleted (fail closed) and
/// must not get a cookie.
pub(crate) async fn move_registry_entry<S>(
    store: &S,
    registry: &dyn SessionRegistryHandle,
    rotation: &Rotation,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    if registry.liveness(&rotation.user_id, &rotation.old_id).await != SessionLiveness::Valid {
        return true;
    }
    if registry.register(&rotation.user_id, &rotation.new_id).await {
        note_revocation(
            registry
                .invalidate_session(&rotation.user_id, &rotation.old_id)
                .await,
            "moving a rotated session's registry entry",
        );
        return true;
    }
    tracing::error!(
        "registering the rotated session failed; ending it rather than leaving it untracked"
    );
    if let Err(e) = store.delete(&rotation.new_id).await {
        tracing::error!(error = %e, "deleting the untracked session failed");
    }
    false
}

/// Move the registry entry of a session that stayed authenticated across an
/// id change, which is still registered under its old id. Returns whether
/// the session may get a cookie: `false` when the registry could not track
/// the new id and the session was ended instead.
pub(crate) async fn settle_registry<S>(
    store: &S,
    registry: Option<&dyn SessionRegistryHandle>,
    outcome: &FinalizeOutcome,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    match (registry, &outcome.rotation) {
        (Some(registry), Some(rotation)) => move_registry_entry(store, registry, rotation).await,
        _ => true,
    }
}

/// Set the session cookie on the response, only when the session was created
/// or changed (and was not ended while its request ran): omitting
/// `Set-Cookie` on unmodified responses reduces header bloat and prevents
/// spurious cache invalidation on CDN and reverse proxies.
pub(crate) fn apply_session_cookie(
    signing_keys: &SigningKeyRing,
    config: &SessionConfig,
    outcome: &FinalizeOutcome,
    registered: bool,
    headers: &mut axum::http::HeaderMap,
) {
    if outcome.session_changed
        && registered
        && let Some(hv) = build_set_cookie(signing_keys, config, outcome.final_id)
    {
        headers.append(axum::http::header::SET_COOKIE, hv);
        mark_cookie_response(headers);
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

#[cfg(test)]
mod policy_tests;
