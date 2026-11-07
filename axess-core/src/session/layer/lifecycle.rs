//! Per-request session lifecycle: the stages `SessionService::call`
//! coordinates, each a `pub(crate)` free function taking narrow inputs
//! (`HeaderMap`, the request's fingerprints, the service's dependencies by
//! reference) so it can be tested without axum.
//!
//! - Load: [`load_session`], here, verifies the cookie, loads the row and
//!   applies the fingerprint, age and registry checks.
//! - Finalize: [`finalize_session`], in `finalize`, saves, swaps or cycles
//!   the row for the response.
//! - Registry: [`settle_registry`], in `registry`, moves the registry entry
//!   of a session whose id rotated.
//! - Cookie: [`apply_session_cookie`] and [`build_set_cookie`], here, write
//!   the `Set-Cookie` header, and [`mark_cookie_response`] keeps a response
//!   that sets a cookie out of shared caches.
//!
//! Load invariant: fresh-mint absorbs every failure mode, so the
//! handler never runs under a client-supplied id we don't trust the
//! data behind.

use crate::cookies::MAX_COOKIE_VALUE_BYTES;
use crate::session::config::SessionConfig;
use crate::session::data::SessionData;
use crate::session::id::SessionId;
use crate::session::layer::signing::SigningKeyRing;
use crate::session::store::{SessionLiveness, SessionRegistryHandle, SessionStore};
use axess_clock::Clock;
use axess_rng::SecureRng;
use cookie::Cookie;
use subtle::ConstantTimeEq;

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
    pub(crate) metrics: Option<&'a crate::metrics::MetricSinks>,
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
/// subsequent requests verify without falling back. It is also set when the
/// load bound an authenticated session that stored no fingerprint, so the
/// fingerprint is written back.
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
    /// The row as the store held it, when the load was trusted (`Some`
    /// exactly when `existing_id` is): before migration and re-binding. It
    /// is the base against which this request's changes are merged when a
    /// write finds the row changed by a concurrent request.
    pub(crate) loaded_row: Option<SessionData>,
}

/// Outcome of [`finalize_session`].
///
/// `final_id` is the id the response cookie should carry.
/// `session_changed` says whether the response sets the session cookie: the
/// session was created or changed and its row was written. A write that
/// failed, found the row gone, or lost to concurrent writes sets no cookie;
/// the one exception is a failed rotation, whose cookie replaces the retired
/// id in the client's jar with one no row backs.
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
    /// Whether the session was already authenticated when the request loaded
    /// it, so the registry held its old id (a login rotates a guest id the
    /// registry never held).
    pub(crate) was_authenticated: bool,
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

    let StoredSession {
        mut existing_id,
        data: mut session_data,
        loaded_row,
        session_ended,
    } = match verified {
        Some(verified) => load_stored_session(store, verified.id, config, policy).await,
        None => StoredSession::fresh(),
    };

    let binding = check_binding(&mut session_data, fingerprints, policy);
    let binding_invalidated = binding.invalidated;
    if binding_invalidated {
        // The cookie's id is now untrusted; clear it so a fresh id is
        // minted below before the inner handler runs. Without this the
        // in-flight request would still execute under the
        // attacker-plantable id (the response cookie would only rotate
        // it on the way out).
        existing_id = None;
    }
    rotation_fallback_used |= binding.fingerprint_rewritten;

    let id = existing_id.unwrap_or_else(|| SessionId::new(rng));

    LoadOutcome {
        id,
        data: session_data,
        existing_id,
        binding_invalidated,
        rotation_fallback_used,
        session_ended,
        // A binding mismatch distrusts the row after it loaded.
        loaded_row: existing_id.and(loaded_row),
    }
}

/// The stored record behind a verified session cookie, as the load found it.
struct StoredSession {
    /// The cookie's id, when the row is trusted so far.
    existing_id: Option<SessionId>,
    data: SessionData,
    /// The row as the store held it, before migration and re-binding.
    loaded_row: Option<SessionData>,
    /// The row was refused as revoked or too old, and deleted.
    session_ended: bool,
}

impl StoredSession {
    /// No trusted row: the request runs as a fresh guest.
    fn fresh() -> Self {
        Self {
            existing_id: None,
            data: SessionData::default(),
            loaded_row: None,
            session_ended: false,
        }
    }
}

/// Load, migrate and vet the row of a session whose cookie verified. Any
/// failure (no row, a store error, a revoked or over-age record) yields a
/// fresh guest; a revoked or over-age row is deleted on the way.
async fn load_stored_session<S>(
    store: &S,
    id: SessionId,
    config: &SessionConfig,
    policy: &LoadPolicy<'_>,
) -> StoredSession
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    match store.load(&id).await {
        Ok(Some(mut data)) => {
            let row = data.clone();
            if data.migrate() {
                tracing::debug!(
                    new_version = data.version,
                    "session data migrated to newer schema version"
                );
            }
            match authenticated_session_verdict(&data, config, policy, &id).await {
                SessionVerdict::Keep => StoredSession {
                    existing_id: Some(id),
                    data,
                    loaded_row: Some(row),
                    session_ended: false,
                },
                SessionVerdict::End => {
                    // Revoked or too old: the row must not stay
                    // Authenticated, so it goes now (best effort), and the
                    // request runs as a fresh guest.
                    if let Err(e) = store.delete(&id).await {
                        tracing::error!(
                            error = %e,
                            "deleting an ended session failed; the row may remain until its TTL"
                        );
                    }
                    StoredSession {
                        session_ended: true,
                        ..StoredSession::fresh()
                    }
                }
                SessionVerdict::Distrust => StoredSession::fresh(),
            }
        }
        Ok(None) => StoredSession::fresh(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "session store load failed; falling back to empty session"
            );
            StoredSession::fresh()
        }
    }
}

/// What [`check_binding`] did to a loaded session.
struct BindingCheck {
    /// The fingerprint mismatched and the session was reset to a guest.
    invalidated: bool,
    /// The stored fingerprint was rewritten (re-keyed or first bound), so the
    /// response must persist it and re-issue the cookie.
    fingerprint_rewritten: bool,
}

/// Session binding check with rotation fallback. Constant-time
/// comparison prevents timing side-channels; the previous-key
/// comparison runs only on current-key mismatch, and only if a
/// rotated fingerprint was precomputed by the caller.
///
/// On previous-key match, the stored fingerprint is REPLACED with
/// the current-key value so subsequent requests match on the fast
/// path without falling back. The session data is thereby marked
/// for persistence via the `fingerprint_rewritten` signal read at the
/// finalize and response-cookie stages.
fn check_binding(
    session_data: &mut SessionData,
    fingerprints: Fingerprints<'_>,
    policy: &LoadPolicy<'_>,
) -> BindingCheck {
    let Fingerprints {
        current: current_fingerprint,
        previous: previous_fingerprint,
    } = fingerprints;
    let mut check = BindingCheck {
        invalidated: false,
        fingerprint_rewritten: false,
    };
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
            if let Some(m) = policy.metrics {
                m.rotation.fingerprint_key_fallback();
            }
            session_data.fingerprint = Some(current_hash.to_string());
            check.fingerprint_rewritten = true;
        } else {
            tracing::warn!(
                "session fingerprint mismatch; invalidating session (possible hijacking)"
            );
            if let Some(m) = policy.metrics {
                m.session.session_binding_mismatch();
            }
            *session_data = SessionData::default();
            check.invalidated = true;
        }
    } else if !session_data.auth_state.is_guest()
        && let Some(current_hash) = current_fingerprint
    {
        // A session past `Guest` that stores no fingerprint (it was stored
        // before binding was turned on, or on a path that bound nothing) is
        // bound to this client now, so that every later request is checked
        // against it. Binding is configured exactly when a request yields a
        // fingerprint: the layer binds a request without material to a fixed
        // value, so none is a request the binding does not apply to.
        tracing::info!("binding an authenticated session that stored no fingerprint");
        if let Some(m) = policy.metrics {
            m.session.session_fingerprint_backfilled();
        }
        session_data.fingerprint = Some(current_hash.to_string());
        check.fingerprint_rewritten = true;
    }
    check
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
        impersonator,
        ..
    } = &data.auth_state
    else {
        return SessionVerdict::Keep;
    };
    let outlived = |cap: Option<std::time::Duration>, since: &chrono::DateTime<chrono::Utc>| {
        cap.and_then(|cap| chrono::Duration::from_std(cap).ok())
            .is_some_and(|cap| policy.clock.now().signed_duration_since(*since) > cap)
    };
    if outlived(config.max_authenticated_age, authn_time) {
        tracing::info!("authenticated session outlived its absolute age cap; ending it");
        return SessionVerdict::End;
    }
    if let Some(crate::session::data::Impersonation { since, .. }) = impersonator
        && outlived(config.max_impersonation_age, since)
    {
        tracing::info!("impersonated session outlived the impersonation age cap; ending it");
        return SessionVerdict::End;
    }
    let Some(registry) = policy.registry else {
        return SessionVerdict::Keep;
    };
    let own = registry_verdict(registry.liveness(user_id, id).await, policy);
    let (SessionVerdict::Keep, Some(imp)) = (&own, impersonator) else {
        return own;
    };
    // An impersonation also stands on the administrator: the entry
    // `begin_impersonation` registered under them goes when their sessions
    // do (a suspension, a deletion, a forced logout).
    let anchor = imp.registry_anchor(user_id);
    let held = registry_verdict(registry.liveness(&imp.admin, &anchor).await, policy);
    if matches!(held, SessionVerdict::End) {
        tracing::info!("the administrator of an impersonation no longer holds it; ending it");
    }
    held
}

/// What the registry's answer about one entry means for the session.
fn registry_verdict(liveness: SessionLiveness, policy: &LoadPolicy<'_>) -> SessionVerdict {
    match liveness {
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

mod finalize;
mod registry;

pub(crate) use finalize::finalize_session;
pub(crate) use registry::settle_registry;

/// Keep a response that sets a session or CSRF cookie out of shared caches.
///
/// Sets `Cache-Control: no-store` unless the handler's own policy already
/// keeps the response out of shared caches (it names `no-store` or
/// `private`); any other policy, `public, max-age=600` included, is replaced,
/// since a shared cache that stored it would serve one client's cookie to
/// another. It also names `Cookie` in `Vary` unless it is already there, for a
/// cache that stores the response anyway.
pub(crate) fn mark_cookie_response(headers: &mut axum::http::HeaderMap) {
    use axum::http::{HeaderValue, header};
    let refused = headers.get_all(header::CACHE_CONTROL).iter().any(|v| {
        v.to_str().is_ok_and(|v| {
            v.split(',').map(str::trim).any(|directive| {
                let name = directive.split('=').next().unwrap_or_default().trim();
                name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("private")
            })
        })
    });
    if !refused {
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
    cookie.set_max_age(cookie::time::Duration::seconds(
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

#[cfg(test)]
mod concurrency_tests;

#[cfg(test)]
mod reread_tests;
