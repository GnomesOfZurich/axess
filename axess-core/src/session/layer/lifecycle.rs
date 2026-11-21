//! Per-request session lifecycle: the stages `SessionService::call`
//! coordinates, each a `pub(crate)` free function taking narrow inputs
//! (`HeaderMap`, the request's fingerprints, the service's dependencies by
//! reference) so it can be tested without axum.
//!
//! - Load: [`load_session`], here, verifies the cookie and applies the
//!   fingerprint, age and registry checks; `load` reads the row behind a
//!   verified cookie and ends a session the checks refuse.
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
use crate::session::layer::audit::{SessionEndAudit, SessionEndReason};
use crate::session::layer::signing::{CookieSession, SigningKeyRing};
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
/// configured absolute age. Both apply to signed-in records only (an
/// authenticated session, or one in a step-up of it).
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
    /// Told of every session the load ends (an age cap, a registry entry
    /// gone), and of one the device-key check after it ends, before its row
    /// is removed. Owned by the task that ends the
    /// session, so it is handed over as the `Arc`.
    pub(crate) audit: &'a std::sync::Arc<dyn SessionEndAudit>,
}

/// Where the finalize stage reports: the metric sinks, when any are
/// attached, and the audit sink told of a session the stage ends.
#[derive(Clone, Copy)]
pub(crate) struct Reporting<'a> {
    pub(crate) metrics: Option<&'a crate::metrics::MetricSinks>,
    pub(crate) audit: &'a dyn SessionEndAudit,
}

#[cfg(test)]
impl Reporting<'static> {
    /// No metric sinks, and the sink that records nothing.
    pub(crate) fn unrecorded() -> Self {
        Self {
            metrics: None,
            audit: &crate::session::layer::audit::UnrecordedSessionEnds,
        }
    }
}

#[cfg(test)]
impl LoadPolicy<'static> {
    /// No registry, no extra checks beyond the age cap in the config, on a
    /// clock at the reference instant.
    pub(crate) fn bare() -> Self {
        static CLOCK: std::sync::LazyLock<axess_clock::testing::MockClock> =
            std::sync::LazyLock::new(axess_clock::testing::MockClock::at_reference);
        static UNRECORDED: std::sync::LazyLock<std::sync::Arc<dyn SessionEndAudit>> =
            std::sync::LazyLock::new(|| {
                std::sync::Arc::new(crate::session::layer::audit::UnrecordedSessionEnds)
            });
        Self {
            registry: None,
            unknown: crate::session::layer::UnknownLiveness::Reject,
            clock: &*CLOCK,
            metrics: None,
            audit: &UNRECORDED,
        }
    }
}

/// Outcome of [`load_session`].
///
/// `session` is always the session this request will run under (the
/// cookie's, when it is trusted, or a freshly minted one). `stored` is
/// `true` only when the cookie's signature verified, the store had live
/// data, and the fingerprint check passed: i.e. when the load was fully
/// trusted, and `session` is then the cookie's. `binding_invalidated`
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
    pub(crate) session: CookieSession,
    pub(crate) data: SessionData,
    pub(crate) stored: bool,
    pub(crate) binding_invalidated: bool,
    pub(crate) rotation_fallback_used: bool,
    /// `true` when this request ended a stored signed-in session: the
    /// registry no longer holds it, it outlived an absolute age cap, or
    /// device keys are required and it outlived its registration window
    /// unbound; its ending is recorded and its row removed. The response replaces the
    /// client's cookie with one for the fresh guest. `false` for a session
    /// that was refused without being ended (another request is ending it,
    /// or its ending could not be recorded).
    pub(crate) session_ended: bool,
    /// The row as the store held it, when the load was trusted (`Some`
    /// exactly when `stored`): before re-binding. It
    /// is the base against which this request's changes are merged when a
    /// write finds the row changed by a concurrent request.
    pub(crate) loaded_row: Option<SessionData>,
}

impl LoadOutcome {
    /// A fresh guest in place of a session this request may not run as. The
    /// stored row is not touched unless the caller deleted it.
    pub(crate) fn guest(rng: &dyn axess_rng::SecureRng, session_ended: bool) -> Self {
        Self {
            session: CookieSession::mint(rng),
            data: SessionData::default(),
            stored: false,
            binding_invalidated: false,
            rotation_fallback_used: false,
            session_ended,
            loaded_row: None,
        }
    }

    /// Fail closed on a row bound to a device key that this layer cannot
    /// hold to its key: the request runs as a guest and the row stays, for
    /// a layer that can check it. A layer that checks keys, or was told to
    /// serve bound rows without one, passes the row on.
    pub(crate) fn refuse_unchecked_binding(
        self,
        unchecked: &UncheckedBinding,
        rng: &dyn axess_rng::SecureRng,
    ) -> Self {
        let (Some(why), true) = (unchecked.why, self.data.key_binding.is_some()) else {
            return self;
        };
        if unchecked
            .reported
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::debug!(why, "a session bound to a device key was not served");
        } else {
            tracing::error!(
                why,
                "a session bound to a device key reached a session layer that cannot check \
                 the key; it is served as a guest, never as an unbound session. Give every \
                 layer that shares the session store the device-key service, or one whose \
                 policy is `Off` to serve bound sessions as bearer sessions on purpose"
            );
        }
        Self::guest(rng, false)
    }
}

/// What a layer does with a row bound to a device key when it cannot check
/// the key.
pub(crate) struct UncheckedBinding {
    /// `Some` when the layer cannot check a key and was not told to serve
    /// bound rows without one: what is missing. Such a row is refused.
    why: Option<&'static str>,
    /// Set once the refusal has been logged as an error.
    reported: std::sync::atomic::AtomicBool,
}

impl UncheckedBinding {
    pub(crate) fn new(why: Option<&'static str>) -> Self {
        Self {
            why,
            reported: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

/// Outcome of [`finalize_session`].
///
/// `session` is the session the response cookie should carry.
/// `session_changed` says whether the response sets the session cookie: the
/// session was created or changed and its row was written. A write that
/// failed, found the row gone, or lost to concurrent writes sets no cookie;
/// the one exception is a failed rotation, whose cookie replaces the retired
/// id in the client's jar with one no row backs.
pub(crate) struct FinalizeOutcome {
    pub(crate) session: CookieSession,
    pub(crate) session_changed: bool,
    /// Set when a signed-in session's key was rotated and its row moved:
    /// the registry still holds the session under the key the request knows
    /// of, and the layer (when it has a registry) moves the entry.
    pub(crate) rotation: Option<Rotation>,
    /// The registry entries of a stored session this finish ended (a failed
    /// rotation, an ending a handler asked for): the layer removes them
    /// once the response is settled.
    pub(crate) released: Vec<Entry>,
}

/// A signed-in session (authenticated, or in a step-up of that session)
/// whose key changed during a request, and what the request knows of its
/// registry entry.
pub(crate) struct Rotation {
    pub(crate) user_id: crate::authn::ids::UserId,
    /// The tenant the session authenticated into and the administrator
    /// impersonating its user, if any: what the audit row of the session's
    /// ending names beside the user.
    pub(crate) tenant_id: crate::authn::ids::TenantId,
    pub(crate) impersonator: Option<crate::authn::ids::UserId>,
    /// The key the request arrived with: the row's key before the rotation.
    pub(crate) arrived: crate::session::id::SessionKey,
    /// The key the response cookie carries.
    pub(crate) new: crate::session::id::SessionKey,
    /// The key the registry holds the session under, when this request
    /// knows one for the user the response names.
    pub(crate) held: Option<crate::session::id::SessionKey>,
    /// The entry an impersonation stands on under its administrator, which
    /// goes when the settlement ends the session.
    pub(crate) anchor: Option<Entry>,
}

/// Extract + verify the session cookie, load the stored session (a row
/// below the current schema version is not served), check the binding
/// fingerprint, and mint a fresh id when any of those steps fails closed.
///
/// **Invariant:** the handler never runs under a client-supplied id we
/// do not trust the data behind. If the cookie verifies but the store
/// has no record (expired, evicted, attempted fixation), if the store
/// errors, or if the fingerprint mismatches, the load returns
/// `stored = false` and `session` is a freshly minted one: the
/// in-flight request executes under it, the response cycles to it.
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
        mut stored,
        data: mut session_data,
        loaded_row,
        session_ended,
    } = match verified {
        Some(verified) => load_stored_session(store, verified.session.key(), config, policy).await,
        None => StoredSession::fresh(),
    };

    let binding = check_binding(&mut session_data, fingerprints, policy);
    let binding_invalidated = binding.invalidated;
    if binding_invalidated {
        // The cookie's session is now untrusted; a fresh one is minted
        // below before the inner handler runs. Without this the
        // in-flight request would still execute under the
        // attacker-plantable id (the response cookie would only rotate
        // it on the way out).
        stored = false;
    }
    rotation_fallback_used |= binding.fingerprint_rewritten;

    // The cookie's session only for a row that is trusted. Every other
    // request (no cookie, no row, a row refused or distrusted) runs under a
    // session minted here, so nothing is ever stored under a name a client
    // chose.
    let session = match verified {
        Some(verified) if stored => verified.session,
        _ => CookieSession::mint(rng),
    };

    LoadOutcome {
        session,
        data: session_data,
        stored,
        binding_invalidated,
        rotation_fallback_used,
        session_ended,
        // A binding mismatch distrusts the row after it loaded.
        loaded_row: loaded_row.filter(|_| stored),
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
    /// Refuse it and end it: the registry says it is gone, or it outlived
    /// the absolute age cap. Carries the reason the audit sink is told.
    End(SessionEndReason),
    /// Refuse it for this request without touching the row: the registry
    /// could not answer and the policy fails closed.
    Distrust,
}

/// Apply the age caps and the registry to a stored session that is signed
/// in: an authenticated record, or one in a step-up, which is still the
/// signed-in session it began from and is checked as that session (the
/// registry entry of its user, its login's time, its impersonation). The
/// absolute cap counts from the login that created the session
/// (`signed_in_at`), which a step-up does not move.
/// A guest, a login in progress and a pending workflow are not checked: no
/// registry holds them yet.
async fn authenticated_session_verdict(
    data: &SessionData,
    config: &SessionConfig,
    policy: &LoadPolicy<'_>,
    key: &crate::session::id::SessionKey,
) -> SessionVerdict {
    let Some(crate::session::data::SignedIn {
        user_id,
        signed_in_at,
        impersonator,
        ..
    }) = data.auth_state.signed_in()
    else {
        return SessionVerdict::Keep;
    };
    let outlived = |cap: Option<std::time::Duration>, since: &axess_clock::Timestamp| {
        cap.and_then(|cap| axess_clock::SignedDuration::try_from(cap).ok())
            .is_some_and(|cap| policy.clock.now().since(*since) > cap)
    };
    if outlived(config.max_authenticated_age, signed_in_at) {
        tracing::info!("authenticated session outlived its absolute age cap; ending it");
        return SessionVerdict::End(SessionEndReason::AgeCap);
    }
    if let Some(crate::session::data::Impersonation { since, .. }) = impersonator
        && outlived(config.max_impersonation_age, since)
    {
        tracing::info!("impersonated session outlived the impersonation age cap; ending it");
        return SessionVerdict::End(SessionEndReason::ImpersonationAgeCap);
    }
    let Some(registry) = policy.registry else {
        return SessionVerdict::Keep;
    };
    let own = registry_verdict(
        registry.liveness(user_id, key).await,
        policy,
        SessionVerdict::End(SessionEndReason::NotRegistered),
    );
    let (SessionVerdict::Keep, Some(imp)) = (&own, impersonator) else {
        return own;
    };
    // An impersonation also stands on the administrator: the entry
    // `begin_impersonation` registered under them goes when their sessions
    // do (a suspension, a deletion, a forced logout).
    let anchor = imp.registry_anchor(user_id);
    let held = registry_verdict(
        registry.liveness(&imp.admin, &anchor).await,
        policy,
        SessionVerdict::End(SessionEndReason::ImpersonationNotRegistered),
    );
    if matches!(held, SessionVerdict::End(_)) {
        tracing::info!("the administrator of an impersonation no longer holds it; ending it");
    }
    held
}

/// What the registry's answer about one entry means for the session: `gone`
/// is the verdict when the registry no longer holds the entry.
fn registry_verdict(
    liveness: SessionLiveness,
    policy: &LoadPolicy<'_>,
    gone: SessionVerdict,
) -> SessionVerdict {
    match liveness {
        SessionLiveness::Valid => SessionVerdict::Keep,
        SessionLiveness::Gone => {
            tracing::info!("session is no longer held by the registry; ending it");
            gone
        }
        SessionLiveness::Unknown => match policy.unknown {
            crate::session::layer::UnknownLiveness::Reject => SessionVerdict::Distrust,
            crate::session::layer::UnknownLiveness::Accept => SessionVerdict::Keep,
        },
    }
}

pub(super) mod ending;
mod finalize;
mod load;
pub(crate) use ending::{Entry, ended_record, release_entries};
pub(crate) use load::load_current;
mod registry;

use load::{StoredSession, load_stored_session};

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
        && let Some(hv) = build_set_cookie(signing_keys, config, &outcome.session)
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
    session: &CookieSession,
) -> Option<axum::http::HeaderValue> {
    // Always sign new/re-issued cookies under the CURRENT sub-key.
    // Previous-key signing only exists on the verify side (fallback).
    let cookie_value = signing_keys.sign_cookie(session);

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

/// Direct unit tests on the `pub(crate)` lifecycle helpers that
/// `SessionService::call` composes. The Tower-service integration tests
/// don't reach the boolean and relational boundaries inside these
/// helpers, so each test here pins one of them by feeding the helper a
/// constructed input the real call site never produces.
#[cfg(test)]
mod helper_tests;

#[cfg(test)]
mod audit_support;
#[cfg(test)]
mod audit_tests;
#[cfg(test)]
mod ending_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod rotation_audit_tests;

#[cfg(test)]
mod concurrency_tests;

#[cfg(test)]
mod settle_tests;

#[cfg(test)]
mod step_up_tests;

#[cfg(test)]
mod stored_version_tests;

#[cfg(all(test, any(feature = "sqlite", feature = "sqlite-unbundled")))]
mod planted_row_tests;
