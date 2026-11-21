//! Device keys in the session layer: what a request must prove, the offer a
//! response carries, and the two paths a key is registered and proven at.
//!
//! The order per request, for a layer given a key service whose policy is
//! not `Off`:
//!
//! 1. [`admit`] reads the request's proof cookies. A session that is bound
//!    and is not met by one of them does not run: the request is a fresh
//!    guest and the row is left alone. Under `Require`, a signed-in session
//!    that is not bound and whose window has passed is ended, through the
//!    layer's ending protocol.
//! 2. The device resolver runs with what was proven
//!    ([`KeyCheck`](crate::device_key::KeyCheck)).
//! 3. After the handler, [`bind_after_handler`] binds a session that is
//!    inside its registration window on a request that proved its device by
//!    key, and [`offer`] adds the registration offer when the session has
//!    just signed in, or just been given its device, on a device that has
//!    no key.
//! 4. Once the write that stores a binding this request made has landed,
//!    [`record_binding`] writes its `SessionKeyBound` row.
//!
//! Every step reads the session through one view, the signed-in one
//! ([`SignedIn`](crate::session::data::SignedIn)): an authenticated
//! session, or one in a step-up of it, which is still that session. The
//! registration window runs from its `signed_in_at`, the time its login
//! completed, for all of them: a step-up, an impersonation and an id
//! rotation keep that time, so none of them pauses, restarts or extends the
//! window. A guest, a login in progress and a pending workflow are not
//! signed in, and no step holds, binds or offers anything to them.

use std::sync::Arc;

use axess_clock::Clock;
use axess_clock::Timestamp;
use axess_factors::key_proof::browser_draft as draft;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use cookie::{Cookie, SameSite, time};

use super::audit::{SessionEndAudit, SessionEndReason};
use super::handle::SessionHandle;
use super::lifecycle::ending::{Ended, Ending, StoredEnding, ended_record};
use super::lifecycle::{FinalizeOutcome, LoadOutcome};
use super::signing::SigningKeyRing;
use crate::authn::event::{AuthEventBuilder, AuthEventType};
use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device_key::cookie::{self as key_cookie, KeyCookieKeys};
use crate::device_key::erased::{ErasedDeviceKeys, Registration};
use crate::device_key::{
    DeviceKeyError, KeyBindingPolicy, KeyChallenge, KeyCheck, KeyProof, KeyProofShape,
    KeyThumbprint, ProvenKey, RequestHead, RequestProof, RequestProofSender, SessionKeyBinding,
    SignedKeyRequest,
};
use crate::session::data::{AuthState, SessionData};
use crate::session::extractor::AuthSession;
use crate::session::store::SessionStore;

/// The request header an app's proof arrives in (RFC 9449).
const APP_PROOF_HEADER: &str = "dpop";
/// The response header an app's challenge is handed out in (RFC 9449).
const APP_CHALLENGE_HEADER: &str = "dpop-nonce";

/// What the layer needs to enforce device keys, built once per service.
pub(crate) struct KeyGate {
    keys: Arc<dyn ErasedDeviceKeys>,
    cookie_keys: KeyCookieKeys,
    clock: Arc<dyn Clock>,
    same_site: SameSite,
    /// How [`admit`] ends a session, as the layer ends every other.
    ending: LayerEnding,
}

/// What the layer's ending protocol needs to end a session [`admit`]
/// judged: the audit sink the layer tells of every session it ends (the
/// one its load is given), and the lifetime the claim on the row is written
/// with (the session's).
pub(crate) struct LayerEnding {
    pub(crate) audit: Arc<dyn SessionEndAudit>,
    pub(crate) ttl: std::time::Duration,
    /// The layer's registry, which loses the entry of a session the gate
    /// ended.
    pub(crate) registry: Option<Arc<dyn crate::session::store::SessionRegistryHandle>>,
}

impl KeyGate {
    /// `None` when the policy is `Off`: the layer then does nothing about
    /// keys and serves bound rows as bearer sessions.
    pub(crate) fn new(
        keys: Arc<dyn ErasedDeviceKeys>,
        ring: &SigningKeyRing,
        clock: Arc<dyn Clock>,
        same_site: SameSite,
        ending: LayerEnding,
    ) -> Option<Arc<Self>> {
        if keys.config().policy() == KeyBindingPolicy::Off {
            return None;
        }
        Some(Arc::new(Self {
            cookie_keys: ring.device_key_cookie_keys(),
            keys,
            clock,
            same_site,
            ending,
        }))
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Whether a session whose login completed at `signed_in_at` is inside
    /// its registration window at `now`, the window's end included. The
    /// window starts at the login and at nothing later, so what keeps
    /// `signed_in_at` (a step-up, an impersonation, an id rotation) neither
    /// pauses nor restarts it.
    fn in_window(&self, signed_in_at: Timestamp, now: Timestamp) -> bool {
        window_holds(signed_in_at, self.keys.config().registration_window(), now)
    }

    fn is_key_path(&self, req: &Request<Body>) -> bool {
        let config = self.keys.config();
        req.method() == axum::http::Method::POST
            && (req.uri().path() == config.registration_path()
                || req.uri().path() == config.refresh_path())
    }
}

/// Whether `now` is inside a registration `window` that opened at
/// `signed_in_at`, the window's end included.
///
/// The end is the one the offer cookie carries
/// ([`Until::after`](axess_clock::Until::after)): a window too long to hold
/// never ends, here as there.
fn window_holds(signed_in_at: Timestamp, window: std::time::Duration, now: Timestamp) -> bool {
    axess_clock::Until::At(now) <= axess_clock::Until::after(signed_in_at, window)
}

/// Step 1: judge the loaded session against what the request proved, and
/// leave the proof for the resolver and the key routes.
///
/// Returns the session the request runs as. Without a gate the layer
/// enforces no keys and the session is returned as it was loaded.
pub(crate) async fn admit<S>(
    gate: Option<&Arc<KeyGate>>,
    mut load: LoadOutcome,
    req: &mut Request<Body>,
    store: &S,
    rng: &dyn axess_rng::SecureRng,
) -> LoadOutcome
where
    S: SessionStore,
    S::Error: std::fmt::Display,
{
    let Some(gate) = gate else {
        return load;
    };
    let config = gate.keys.config();
    let now = gate.now();
    let grace = config.acceptance_grace();
    let mut proven = key_cookie::read_proofs(
        &gate.cookie_keys,
        req.headers(),
        config.proof_cookie_name(),
        now,
        grace,
    );
    // Owned parts only cross the await: a borrow of the request would not
    // be `Send`.
    if let Some(riding) = RidingProof::of(gate, &load.data, req) {
        let proof = RequestProof {
            jws: &riding.jws,
            method: &riding.method,
            url: &riding.url,
        };
        if let Some(key) = gate
            .keys
            .request_proof(&riding.tenant, &riding.device, riding.sender, proof, now)
            .await
            && !proven.contains(&key)
        {
            proven.push(key);
        }
    }

    // The layer's own verdict, kept for the request: whether this request
    // proved the key the session is bound to. It does not depend on the
    // device resolver or on the device token being presented.
    // A binding made for another person than the one at the session's
    // browser binds nothing: such a session is judged as an unbound one.
    let binding = load.data.key_binding_in_force().copied();
    load.data.key_proven =
        binding.is_some_and(|binding| proven.iter().any(|key| binding.is_met_by(key)));
    if binding.is_some() && !load.data.key_proven {
        // Bound, and this request did not prove the key: it does not run as
        // the session. The row stays, for the client that holds the key.
        tracing::debug!("a bound session's request carried no valid key proof; serving a guest");
        gate.keys.metrics().bound_session_unproven();
        load = LoadOutcome::guest(rng, false);
    } else if config.policy() == KeyBindingPolicy::Require
        && binding.is_none()
        && let Some(signed_in) = load.data.auth_state.signed_in()
        && !gate.in_window(*signed_in.signed_in_at, now)
    {
        // Signed in (authenticated, or in a step-up of that session), not
        // bound, and its window is over: the session ends. A login in
        // progress and a guest have no window yet and are not held.
        load = end_unbound(gate, load, store, now, rng).await;
    }

    if gate.is_key_path(req) {
        req.extensions_mut().insert(SignedKeyRequest);
    }
    req.extensions_mut().insert(KeyCheck::new(proven));
    req.extensions_mut().insert(gate.clone());
    load
}

/// End a signed-in session that outlived its registration window unbound,
/// as the layer ends every session it ends by itself: claimed with a
/// compare-and-swap on the row the load read, recorded through the layer's
/// audit sink (naming the administrator for an impersonation), then
/// removed, in a task of its own ([`StoredEnding`]).
///
/// The request runs as a fresh guest whatever becomes of the ending. Only
/// the request that ended the session has its cookie replaced and counts
/// the ending. One whose claim lost (another request carrying the cookie
/// is ending it) or whose audit row could not be written leaves the row
/// stored; the next request that presents it is judged again, and a claim
/// left behind is finished by the load for this reason.
async fn end_unbound<S>(
    gate: &KeyGate,
    load: LoadOutcome,
    store: &S,
    now: Timestamp,
    rng: &dyn axess_rng::SecureRng,
) -> LoadOutcome
where
    S: SessionStore,
    S::Error: std::fmt::Display,
{
    // The judgement read the loaded state; the claim and the record are of
    // the row as the store holds it, which a signed-in state came from.
    let session = load.session;
    let ended = load.loaded_row.filter(|_| load.stored).and_then(|row| {
        let ended = ended_record(&row, *session.key(), SessionEndReason::KeyBindingRequired)?;
        Some((row, ended))
    });
    let Some((row, ended)) = ended else {
        // No stored row stands behind the state: nothing to end, and
        // nothing to serve.
        return LoadOutcome::guest(rng, false);
    };
    let entries = super::lifecycle::ending::entries_left(&row, *session.key());
    tracing::info!("an unbound session outlived the registration window; ending it");
    let stored = StoredEnding {
        store: store.clone(),
        audit: gate.ending.audit.clone(),
        what: Ending {
            row,
            ended,
            now,
            ttl: gate.ending.ttl,
            resumed: false,
        },
    };
    match stored.run_detached().await {
        Ended::Done => {
            gate.keys.metrics().unbound_session_ended();
            super::lifecycle::release_entries(gate.ending.registry.as_deref(), &entries).await;
            LoadOutcome::guest(rng, true)
        }
        Ended::Deferred => LoadOutcome::guest(rng, false),
    }
}

/// A proof riding on an ordinary request, as owned parts, with the device
/// it is for: the device a bound session is bound to, and for any other
/// request the one the identifier header names. Off the two key paths, whose
/// own proofs answer challenges.
struct RidingProof {
    tenant: TenantId,
    device: DeviceId,
    /// What the request has shown besides the proof.
    sender: RequestProofSender,
    jws: String,
    method: String,
    url: String,
}

impl RidingProof {
    fn of(gate: &KeyGate, data: &SessionData, req: &Request<Body>) -> Option<Self> {
        if !gate.keys.takes_request_proofs() || gate.is_key_path(req) {
            return None;
        }
        let jws = req
            .headers()
            .get(APP_PROOF_HEADER)?
            .to_str()
            .ok()?
            .to_owned();
        let binding = data.key_binding_in_force();
        let (tenant, device) = match binding {
            Some(binding) => (binding.tenant_id, binding.device_id),
            None => paths::named_device(req.headers())?,
        };
        // The URL as the server knows it: the origin it serves the request's
        // host at, and the path; a host it does not serve has no proofs.
        let origin = gate.keys.config().origin_for(RequestHead::of(req))?;
        Some(Self {
            tenant,
            device,
            sender: match binding {
                Some(_) => RequestProofSender::BoundSession,
                None => RequestProofSender::Unbound,
            },
            jws,
            method: req.method().as_str().to_owned(),
            url: format!("{origin}{}", req.uri().path()),
        })
    }
}

/// Step 3a: a signed-in session that is not bound, inside its registration
/// window, on a request that proved a device by key, is bound to that key
/// in the write that follows, when the device is the signed-in person's.
///
/// The window is the one a registration has, counted from the login: it
/// covers the request that completes the login and the requests soon after
/// it, a step-up's among them. The binding's `SessionKeyBound` row is
/// written by [`record_binding`] once the write has stored it.
///
/// The request that completes a sign-in resolved its device before anyone
/// was signed in, so the device it proved may be another account's (a
/// browser profile two accounts share). The session is bound only when the
/// device's row is owned by the user now authenticated, or has no owner and
/// is claimed for that user by the store's conditional write; and only
/// when the tenant the proof names is the session's. Otherwise the session
/// stays unbound: the next request resolves the user's own device and binds
/// to it, or is offered a registration.
///
/// Under impersonation the browser, and so the device, is the
/// administrator's: the owner the device must have, or is claimed for, is
/// the administrator, never the user the session runs as.
pub(crate) async fn bind_after_handler(gate: &KeyGate, handle: &SessionHandle) {
    let now = gate.now();
    let (user_id, admin, proven) = {
        let inner = handle.0.read().await;
        let Some(signed_in) = inner.data.auth_state.signed_in() else {
            return;
        };
        // A binding made for another person does not stand in the way:
        // only one in force for the person signed in now does.
        let (Some(device_id), Some(proven), true, None) = (
            inner.device_in_force(),
            inner.data.device_key,
            inner.data.device_proven && gate.in_window(*signed_in.signed_in_at, now),
            inner.data.key_binding_in_force(),
        ) else {
            return;
        };
        if proven.device != device_id || proven.tenant != *signed_in.tenant_id {
            tracing::debug!("the proven key names another tenant or device; not binding");
            return;
        }
        (
            *signed_in.user_id,
            signed_in.impersonator.map(|by| by.admin),
            proven,
        )
    };
    let owner = admin.unwrap_or(user_id);
    // A store read and, for an unowned device, one conditional write: not
    // under the session's lock.
    if !gate.keys.claim_for_binding(&proven, &owner, now).await {
        tracing::debug!("the proven device is not the signed-in person's; not binding");
        return;
    }
    let mut inner = handle.0.write().await;
    // The handler is done; what it left is what is bound. A session the
    // lock shows changed since the read above is left alone.
    let still = inner.data.auth_state.signed_in().is_some_and(|signed_in| {
        *signed_in.user_id == user_id
            && *signed_in.tenant_id == proven.tenant
            && signed_in.impersonator.map(|by| by.admin) == admin
    }) && inner.data.key_binding_in_force().is_none();
    if !still {
        return;
    }
    inner.data.key_binding = Some(SessionKeyBinding {
        owner,
        tenant_id: proven.tenant,
        device_id: proven.device,
        thumbprint: proven.thumbprint,
        bound_at: now,
    });
    inner.modified = true;
}

/// The binding this request gave the session: the one the session holds
/// now that the row as the request last saw it stored did not. Read before
/// the write, so that the binding's row can wait for the write
/// ([`record_binding`]).
pub(crate) async fn added_binding(handle: &SessionHandle) -> Option<SessionKeyBinding> {
    let inner = handle.0.read().await;
    let stored = inner
        .consume
        .as_ref()
        .and_then(|target| target.loaded.as_ref())
        .and_then(|row| row.key_binding);
    inner
        .data
        .key_binding_in_force()
        .copied()
        .filter(|binding| stored != Some(*binding))
}

/// Step 4: write the `SessionKeyBound` row of a binding this request made
/// (`added`), once the write that stores it has landed.
///
/// The row says the session is bound, so it is written only when it is
/// true: the response's write stored the session, and the session as
/// written holds this very binding. A write that found the row ended, lost
/// to concurrent writes, failed, or failed a rotation stores no binding,
/// and no row is written for it. The row names the session by the id it is
/// stored under after the write, the signed-in user, the administrator as
/// actor for an impersonation, and the binding's tenant, device and time.
pub(crate) async fn record_binding(
    gate: &KeyGate,
    handle: &SessionHandle,
    finalized: &FinalizeOutcome,
    added: SessionKeyBinding,
) {
    let event = {
        let inner = handle.0.read().await;
        if !finalized.session_changed || inner.data.key_binding_in_force() != Some(&added) {
            tracing::debug!("the write that was to store a binding did not land; no row for it");
            return;
        }
        let Some(signed_in) = inner.data.auth_state.signed_in() else {
            return;
        };
        bound_event(
            signed_in.user_id,
            signed_in.impersonator.map(|by| by.admin),
            &added.tenant_id,
        )
        .with_session(*finalized.session.key())
        .with_device(added.device_id)
        .build_at(added.bound_at)
    };
    gate.keys.emit(event).await;
}

/// The row of a session bound to a key: the session's user, and the
/// administrator as actor when the session is an impersonation.
fn bound_event(user: &UserId, admin: Option<UserId>, tenant: &TenantId) -> AuthEventBuilder {
    let event =
        AuthEventBuilder::success(AuthEventType::SessionKeyBound).attributed_to(user, tenant);
    match admin {
        Some(admin) => event.with_actor(admin),
        None => event,
    }
}

/// When the session's login completed, if it is signed in.
fn signed_in_at_of(state: &AuthState) -> Option<Timestamp> {
    state.signed_in().map(|signed_in| *signed_in.signed_in_at)
}

/// What a request was before its handler ran, for deciding whether its
/// response is the one that carries the registration offer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OfferDue {
    /// When the session's login completed, as the request found it.
    signed_in_at_before: Option<Timestamp>,
    /// Whether this request gave the session a device it did not have.
    device_changed: bool,
}

impl OfferDue {
    /// From the session as the request found it, before the handler ran.
    pub(crate) fn before(data: &SessionData, device_changed: bool) -> Self {
        Self {
            signed_in_at_before: signed_in_at_of(&data.auth_state),
            device_changed,
        }
    }
}

/// Step 3b: offer a registration, once, to a session that has just signed
/// in, on a device that was proven by its token, which under enforcement
/// means the device has no key.
///
/// The offer rides on one response per login: the response of the request
/// on which the session came to hold both its login and its device, which
/// is the request that completed the login when the device was already
/// known, and otherwise the request that gave the session its device. Every
/// later response inside the window carries none, so presenting the
/// session and device cookies again does not fetch it. A step-up, begun or
/// finished, keeps the login's time and is offered nothing: the window it
/// would offer into is the login's, already offered. The offer expires with
/// the window, at the login's time plus the window.
pub(crate) async fn offer<B>(
    gate: Option<&KeyGate>,
    handle: &SessionHandle,
    finalized: &FinalizeOutcome,
    due: OfferDue,
    response: &mut axum::http::Response<B>,
) {
    let Some(gate) = gate else {
        return;
    };
    let headers = response.headers_mut();
    let session = *finalized.session.key();
    let inner = handle.0.read().await;
    let Some(signed_in) = inner.data.auth_state.signed_in() else {
        return;
    };
    let signed_in_at = *signed_in.signed_in_at;
    if !due.device_changed && due.signed_in_at_before == Some(signed_in_at) {
        return;
    }
    let now = gate.now();
    let (Some(device), true, None) = (
        inner.device_in_force(),
        inner.data.device_proven && gate.in_window(signed_in_at, now),
        inner.data.device_key,
    ) else {
        return;
    };
    // The response to a registration: the session is bound to this very
    // device, which therefore has its key.
    if inner
        .data
        .key_binding_in_force()
        .is_some_and(|binding| binding.device_id == device)
    {
        return;
    }
    let config = gate.keys.config();
    let expires = axess_clock::Until::after(signed_in_at, config.registration_window());
    let offer = key_cookie::mint_offer(
        &gate.cookie_keys,
        &session,
        signed_in.tenant_id,
        &device,
        expires,
    );
    let value = draft::registration_header_value(
        axess_factors::key_proof::KEY_PROOF_ALG,
        config.registration_path(),
        &offer,
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        headers.insert(HeaderName::from_static(draft::REGISTRATION_HEADER), value);
        // The offer is for this client alone: no cache keeps the response.
        super::lifecycle::mark_cookie_response(headers);
        gate.keys.metrics().key_offered();
    }
}

mod paths;
#[cfg(any(test, feature = "testing"))]
pub(crate) use paths::named_device;
pub(crate) use paths::routes;
