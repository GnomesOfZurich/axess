//! Tower middleware service that runs the per-request session lifecycle.
//!
//! [`SessionService`] is the concrete `tower::Service` constructed by
//! [`SessionLayer::layer`](super::SessionLayer). Its `call` method
//! coordinates the four lifecycle steps: load → device-resolve →
//! handler → finalize, then emits the response cookie.

#[cfg(feature = "device")]
use crate::device::resolver::{DeviceResolution, ErasedDeviceResolver};
use crate::session::binding::SessionBinding;
use crate::session::config::SessionConfig;
use crate::session::layer::SessionLayer;
#[cfg(feature = "device-keys")]
use crate::session::layer::device_keys;
use crate::session::layer::handle::{ConsumeTarget, SessionHandle, SessionInner};
use crate::session::layer::lifecycle::{
    FinalizeOutcome, Fingerprints, LoadPolicy, Reporting, UncheckedBinding, apply_session_cookie,
    finalize_session, load_session, release_entries, settle_registry,
};
use crate::session::layer::signing::SigningKeyRing;
use crate::session::store::SessionStore;
use axum::{body::Body, http::Request, response::Response};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::RwLock;
use tower::{Layer, Service};

/// Tower service wrapping an inner service with session management.
///
/// Returned by [`<SessionLayer as tower::Layer>::layer`](super::SessionLayer).
/// `pub` because the [`tower::Layer`] impl is on the public
/// `SessionLayer` and its `type Service = SessionService<…>`
/// associated type cannot be more private than the trait impl.
/// `#[doc(hidden)]` keeps the type out of rendered API docs;
/// adopters reach it only through the trait surface.
#[doc(hidden)]
#[derive(Clone)]
pub struct SessionService<S, Inner> {
    inner: Inner,
    store: S,
    signing_keys: Arc<SigningKeyRing>,
    /// Shared with [`SessionLayer`] via `Arc` to keep
    /// `Layer::layer` and per-request `Service::call` cloning cheap.
    config: Arc<SessionConfig>,
    binding: Option<Arc<dyn SessionBinding>>,
    metrics: Option<crate::metrics::MetricSinks>,
    rng: Arc<dyn axess_rng::SecureRng>,
    clock: Arc<dyn axess_clock::Clock>,
    registry: Option<Arc<dyn crate::session::store::SessionRegistryHandle>>,
    unknown_liveness: crate::session::layer::UnknownLiveness,
    audit: Arc<dyn crate::session::layer::SessionEndAudit>,
    websocket_origins: Arc<[Arc<str>]>,
    #[cfg(feature = "device")]
    device_resolver: Option<Arc<dyn ErasedDeviceResolver>>,
    /// `Some` when device keys are enforced.
    #[cfg(feature = "device-keys")]
    key_gate: Option<Arc<device_keys::KeyGate>>,
    /// What this layer does with a row bound to a device key that it cannot
    /// hold to the key.
    unchecked_binding: Arc<UncheckedBinding>,
}

/// Request extension marking a request that arrived without a session the
/// layer could trust, so the session it runs under is a fresh guest that
/// exists only in memory until something asks for it to be stored. The CSRF
/// layer reads it to avoid storing a session for traffic that never uses one.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FreshSession;

/// The binding fingerprint pair of a request, computed before the request is
/// moved. `(current, previous)`: `previous` is only `Some` when a rotation
/// window is active. The pair is threaded into `load_session` so verification
/// can fall back to the previous key and re-store the fingerprint under the
/// current key.
///
/// A request the binding yields no material for is bound to a fixed
/// value that stands for "no material": a session that logged in
/// without it stays bound to that, and a replay that does present
/// material fails the comparison instead of skipping it.
fn request_fingerprints(
    binding: Option<&dyn SessionBinding>,
    signing_keys: &SigningKeyRing,
    req: &Request<Body>,
) -> (Option<String>, Option<String>) {
    match binding {
        Some(binding) => {
            let material = binding
                .extract(req)
                .unwrap_or_else(|| crate::session::binding::NO_BINDING_MATERIAL.to_vec());
            let (curr, prev) = signing_keys.compute_binding_fingerprints(&material);
            (Some(curr), prev)
        }
        None => (None, None),
    }
}

/// Whether `req` may proceed past the WebSocket Origin rule: anything that is
/// not an upgrade, an upgrade from an allowed origin when there is an
/// allow-list, and otherwise an upgrade from the request's own host.
fn websocket_origin_admitted(req: &Request<Body>, allowed: &[Arc<str>], secure: bool) -> bool {
    use crate::middleware::csrf::{
        is_websocket_upgrade, origin_is_own_host, origin_matches_allowed,
    };
    if !is_websocket_upgrade(req) {
        return true;
    }
    if allowed.is_empty() {
        origin_is_own_host(req, secure)
    } else {
        origin_matches_allowed(req, allowed)
    }
}

impl<S, Inner> Layer<Inner> for SessionLayer<S>
where
    S: SessionStore + Clone,
{
    type Service = SessionService<S, Inner>;

    /// # Panics
    ///
    /// Panics when the configuration is invalid; see the `# Panics` section
    /// of [`SessionLayer`].
    fn layer(&self, inner: Inner) -> Self::Service {
        // The one place the whole configuration is checked: setters run in
        // any order, so only here can the combination be judged.
        let config = Arc::new((*self.config).clone().finalize());
        #[cfg(feature = "device-keys")]
        let session_ttl = config.ttl;
        // Keys are registered on, and sessions bound to, the device the
        // resolver proves: a key service without a resolver binds nothing.
        // One whose policy is `Off` needs none.
        #[cfg(feature = "device-keys")]
        if self.device_resolver.is_none()
            && self.device_keys.as_ref().is_some_and(|keys| {
                keys.config().policy() != crate::device_key::KeyBindingPolicy::Off
            })
        {
            tracing::error!(
                "this session layer was given a device-key service and no device resolver \
                 (SessionLayer::with_device_resolver): no device is ever proven, so no key is \
                 offered and no session is bound; under `Require` every session ends at the \
                 end of its registration window"
            );
        }
        SessionService {
            inner,
            store: self.store.clone(),
            signing_keys: self.signing_keys.clone(),
            config,
            clock: self.clock.clone(),
            registry: self.registry.clone(),
            unknown_liveness: self.unknown_liveness,
            audit: self.audit.clone(),
            websocket_origins: self.websocket_origins.clone(),
            binding: self.binding.clone(),
            metrics: self.metrics.clone(),
            rng: self.rng.clone(),
            #[cfg(feature = "device")]
            device_resolver: self.device_resolver.clone(),
            #[cfg(feature = "device-keys")]
            // A session the gate ends is ended as the load ends one: through
            // the same audit sink, its claim written for the session's TTL.
            key_gate: self.device_keys.clone().and_then(|keys| {
                let ending = device_keys::LayerEnding {
                    audit: self.audit.clone(),
                    ttl: session_ttl,
                    registry: self.registry.clone(),
                };
                let (ring, same_site) = (&self.signing_keys, self.config.same_site);
                device_keys::KeyGate::new(keys, ring, self.clock.clone(), same_site, ending)
            }),
            // A key service whose policy is `Off` is the one way to say that
            // bound sessions are served as bearer sessions.
            #[cfg(feature = "device-keys")]
            unchecked_binding: Arc::new(UncheckedBinding::new(match &self.device_keys {
                Some(_) => None,
                None => Some(
                    "this session layer was given no device-key service \
                     (SessionLayer::with_device_keys)",
                ),
            })),
            #[cfg(not(feature = "device-keys"))]
            unchecked_binding: Arc::new(UncheckedBinding::new(Some(
                "this build has no `device-keys` feature",
            ))),
        }
    }
}

impl<S, Inner> SessionService<S, Inner> {
    /// [`websocket_origin_admitted`] for this service's allow-list, logging
    /// a refusal and counting it on the request-guard sink.
    ///
    /// A WebSocket upgrade is a GET a browser sends with the session cookie
    /// from any site, so its Origin is checked before the session is read: a
    /// socket route outside the CSRF layer is covered too.
    fn websocket_admitted(&self, req: &Request<Body>) -> bool {
        let admitted = websocket_origin_admitted(req, &self.websocket_origins, self.config.secure);
        if !admitted {
            tracing::warn!(
                route = %crate::logged_route::logged_route(req.extensions()),
                "session: WebSocket upgrade refused, Origin is not an allowed origin or the \
                 request's own host"
            );
            if let Some(m) = &self.metrics {
                m.guard
                    .csrf_rejected(crate::metrics::CsrfRefusal::WebSocketOrigin);
            }
        }
        admitted
    }
}

/// An empty 403.
fn forbidden<B: Default>() -> Response<B> {
    let mut response = Response::new(B::default());
    *response.status_mut() = axum::http::StatusCode::FORBIDDEN;
    response
}

impl<S, Inner, ResBody> Service<Request<Body>> for SessionService<S, Inner>
where
    S: SessionStore + Clone + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
    Inner: Service<Request<Body>, Response = Response<ResBody>> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
    Inner::Error: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = Inner::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // The Origin of a WebSocket upgrade is checked before the session is read.
        if !self.websocket_admitted(&req) {
            return Box::pin(async { Ok(forbidden()) });
        }
        let store = self.store.clone();
        let config = self.config.clone();
        let signing_keys = self.signing_keys.clone();
        let session_binding = self.binding.clone();
        let metrics = self.metrics.clone();
        let (rng, clock) = (self.rng.clone(), self.clock.clone());
        let registry = self.registry.clone();
        let (unknown_liveness, audit) = (self.unknown_liveness, self.audit.clone());
        #[cfg(feature = "device")]
        let device_resolver = self.device_resolver.clone();
        #[cfg(feature = "device-keys")]
        let key_gate = self.key_gate.clone();
        let unchecked = self.unchecked_binding.clone();

        // Clone inner *before* the async block; required by tower's contract.
        let mut inner = self.inner.clone();
        std::mem::swap(&mut inner, &mut self.inner);

        let (current_fingerprint, previous_fingerprint) =
            request_fingerprints(session_binding.as_deref(), &signing_keys, &req);

        Box::pin(async move {
            // 1. Load session; cookie verify, store load, fingerprint check, fresh-mint.
            let load = load_session(
                &store,
                &signing_keys,
                &config,
                req.headers(),
                Fingerprints {
                    current: current_fingerprint.as_deref(),
                    previous: previous_fingerprint.as_deref(),
                },
                &*rng,
                &LoadPolicy {
                    registry: registry.as_deref(),
                    unknown: unknown_liveness,
                    clock: &*clock,
                    metrics: metrics.as_ref(),
                    audit: &audit,
                },
            )
            .await;

            // 1b. Hold the session to its device key (see `device_keys`).
            #[cfg(feature = "device-keys")]
            let load = device_keys::admit(key_gate.as_ref(), load, &mut req, &store, &*rng).await;
            let load = load.refuse_unchecked_binding(&unchecked, &*rng);

            // 1c. Resolve the device (best-effort; see `resolve_device`). The
            //     session is modified iff the resolved id differs from the loaded.
            #[cfg(feature = "device")]
            let (load, device_changed, device_cookie) = {
                let resolved = resolve_device(load, req, device_resolver).await;
                req = resolved.request;
                (resolved.load, resolved.changed, resolved.cookie)
            };
            #[cfg(not(feature = "device"))]
            let device_changed = false;

            // 2. Insert SessionHandle into request extensions. With a binding and no
            //    fingerprint on the session yet, pass the pre-computed one so the
            //    extractor applies it when the session becomes Authenticated.
            let pending_fp = if session_binding.is_some() && load.data.fingerprint.is_none() {
                current_fingerprint.clone()
            } else {
                None
            };

            let stored = load.stored;
            #[cfg(feature = "device-keys")]
            let due = device_keys::OfferDue::before(&load.data, device_changed);
            let inner_state = seed_session_state(
                load,
                (device_changed, registry.is_some()),
                pending_fp,
                &config,
                rng.clone(),
                Arc::new(store.clone()),
            );
            let handle = SessionHandle(Arc::new(RwLock::new(inner_state)));
            req.extensions_mut().insert(handle.clone());
            if !stored {
                req.extensions_mut().insert(FreshSession);
            }

            // 3. Call the inner service. The finalize is owed to the session
            //    whatever becomes of this future (see `FinishGuard`).
            let finish = Finish {
                store,
                config: config.clone(),
                metrics,
                clock,
                rng,
                registry,
                unknown_liveness,
                audit,
                handle: handle.clone(),
                stored,
                #[cfg(feature = "device-keys")]
                key_binding: key_gate.clone(),
            };
            let mut owed = FinishGuard(Some(finish));
            let response = inner.call(req).await;
            let Some(finish) = owed.0.take() else {
                return response;
            };
            let mut response = match response {
                Ok(response) => response,
                // The guard is gone, so run the finish here, and wait for it,
                // before returning the handler's error: the session is stored
                // by the time the caller sees it. An error carries no
                // headers, so a cookie this request issued (a new device
                // token) cannot ride it; the next request is issued one
                // again.
                Err(error) => {
                    finish_in_task(finish, &handle).await;
                    return Err(error);
                }
            };

            // 4 + 5. Finalize in a task of its own; set the cookie only when it changed.
            let (outcome, registered) = finish_in_task(finish, &handle).await;
            apply_session_cookie(
                &signing_keys,
                &config,
                &outcome,
                registered,
                response.headers_mut(),
            );
            #[cfg(feature = "device-keys")]
            device_keys::offer(key_gate.as_deref(), &handle, &outcome, due, &mut response).await;

            // A device token issued by this request reaches the browser in
            // its own cookie.
            #[cfg(feature = "device")]
            if let Some(cookie) = device_cookie {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, cookie);
                crate::session::layer::lifecycle::mark_cookie_response(response.headers_mut());
            }

            Ok(response)
        })
    }
}

/// The in-memory session state a request starts from, built from what the
/// load found. `rotation_fallback_used` is folded into `modified` so the
/// finalize path persists the re-signed fingerprint and re-issues the cookie
/// under the current key. A device found for a session that has no stored
/// row yet is carried in memory and persisted only when something else saves
/// the session, so a cookieless request stores nothing.
///
/// The registry entry the request knows of is the one the loaded row stands
/// for: a signed-in row is registered under the key the request arrived
/// with. `layer_moves_registry` says whether this layer has a registry.
fn seed_session_state<S>(
    load: crate::session::layer::lifecycle::LoadOutcome,
    (device_changed, layer_moves_registry): (bool, bool),
    pending_fingerprint: Option<String>,
    config: &SessionConfig,
    rng: Arc<dyn axess_rng::SecureRng>,
    store: Arc<S>,
) -> SessionInner
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
{
    let row_stored = load.stored;
    // The state as loaded is the state the device resolver ran on.
    let device_resolved_for = load.data.auth_state.person_at_browser();
    let registered = load
        .loaded_row
        .as_ref()
        .and_then(|row| row.auth_state.signed_in())
        .map(|signed_in| (*signed_in.user_id, *load.session.key()));
    SessionInner {
        session: load.session,
        data: load.data,
        device_resolved_for,
        modified: load.binding_invalidated
            || (device_changed && row_stored)
            || load.rotation_fallback_used
            || load.session_ended,
        needs_persist: false,
        regenerate: load.binding_invalidated,
        pre_cycle: None,
        pending_fingerprint,
        max_custom_bytes: config.max_custom_bytes,
        rng,
        consume: Some(ConsumeTarget {
            store,
            ttl: config.ttl,
            loaded: load.loaded_row,
        }),
        registered,
        layer_moves_registry,
        owed_ending: None,
    }
}

/// What [`resolve_device`] hands back.
#[cfg(feature = "device")]
struct ResolvedDevice {
    load: crate::session::layer::lifecycle::LoadOutcome,
    /// The resolved id differs from the loaded one.
    changed: bool,
    request: Request<Body>,
    /// The `Set-Cookie` of a device token this request was issued.
    cookie: Option<axum::http::HeaderValue>,
}

/// Run the owed [`Finish`] in a task of its own, so that dropping the caller
/// cannot cut it short.
async fn finish_in_task<S>(finish: Finish<S>, handle: &SessionHandle) -> (FinalizeOutcome, bool)
where
    S: SessionStore + Clone + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
{
    match tokio::spawn(finish.run()).await {
        Ok(settled) => settled,
        Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
        Err(_) => {
            // The runtime is shutting down: nothing was settled, so no cookie
            // is set for a session that may not be stored.
            let session = handle.0.read().await.session;
            (
                FinalizeOutcome {
                    session,
                    session_changed: false,
                    rotation: None,
                    released: Vec::new(),
                },
                false,
            )
        }
    }
}

/// Everything that must still run after the handler of a request: the
/// session's write to the store and the move of its registry entry.
struct Finish<S> {
    store: S,
    config: Arc<SessionConfig>,
    metrics: Option<crate::metrics::MetricSinks>,
    clock: Arc<dyn axess_clock::Clock>,
    rng: Arc<dyn axess_rng::SecureRng>,
    registry: Option<Arc<dyn crate::session::store::SessionRegistryHandle>>,
    unknown_liveness: crate::session::layer::UnknownLiveness,
    /// Told of a session the finish ends (a rotation the registry cannot
    /// track, or one the store cannot make) before its row is removed.
    audit: Arc<dyn crate::session::layer::SessionEndAudit>,
    handle: SessionHandle,
    /// The request ran under a stored session the load trusted.
    stored: bool,
    /// The key gate, when device keys are enforced.
    #[cfg(feature = "device-keys")]
    key_binding: Option<Arc<device_keys::KeyGate>>,
}

impl<S> Finish<S>
where
    S: SessionStore + Clone + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
{
    async fn run(self) -> (FinalizeOutcome, bool) {
        // A fresh session on a request that proved its device by key is
        // bound to the key, in the write that follows. The binding this
        // request made, here or at the registration path, is noted before
        // the write, and its row waits for the write to land.
        #[cfg(feature = "device-keys")]
        let added = match &self.key_binding {
            Some(gate) => {
                device_keys::bind_after_handler(gate, &self.handle).await;
                device_keys::added_binding(&self.handle).await
            }
            None => None,
        };
        let outcome = finalize_session(
            &self.store,
            &self.config,
            Reporting {
                metrics: self.metrics.as_ref(),
                audit: &*self.audit,
            },
            &*self.clock,
            &self.handle,
            self.stored,
            &*self.rng,
        )
        .await;
        #[cfg(feature = "device-keys")]
        if let (Some(gate), Some(added)) = (&self.key_binding, added) {
            device_keys::record_binding(gate, &self.handle, &outcome, added).await;
        }
        let registered = settle_registry(
            &self.store,
            self.registry.as_deref(),
            (self.unknown_liveness, &*self.audit),
            (self.clock.now(), self.config.ttl),
            &outcome,
        )
        .await;
        // A session that ended leaves the registry, as a last step that
        // cannot undo the ending: the entries of a stored session this finish
        // ended, and the entry the request knew of when the response does
        // not leave the session signed in as that entry's user (a sign-out,
        // another person's sign-in, an ending a handler asked for).
        let mut released = outcome.released.clone();
        {
            let guard = self.handle.0.read().await;
            if let Some((user, key)) = guard.registered
                && guard
                    .data
                    .auth_state
                    .signed_in()
                    .map(|signed_in| *signed_in.user_id)
                    != Some(user)
            {
                released.push((user, key));
            }
        }
        release_entries(self.registry.as_deref(), &released).await;
        (outcome, registered)
    }
}

/// Runs the owed [`Finish`] in a task of its own when the request future is
/// dropped before the handler returned.
struct FinishGuard<S>(Option<Finish<S>>)
where
    S: SessionStore + Clone + Send + Sync + 'static,
    S::Error: Send + Sync + 'static;

impl<S> Drop for FinishGuard<S>
where
    S: SessionStore + Clone + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
{
    fn drop(&mut self) {
        let Some(finish) = self.0.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(finish.run());
            }
            Err(_) => tracing::error!(
                "a request was dropped outside a runtime; its session was not finalized"
            ),
        }
    }
}

/// Resolve the device for a request and stamp it on the loaded session.
///
/// `Err(_)` from the resolver is logged by the erasure wrapper and leaves a
/// signed-in session's device as it was; with nobody signed in, it and an
/// absent resolver clear it (see `forget_device_held_for_nobody`).
/// `axum::body::Body` is `!Sync`, so `&Request<Body>` cannot be
/// borrowed across an `await`: the request is split into `(Parts, Body)`, the
/// resolver runs against the parts, and the request is reassembled. Reports
/// whether the resolved id differs from the loaded one, so an unchanged
/// device on a stable session does not trigger a save on every request.
#[cfg(feature = "device")]
async fn resolve_device(
    mut load: crate::session::layer::lifecycle::LoadOutcome,
    req: Request<Body>,
    resolver: Option<Arc<dyn ErasedDeviceResolver>>,
) -> ResolvedDevice {
    let Some(resolver) = resolver else {
        return ResolvedDevice {
            changed: forget_device_held_for_nobody(&mut load.data),
            load,
            request: req,
            cookie: None,
        };
    };
    let (mut parts, body) = req.into_parts();
    // Hand the resolver the person at the browser, so a device is matched
    // to its owner: the signed-in user, and under impersonation the
    // administrator, whose browser it is. A session in a step-up is still
    // that signed-in session and supplies the same, so its device, and a
    // bound key's proof of it, carry through the step. A guest, or a
    // session part-way through a login, supplies none: its claimed user is
    // not verified.
    if let Some(owner) = load.data.auth_state.person_at_browser() {
        parts.extensions.insert(crate::device::SessionUser(owner));
        // The tenant the session logged in under, for a resolver whose
        // tenant is a property of the user rather than of the request.
        if let Some(tenant) = load.data.auth_state.tenant_id() {
            parts
                .extensions
                .insert(crate::device::SessionTenant(*tenant));
        }
        // The device the session was last bound to, for a request that
        // presents no device token.
        if let Some(device) = load.data.device_id {
            parts
                .extensions
                .insert(crate::device::SessionDevice(device));
        }
    }
    let slot = crate::device::DeviceCookieSlot::default();
    parts.extensions.insert(slot.clone());
    let resolution = resolver.resolve_erased(&parts).await;
    parts.extensions.remove::<crate::device::DeviceCookieSlot>();
    let request = Request::from_parts(parts, body);
    // Whether the device was proven is this request's answer and is never
    // stored: only the device's id is, so a session that is recognised on
    // one request and proven on the next is not rewritten for it. A resolver
    // that failed said nothing about the device: a signed-in session keeps
    // the one it was bound to and is not rewritten for it, a session with
    // nobody signed in keeps none, and it stays unproven, as
    // every loaded row is until a resolver answers (the load clears what a
    // store kept).
    let changed = match resolution {
        DeviceResolution::Resolved(resolved) => {
            let id = resolved.map(|b| b.id());
            // A bound session whose key this request proved has its bound
            // device proven by that key, whether or not the request also
            // presented the device's token.
            let bound_key = load
                .data
                .key_binding_in_force()
                .copied()
                .filter(|binding| load.data.key_proven && id == Some(binding.device_id))
                .and_then(|binding| {
                    request
                        .extensions()
                        .get::<crate::device_key::KeyCheck>()
                        .and_then(|check| check.for_device(&binding.tenant_id, &binding.device_id))
                        .copied()
                });
            load.data.device_proven =
                matches!(resolved, Some(crate::device::BoundDevice::Proven(_)))
                    || bound_key.is_some();
            // The proven key as the layer verified it, tenant included: a
            // resolver's word for a key the request's own check did not
            // prove is not taken.
            load.data.device_key = match resolved {
                Some(crate::device::BoundDevice::Proven(proven)) => match proven.proof() {
                    crate::device_key::DeviceProof::Key(thumbprint) => request
                        .extensions()
                        .get::<crate::device_key::KeyCheck>()
                        .and_then(|check| check.key_of(&proven.id(), &thumbprint)),
                    crate::device_key::DeviceProof::Token => None,
                },
                _ => None,
            }
            .or(bound_key);
            let changed = id != load.data.device_id;
            if changed {
                load.data.device_id = id;
            }
            changed
        }
        DeviceResolution::Failed => forget_device_held_for_nobody(&mut load.data),
    };
    ResolvedDevice {
        load,
        changed,
        request,
        cookie: slot.take(),
    }
}

/// On a request that resolved nothing, a device the loaded row names holds
/// only while somebody is signed in, for whom it was resolved. With nobody
/// at the browser it was stamped on an earlier request, for the user that
/// request's login named, and this request may complete another person's
/// login: it is cleared, never a hint. Says whether it cleared one.
#[cfg(feature = "device")]
fn forget_device_held_for_nobody(data: &mut crate::session::SessionData) -> bool {
    data.auth_state.person_at_browser().is_none() && data.device_id.take().is_some()
}
