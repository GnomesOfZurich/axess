//! Tower middleware service that runs the per-request session lifecycle.
//!
//! [`SessionService`] is the concrete `tower::Service` constructed by
//! [`SessionLayer::layer`](super::SessionLayer). Its `call` method
//! coordinates the four lifecycle steps: load → device-resolve →
//! handler → finalize, then emits the response cookie.

#[cfg(feature = "device")]
use crate::device::resolver::ErasedDeviceResolver;
use crate::session::binding::SessionBinding;
use crate::session::config::SessionConfig;
use crate::session::id::SessionId;
use crate::session::layer::SessionLayer;
use crate::session::layer::handle::{ConsumeTarget, SessionHandle, SessionInner};
use crate::session::layer::lifecycle::{
    FinalizeOutcome, Fingerprints, LoadPolicy, apply_session_cookie, finalize_session,
    load_session, settle_registry,
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
    metrics: Option<Arc<dyn crate::metrics::AuthnMetrics>>,
    rng: Arc<dyn axess_rng::SecureRng>,
    clock: Arc<dyn axess_clock::Clock>,
    registry: Option<Arc<dyn crate::session::store::SessionRegistryHandle>>,
    unknown_liveness: crate::session::layer::UnknownLiveness,
    #[cfg(feature = "device")]
    device_resolver: Option<Arc<dyn ErasedDeviceResolver>>,
}

/// Request extension marking a request that arrived without a session the
/// layer could trust, so the session it runs under is a fresh guest that
/// exists only in memory until something asks for it to be stored. The CSRF
/// layer reads it to avoid storing a session for traffic that never uses one.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FreshSession;

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
        SessionService {
            inner,
            store: self.store.clone(),
            signing_keys: self.signing_keys.clone(),
            config,
            clock: self.clock.clone(),
            registry: self.registry.clone(),
            unknown_liveness: self.unknown_liveness,
            binding: self.binding.clone(),
            metrics: self.metrics.clone(),
            rng: self.rng.clone(),
            #[cfg(feature = "device")]
            device_resolver: self.device_resolver.clone(),
        }
    }
}

impl<S, Inner, ResBody> Service<Request<Body>> for SessionService<S, Inner>
where
    S: SessionStore + Clone + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
    Inner: Service<Request<Body>, Response = Response<ResBody>> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
    Inner::Error: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = Inner::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let store = self.store.clone();
        let config = self.config.clone();
        let signing_keys = self.signing_keys.clone();
        let session_binding = self.binding.clone();
        let metrics = self.metrics.clone();
        let rng = self.rng.clone();
        let clock = self.clock.clone();
        let registry = self.registry.clone();
        let unknown_liveness = self.unknown_liveness;
        #[cfg(feature = "device")]
        let device_resolver = self.device_resolver.clone();

        // Clone inner *before* the async block; required by tower's contract.
        let mut inner = self.inner.clone();
        std::mem::swap(&mut inner, &mut self.inner);

        // Pre-compute the binding fingerprint pair from the request
        // before moving it. `compute_binding_fingerprints` returns
        // (current, previous): `previous` is only `Some` when a
        // rotation window is active. The pair is threaded into
        // `load_session` so verification can fall back to the previous
        // key and re-store the fingerprint under the current key.
        let (current_fingerprint, previous_fingerprint) =
            match session_binding.as_deref().and_then(|b| b.extract(&req)) {
                Some(material) => {
                    let (curr, prev) = signing_keys.compute_binding_fingerprints(&material);
                    (Some(curr), prev)
                }
                None => (None, None),
            };

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
                    metrics: metrics.as_deref(),
                },
            )
            .await;

            // 1c. Resolve the device for this request (best-effort; see
            //     `resolve_device`). The session is marked modified iff the
            //     resolved id differs from the loaded one.
            #[cfg(feature = "device")]
            let (load, device_changed, device_cookie) = {
                let resolved = resolve_device(load, req, device_resolver).await;
                req = resolved.request;
                (resolved.load, resolved.changed, resolved.cookie)
            };
            #[cfg(not(feature = "device"))]
            let device_changed = false;

            // 2. Insert SessionHandle into request extensions.
            //    If binding is configured and the session has no fingerprint yet,
            //    pass the pre-computed fingerprint so the extractor can apply it
            //    immediately when the session transitions to Authenticated.
            let pending_fp = if session_binding.is_some() && load.data.fingerprint.is_none() {
                current_fingerprint.clone()
            } else {
                None
            };

            let existing_id = load.existing_id;
            let inner_state = seed_session_state(
                load,
                device_changed,
                pending_fp,
                &config,
                rng.clone(),
                Arc::new(store.clone()),
            );
            let handle = SessionHandle(Arc::new(RwLock::new(inner_state)));
            req.extensions_mut().insert(handle.clone());
            if existing_id.is_none() {
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
                handle: handle.clone(),
                existing_id,
            };
            let mut owed = FinishGuard(Some(finish));
            let response = inner.call(req).await;
            let Some(finish) = owed.0.take() else {
                return response;
            };
            let mut response = match response {
                Ok(response) => response,
                // The guard is gone, so run the finish here before
                // returning the handler's error.
                Err(error) => {
                    tokio::spawn(finish.run());
                    return Err(error);
                }
            };

            // 4 + 5. Finalize in a task of its own, then set the cookie only
            //     when the session was created or changed.
            let (outcome, registered) = finish_in_task(finish, &handle).await;
            apply_session_cookie(
                &signing_keys,
                &config,
                &outcome,
                registered,
                response.headers_mut(),
            );

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
fn seed_session_state<S>(
    load: crate::session::layer::lifecycle::LoadOutcome,
    device_changed: bool,
    pending_fingerprint: Option<String>,
    config: &SessionConfig,
    rng: Arc<dyn axess_rng::SecureRng>,
    store: Arc<S>,
) -> SessionInner
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
{
    let row_stored = load.existing_id.is_some();
    SessionInner {
        id: load.id,
        data: load.data,
        modified: load.binding_invalidated
            || (device_changed && row_stored)
            || load.rotation_fallback_used
            || load.session_ended,
        needs_persist: false,
        regenerate: load.binding_invalidated,
        pre_cycle_id: None,
        pending_fingerprint,
        max_custom_bytes: config.max_custom_bytes,
        rng,
        consume: Some(ConsumeTarget {
            store,
            ttl: config.ttl,
            row_stored,
        }),
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
            let id = handle.0.read().await.id;
            (
                FinalizeOutcome {
                    final_id: id,
                    session_changed: false,
                    rotation: None,
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
    metrics: Option<Arc<dyn crate::metrics::AuthnMetrics>>,
    clock: Arc<dyn axess_clock::Clock>,
    rng: Arc<dyn axess_rng::SecureRng>,
    registry: Option<Arc<dyn crate::session::store::SessionRegistryHandle>>,
    handle: SessionHandle,
    existing_id: Option<SessionId>,
}

impl<S> Finish<S>
where
    S: SessionStore + Clone + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
{
    async fn run(self) -> (FinalizeOutcome, bool) {
        let outcome = finalize_session(
            &self.store,
            &self.config,
            self.metrics.as_deref(),
            &*self.clock,
            &self.handle,
            self.existing_id,
            &*self.rng,
        )
        .await;
        let registered = settle_registry(&self.store, self.registry.as_deref(), &outcome).await;
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
/// `Err(_)` from the resolver is logged and treated as `None` by the erasure
/// wrapper. `axum::body::Body` is `!Sync`, so `&Request<Body>` cannot be
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
            load,
            changed: false,
            request: req,
            cookie: None,
        };
    };
    let (mut parts, body) = req.into_parts();
    // Hand the resolver the user the session has fully authenticated, so a
    // device is matched to its owner. A guest, or a session part-way through
    // a login, supplies none: its claimed user is not verified.
    if load.data.auth_state.is_authenticated()
        && let Some(user) = load.data.auth_state.user_id()
    {
        parts.extensions.insert(crate::device::SessionUser(*user));
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
    let resolved = resolver.resolve_erased(&parts).await;
    parts.extensions.remove::<crate::device::DeviceCookieSlot>();
    let request = Request::from_parts(parts, body);
    let changed = resolved != load.data.device_id;
    if changed {
        load.data.device_id = resolved;
    }
    ResolvedDevice {
        load,
        changed,
        request,
        cookie: slot.take(),
    }
}
