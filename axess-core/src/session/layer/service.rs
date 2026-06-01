//! Tower middleware service that runs the per-request session lifecycle.
//!
//! [`SessionService`] is the concrete `tower::Service` constructed by
//! [`SessionLayer::layer`](super::SessionLayer). Its `call` method
//! coordinates the four lifecycle steps: load → device-resolve →
//! handler → finalize, then emits the response cookie.

#[cfg(feature = "device")]
use crate::device::resolver::ErasedDeviceResolver;
use crate::session::binding::{self, SessionBinding};
use crate::session::config::SessionConfig;
use crate::session::layer::SessionLayer;
use crate::session::layer::handle::{SessionHandle, SessionInner};
use crate::session::layer::lifecycle::{build_set_cookie, finalize_session, load_session};
use crate::session::layer::signing::SigningKeys;
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
    signing_keys: Arc<SigningKeys>,
    /// Shared with [`SessionLayer`] via `Arc` to keep
    /// `Layer::layer` and per-request `Service::call` cloning cheap.
    config: Arc<SessionConfig>,
    binding: Option<Arc<dyn SessionBinding>>,
    metrics: Option<Arc<dyn crate::metrics::AuthnMetrics>>,
    #[cfg(feature = "device")]
    device_resolver: Option<Arc<dyn ErasedDeviceResolver>>,
}

impl<S, Inner> Layer<Inner> for SessionLayer<S>
where
    S: SessionStore + Clone,
{
    type Service = SessionService<S, Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        SessionService {
            inner,
            store: self.store.clone(),
            signing_keys: self.signing_keys.clone(),
            config: self.config.clone(),
            binding: self.binding.clone(),
            metrics: self.metrics.clone(),
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
        #[cfg(feature = "device")]
        let device_resolver = self.device_resolver.clone();

        // Clone inner *before* the async block; required by tower's contract.
        let mut inner = self.inner.clone();
        std::mem::swap(&mut inner, &mut self.inner);

        // Pre-compute the binding HMAC from the request before moving it.
        // Use the dedicated fingerprint sub-key; distinct from the
        // cookie-signing key.
        let current_fingerprint = session_binding
            .as_deref()
            .and_then(|b| binding::compute_fingerprint(b, &req, &signing_keys.fingerprint));

        Box::pin(async move {
            // 1. Load session; cookie verify, store load, fingerprint check, fresh-mint.
            let load = load_session(
                &store,
                &signing_keys,
                &config,
                metrics.as_deref(),
                req.headers(),
                current_fingerprint.as_deref(),
            )
            .await;

            // 1c. Resolve the device for this request. Best-effort;
            //     `Err(_)` is logged and treated as `None` by the
            //     erasure wrapper. We mark the session modified iff
            //     the resolved id differs from the loaded one, so an
            //     unchanged device on a stable session does not trigger
            //     a gratuitous save on every request.
            //
            //     `axum::body::Body` is `!Sync`, so `&Request<Body>`
            //     cannot be borrowed across an `await`. Split the
            //     request into `(Parts, Body)`, run the resolver
            //     against the parts, then reassemble before the inner
            //     service call.
            //
            //     The `mut load` shadow binding scopes the mutability
            //     to the device-enabled branch; under
            //     `cfg(not(feature = "device"))` the outer `load`
            //     stays immutable so no lint suppression is needed.
            #[cfg(feature = "device")]
            let (load, device_changed) = {
                let mut load = load;
                let dc = if let Some(ref resolver) = device_resolver {
                    let (parts, body) = req.into_parts();
                    let resolved = resolver.resolve_erased(&parts).await;
                    req = Request::from_parts(parts, body);
                    let differs = resolved != load.data.device_id;
                    if differs {
                        load.data.device_id = resolved;
                    }
                    differs
                } else {
                    false
                };
                (load, dc)
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

            let inner_state = SessionInner {
                id: load.id,
                data: load.data,
                modified: load.binding_invalidated || device_changed,
                regenerate: load.binding_invalidated,
                pre_cycle_id: None,
                pending_fingerprint: pending_fp,
                max_custom_bytes: config.max_custom_bytes,
            };
            let handle = SessionHandle(Arc::new(RwLock::new(inner_state)));
            req.extensions_mut().insert(handle.clone());

            // 3. Call the inner service.
            let response = inner.call(req).await?;

            // 4. Finalize; custom-data size enforcement + save-or-cycle decision.
            let outcome = finalize_session(
                &store,
                &config,
                metrics.as_deref(),
                &handle,
                load.existing_id,
            )
            .await;

            // 5. Set the cookie only when the session was created or changed.
            //    Omitting Set-Cookie on unmodified responses reduces header bloat
            //    and prevents spurious cache invalidation on CDN / reverse proxies.
            let mut response = response;
            if outcome.session_changed
                && let Some(hv) = build_set_cookie(&signing_keys, &config, outcome.final_id)
            {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, hv);
            }

            Ok(response)
        })
    }
}
