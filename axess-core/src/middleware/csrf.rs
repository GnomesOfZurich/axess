//! CSRF (Cross-Site Request Forgery) protection middleware.
//!
//! Implements the **signed double-submit cookie** pattern: the server issues
//! a token bound to the session id via HMAC and the client must echo it back
//! on every state-changing request (POST/PUT/PATCH/DELETE) either as the
//! `X-CSRF-Token` header (AJAX) or the `_csrf` form field on
//! `application/x-www-form-urlencoded` bodies (HTML forms). The cookie
//! itself is sent automatically by the browser, but cannot be read or
//! forged by cross-origin code thanks to the same-origin policy.
//!
//! `multipart/form-data` bodies (file uploads) are NOT scanned for the
//! form field: extracting one field would parse the whole upload. Use
//! the header path for multipart. Field name and buffer cap are
//! configurable via [`CsrfConfig::form_field_name`](crate::middleware::csrf::CsrfConfig::form_field_name)
//! and [`CsrfConfig::form_body_limit`](crate::middleware::csrf::CsrfConfig::form_body_limit)
//! (default 64 KiB); requests that exceed the cap fail closed.
//!
//! Optional Origin/Referer validation via
//! [`CsrfConfig::require_origin`](crate::middleware::csrf::CsrfConfig::require_origin)
//! adds a second gate: state-changing requests must present an
//! `Origin` (or `Referer`-derived) matching one of the configured
//! allowed origins. Both the token check and the Origin check must
//! pass. Off by default: enabling it rejects bearer-token clients
//! (native mobile, server-to-server) that hit the same routes without
//! an `Origin` header.
//!
//! A WebSocket upgrade (a `GET` with `Upgrade: websocket`, which the token
//! check never sees) gets its own `Origin` gate, since a cross-site page can
//! open a socket with the user's cookies: with an allow-list configured it
//! must present an allowed `Origin`; without one it must come from the
//! request's own `Host` under the scheme the deployment serves (`https`
//! while `secure` is on). Either way it is refused with `403` otherwise.
//! An upgrade with no `Origin` is not a browser's and passes the host rule.
//! [`CsrfConfig::websocket_origin_check`](crate::middleware::csrf::CsrfConfig::websocket_origin_check)
//! turns the host rule off.
//!
//! The token is `HMAC(signing_key, nonce || session_id)`, so it is bound to
//! the session that was current when it was minted: a token minted under one
//! session id fails validation once the request carries a different session
//! id (e.g. after the session is regenerated on login). A token stolen from
//! one session therefore cannot be replayed against another. Tokens are
//! constant-time verified against the cookie.
//!
//! # Layering requirement
//!
//! The [`CsrfLayer`](crate::middleware::csrf::CsrfLayer) reads the current session id from the session-handle
//! request extension that the session layer injects. It MUST therefore be
//! layered **inside** (i.e. run after) the session layer so the handle is
//! present by the time this middleware runs. In an `axum` `Router`, layers
//! applied later wrap earlier ones, so add the session layer *after*
//! `CsrfLayer`:
//!
//! ```rust,ignore
//! let app = Router::new()
//!     .route("/api/transfer", post(transfer))
//!     .layer(CsrfLayer::new(csrf_config)) // inner: runs second, sees the handle
//!     .layer(session_layer);              // outer: runs first, injects the handle
//! ```
//!
//! If the session-handle extension is absent on a state-changing request,
//! the middleware **fails closed** (403) rather than validating an unbound
//! token, so a mis-ordered stack surfaces as a hard failure instead of a
//! silent loss of the session-binding property.
//!
//! # Threat model
//!
//! - **Defends against:** CSRF on POST/PUT/PATCH/DELETE from cross-origin
//!   pages, including those served over the same eTLD+1 (where SameSite=Lax
//!   would not help).
//! - **Does NOT defend against:** XSS (an injected script can read the
//!   token), network MITM (use HTTPS + HSTS), or login CSRF (use a
//!   pre-session token strategy).
//!
//! # Wiring
//!
//! ```rust,ignore
//! use axess::middleware::csrf::{CsrfLayer, CsrfConfig};
//!
//! let csrf = CsrfLayer::new(CsrfConfig::new(signing_key));
//!
//! let app = Router::new()
//!     .route("/api/transfer", post(transfer))
//!     .layer(csrf)           // inner: sees the session handle
//!     .layer(session_layer); // outer: injects the session handle first
//! ```
//!
//! Read the token from the `CsrfToken` request extension and inject it into
//! HTML forms or expose it to your SPA via a `/csrf` endpoint. Because the
//! token is bound to the session id, a client that caches the token across a
//! session change (e.g. login, which regenerates the session) must re-read
//! it afterwards or its first post-login state-changing request will 403.
//!
//! **Rotating the session in the handler.** The [`CsrfToken`](crate::middleware::csrf::CsrfToken) request
//! extension is bound to the session id observed at request entry, and a
//! handler cannot change a value it was handed by clone. A handler that
//! rotates the session (e.g. after login) and then embeds a token in the
//! page it renders must therefore take the [`CsrfIssuer`](crate::middleware::csrf::CsrfIssuer) request extension
//! and call [`CsrfIssuer::token`](crate::middleware::csrf::CsrfIssuer::token) *after* rotating: it returns a token bound
//! to the post-rotation id, and it is the very token the layer ships as the
//! response `Set-Cookie`, so the embedded value and the cookie always agree.
//! Before any rotation `token()` returns the same value as the [`CsrfToken`](crate::middleware::csrf::CsrfToken)
//! extension.

use axess_rng::SecureRng;
use axum::{
    body::Body,
    http::{HeaderValue, Request, Response, StatusCode, header},
    response::IntoResponse,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tower::{Layer, Service};
use zeroize::Zeroizing;

use crate::session::id::SessionId;
use crate::session::layer::SessionHandle;

/// Default cookie name for the CSRF token when the cookie is `Secure`. The
/// `__Host-` prefix makes the browser refuse the cookie from any other host
/// or path, so a sibling subdomain cannot plant a CSRF cookie of its own.
pub const DEFAULT_CSRF_COOKIE: &str = "__Host-axess.csrf";

/// Cookie name used instead of [`DEFAULT_CSRF_COOKIE`] when the config does
/// not name a cookie and `Secure` is off: browsers drop a `__Host-` cookie
/// that is not `Secure`, so the unprefixed name is the one that still works.
pub const FALLBACK_CSRF_COOKIE: &str = "axess.csrf";

/// Default header name for the CSRF token on AJAX requests.
pub const DEFAULT_CSRF_HEADER: &str = "x-csrf-token";

/// Default form-field name for the CSRF token on HTML form submissions.
pub const DEFAULT_CSRF_FORM_FIELD: &str = "_csrf";

/// Default cap on buffered `application/x-www-form-urlencoded` bodies
/// during CSRF form-field extraction. Requests declaring a Content-Length
/// larger than this fail closed (413-shaped 403); requests without a
/// declared length are read up to this cap and then aborted.
pub const DEFAULT_CSRF_FORM_BODY_LIMIT: usize = 64 * 1024;

/// Number of random bytes in the token nonce. 32 bytes = 256 bits.
const TOKEN_NONCE_BYTES: usize = 32;

use crate::cookies::MAX_COOKIE_VALUE_BYTES;

/// Configuration for [`CsrfLayer`].
#[derive(Clone)]
pub struct CsrfConfig {
    /// Wiped when the last clone of the config drops.
    signing_key: Arc<Zeroizing<[u8; 32]>>,
    /// Source of every token nonce.
    rng: Arc<dyn SecureRng>,
    /// The name the adopter set; `None` takes the default that follows the
    /// `Secure` flag (see [`effective_cookie_name`](Self::effective_cookie_name)).
    cookie_name: Option<Arc<str>>,
    header_name: Arc<str>,
    form_field_name: Arc<str>,
    form_body_limit: usize,
    secure: bool,
    same_site: cookie::SameSite,
    path: Arc<str>,
    /// If populated, state-changing requests must present an `Origin`
    /// (or `Referer`-derived origin) matching one of these exact strings
    /// in addition to passing the token check.
    allowed_origins: Arc<[Arc<str>]>,
    /// Issue a token (and so store a session) on every request that arrives
    /// without one, whether or not a handler uses it.
    mint_on_every_request: bool,
    /// Without an allow-list, refuse a WebSocket upgrade whose `Origin` is
    /// not the request's own host and scheme.
    websocket_origin_check: bool,
}

/// Whether [`CsrfConfig::require_origin`] should warn about entries it dropped.
///
/// True when *some* supplied origins canonicalized and some did not. The
/// all-failed case is an assert, not a warning, because it silently disables
/// the gate; a partial failure still leaves the gate armed, so it is
/// "suspicious but functional" and warns instead.
///
/// Lifted out of [`CsrfConfig::require_origin`] so the boolean guard is
/// observable in a unit test without depending on a tracing capture, matching
/// `should_warn_insecure_cookie` in `session::config`.
fn should_warn_dropped_origins(kept: usize, rejected: usize) -> bool {
    kept > 0 && rejected > 0
}

impl CsrfConfig {
    /// Create a new config with the given HMAC signing key. Use a key of its
    /// own: either an independent 32-byte secret, or a purpose-bound subkey
    /// of the session layer's master key (`SessionLayer::derive_subkey`,
    /// for example with the label `axess.v1.csrf`). Do not pass the session
    /// master itself, so a leak of one use does not hand over the other.
    /// There is no previous-key fallback: changing this key invalidates the
    /// tokens already rendered into open forms, and those pages reload.
    /// A key that is a single repeated byte is logged at `error`; use
    /// [`try_new`](Self::try_new) to refuse it.
    pub fn new(signing_key: [u8; 32]) -> Self {
        crate::session::weak_key::warn_if_constant_key("CSRF signing key", &signing_key);
        Self {
            signing_key: Arc::new(Zeroizing::new(signing_key)),
            rng: Arc::new(axess_rng::SystemRng),
            cookie_name: None,
            header_name: DEFAULT_CSRF_HEADER.into(),
            form_field_name: DEFAULT_CSRF_FORM_FIELD.into(),
            form_body_limit: DEFAULT_CSRF_FORM_BODY_LIMIT,
            secure: true,
            same_site: cookie::SameSite::Lax,
            path: "/".into(),
            allowed_origins: Arc::from(Vec::new()),
            mint_on_every_request: false,
            websocket_origin_check: true,
        }
    }

    /// Like [`new`](Self::new), refusing a signing key that is a single
    /// repeated byte.
    ///
    /// # Errors
    ///
    /// [`WeakKeyError`](crate::session::WeakKeyError) for such a key.
    pub fn try_new(signing_key: [u8; 32]) -> Result<Self, crate::session::WeakKeyError> {
        if crate::session::is_constant_key(&signing_key) {
            return Err(crate::session::WeakKeyError);
        }
        Ok(Self::new(signing_key))
    }

    /// Issue a CSRF token, and store a session to bind it to, on every
    /// request that arrives without a session cookie, even when no handler
    /// reads the token (default: `false`).
    ///
    /// By default a cookieless request stores a session and sets cookies
    /// only when a handler actually used the token, through the
    /// [`CsrfToken`] extension or [`CsrfIssuer::token`]. That keeps bots,
    /// health checks and asset requests from writing a row each. Turn this
    /// on for a single-page app that reads the token cookie in JavaScript on
    /// its first load without any handler touching the extension.
    pub fn mint_on_every_request(mut self, mint: bool) -> Self {
        self.mint_on_every_request = mint;
        self
    }

    /// Without an allow-list ([`require_origin`](Self::require_origin)),
    /// refuse a WebSocket upgrade whose `Origin` is not the request's own
    /// `Host` under the scheme the deployment serves (`https` while
    /// [`secure`](Self::secure) is on, `http` or `https` otherwise); on by
    /// default. A cross-site page can open a socket with the user's
    /// cookies, and the token check never sees an upgrade. An upgrade with
    /// no `Origin` at all is not a browser's and passes. Turn this off only
    /// for a deployment that terminates WebSockets on another host than the
    /// one the browser addresses, and then set an allow-list instead.
    pub fn websocket_origin_check(mut self, check: bool) -> Self {
        self.websocket_origin_check = check;
        self
    }

    /// Draw token nonces from `rng` (default: `SystemRng`), so a seeded RNG
    /// makes the issued tokens reproducible.
    pub fn rng(mut self, rng: impl SecureRng) -> Self {
        self.rng = Arc::new(rng);
        self
    }

    /// Override the cookie name (default [`DEFAULT_CSRF_COOKIE`], or
    /// [`FALLBACK_CSRF_COOKIE`] when `Secure` is off).
    pub fn cookie_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.cookie_name = Some(name.into());
        self
    }

    /// Override the request header name (default `X-CSRF-Token`).
    pub fn header_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.header_name = name.into();
        self
    }

    /// Override the form-field name used when the request is
    /// `application/x-www-form-urlencoded` and no header token is
    /// present (default `_csrf`).
    pub fn form_field_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.form_field_name = name.into();
        self
    }

    /// Cap on bytes buffered when scanning a form-urlencoded body for
    /// the token field. Requests larger than this fail closed rather
    /// than let a hostile client exhaust memory (default 64 KiB).
    pub fn form_body_limit(mut self, limit: usize) -> Self {
        self.form_body_limit = limit;
        self
    }

    /// Set the cookie `Secure` attribute (default: true). Set to `false`
    /// only in local development over HTTP. A default cookie name follows
    /// the flag: [`DEFAULT_CSRF_COOKIE`] when `Secure`, else
    /// [`FALLBACK_CSRF_COOKIE`], since browsers drop a `__Host-` cookie
    /// that is not `Secure`.
    pub fn secure(mut self, secure: bool) -> Self {
        if !secure {
            tracing::warn!(
                "CsrfConfig: Secure cookie flag disabled; the CSRF cookie will be \
                 sent over plain HTTP. Do not use in production."
            );
        }
        self.secure = secure;
        self
    }

    /// The cookie name in use: the one set with
    /// [`cookie_name`](Self::cookie_name), else [`DEFAULT_CSRF_COOKIE`] while
    /// `Secure` is on and [`FALLBACK_CSRF_COOKIE`] otherwise. Derived from
    /// the settings on every read, so the order of the setters never
    /// matters.
    pub(crate) fn effective_cookie_name(&self) -> &str {
        match &self.cookie_name {
            Some(name) => name,
            None if self.secure => DEFAULT_CSRF_COOKIE,
            None => FALLBACK_CSRF_COOKIE,
        }
    }

    /// Set the cookie `SameSite` attribute. Default `Lax`.
    pub fn same_site(mut self, same_site: cookie::SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Enable Origin/Referer validation as defence in depth.
    ///
    /// When configured, state-changing requests must present an `Origin`
    /// header (or, if `Origin` is absent, a `Referer` whose origin
    /// component) matches one of `origins`, in addition to passing the
    /// signed-double-submit token check. Both checks must pass.
    ///
    /// Off by default: adopters serving bearer-token clients (native
    /// mobile apps, server-to-server RPC) on the same routes would see
    /// legitimate `Origin`-less requests rejected. Enable only for
    /// browser-scoped routers.
    ///
    /// `origins` are matched against the browser's `Origin` / `Referer`
    /// after both sides are canonicalized via [`url::Url::origin`]
    /// (scheme + host case-folded, `userinfo@` stripped, default port
    /// dropped for `http`/`https`). Adopters can therefore pass any
    /// RFC-6454-equivalent form. Wildcard / regex matching is deliberately
    /// not supported; if several subdomains are legitimate, list them
    /// explicitly.
    ///
    /// # Panics
    ///
    /// Panics if `origins` yielded at least one input but every entry
    /// failed to canonicalize (missing scheme, opaque-origin scheme,
    /// unparseable URL). Silently dropping every entry would leave
    /// `allowed_origins` empty, which the request-time gate treats as
    /// "Origin check disabled": the adopter would think Origin
    /// validation was on when it was actually off. Fail-fast at
    /// construction matches `SessionConfigBuilder::build`'s discipline
    /// for the same misconfig class.
    ///
    /// If only *some* entries fail to canonicalize, the surviving ones are
    /// kept and the failures are logged at `WARN`. The gate stays armed, so
    /// this is fail-closed rather than fail-open: but a dropped entry means
    /// browser traffic from that origin is rejected as though it had never
    /// been allow-listed, which is why it is not silent.
    pub fn require_origin(mut self, origins: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        let mut normalized: Vec<Arc<str>> = Vec::new();
        let mut supplied_any = false;
        let mut rejected: Vec<String> = Vec::new();
        for raw in origins {
            supplied_any = true;
            let raw = raw.as_ref();
            match normalize_origin(raw) {
                Some(n) => normalized.push(Arc::from(n)),
                None => rejected.push(raw.to_owned()),
            }
        }
        assert!(
            !(supplied_any && normalized.is_empty()),
            "CsrfConfig::require_origin: all {} supplied origin(s) failed to canonicalize \
             (missing scheme, opaque-origin scheme, or unparseable URL): {:?}. \
             Leaving the list empty would silently disable the Origin/Referer gate.",
            rejected.len(),
            rejected,
        );
        if should_warn_dropped_origins(normalized.len(), rejected.len()) {
            tracing::warn!(
                rejected = ?rejected,
                kept = normalized.len(),
                "CsrfConfig::require_origin: {} supplied origin(s) failed to \
                 canonicalize and were dropped. Requests from them will be \
                 rejected as if they were never allow-listed.",
                rejected.len(),
            );
        }
        self.allowed_origins = normalized.into();
        self
    }
}

mod issuer;
pub use issuer::{CsrfIssuer, CsrfToken};

/// Tower layer that issues and validates CSRF tokens.
#[derive(Clone)]
pub struct CsrfLayer {
    config: CsrfConfig,
    metrics: Arc<dyn crate::metrics::RequestGuardMetrics>,
}

impl CsrfLayer {
    /// Construct a layer that issues and validates CSRF tokens with `config`.
    ///
    /// # Panics
    ///
    /// Panics when the cookie name carries a `__Host-` or `__Secure-` prefix
    /// the configuration cannot honour (no `Secure`, or for `__Host-` a path
    /// other than `/`), when `SameSite=None` is set without `Secure`
    /// (browsers drop such a cookie silently), or when the cookie path does
    /// not start with `/` or holds `;` or a control character.
    pub fn new(config: CsrfConfig) -> Self {
        check_cookie_rules(
            config.effective_cookie_name(),
            config.secure,
            &config.path,
            config.same_site,
        );
        Self {
            config,
            metrics: Arc::new(crate::metrics::NoopMetrics),
        }
    }

    /// Attach the metric sinks; the layer reports the request-guard concern
    /// (`csrf_rejected`, with the [`CsrfRefusal`](crate::metrics::CsrfRefusal)
    /// that names why).
    pub fn with_metrics(mut self, metrics: crate::metrics::MetricSinks) -> Self {
        self.metrics = metrics.guard;
        self
    }
}

impl<S> Layer<S> for CsrfLayer {
    type Service = CsrfService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfService {
            inner,
            config: self.config.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

/// Tower service produced by [`CsrfLayer`].
#[derive(Clone)]
pub struct CsrfService<S> {
    inner: S,
    config: CsrfConfig,
    metrics: Arc<dyn crate::metrics::RequestGuardMetrics>,
}

impl<S> Service<Request<Body>> for CsrfService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let config = self.config.clone();
        let metrics = self.metrics.clone();
        let mut inner = self.inner.clone();
        std::mem::swap(&mut inner, &mut self.inner);

        Box::pin(async move {
            let cookie_token = extract_cookie_token(&req, config.effective_cookie_name());

            // Read the current session id from the handle the session layer
            // injects. The token is HMAC-bound to this id, so the session
            // layer MUST wrap this middleware (see the module docs). Clone
            // the handle out first so the request borrow ends before we await
            // the read lock.
            let session_handle = req.extensions().get::<SessionHandle>().cloned();
            let session_id = match &session_handle {
                Some(handle) => Some(handle.0.read().await.id),
                None => None,
            };

            // A WebSocket upgrade is a GET the browser sends with cookies
            // from any origin, and the CSRF token never applies to it. With
            // an allow-list configured it gets the same Origin gate; without
            // one the request's own host is the one origin it may come from.
            if is_websocket_upgrade(&req) {
                let admitted = if !config.allowed_origins.is_empty() {
                    origin_matches_allowed(&req, &config.allowed_origins)
                } else if config.websocket_origin_check {
                    origin_is_own_host(&req, config.secure)
                } else {
                    true
                };
                if !admitted {
                    metrics.csrf_rejected(crate::metrics::CsrfRefusal::WebSocketOrigin);
                    tracing::warn!(
                        path = %req.uri().path(),
                        "csrf: WebSocket upgrade refused, Origin is not an allowed origin or the \
                         request's own host"
                    );
                    return Ok(forbidden());
                }
            }

            // Validate on state-changing methods. GET/HEAD/OPTIONS pass through
            // because they must be safe (idempotent, no side effects) per
            // RFC 9110 section 9.2.1; and CSRF only matters for unsafe verbs.
            if is_state_changing(req.method()) {
                req = match validate_state_changing(
                    req,
                    &config,
                    session_id,
                    cookie_token.as_deref(),
                )
                .await
                {
                    Ok(req) => req,
                    Err(Refused(reason)) => {
                        metrics.csrf_rejected(reason);
                        return Ok(forbidden());
                    }
                };
            }

            let EntryToken {
                provisional_mint,
                extension_token,
            } = entry_token(&config, cookie_token.as_deref(), session_id);
            // A request the session layer could not tie to a stored session
            // runs under a guest that exists only in memory. Storing it for a
            // token nobody reads is storage amplification from unauthenticated
            // traffic, so the token's use decides.
            let fresh_session = req
                .extensions()
                .get::<crate::session::layer::FreshSession>()
                .is_some();
            let read = Arc::new(AtomicBool::new(false));
            let issuer = CsrfIssuer::new(
                config.signing_key.clone(),
                config.rng.clone(),
                session_handle.clone(),
                session_id.map(|sid| (sid, extension_token.clone())),
                read.clone(),
            );
            req.extensions_mut()
                .insert(CsrfToken::tracked(extension_token, read.clone()));
            req.extensions_mut().insert(issuer.clone());

            let mut response = inner.call(req).await?;

            // Re-read the session id after the handler runs. If the
            // handler regenerated (login-success, MFA add, tenant switch),
            // the cookie the client currently holds: even if it was
            // valid at request entry: no longer validates against the
            // new id. Left alone the client would 403 on every state-
            // changing request until the browser cookie expires. Deciding
            // the mint post-handler closes that gap: if the cookie the
            // client will present next no longer verifies against the
            // effective (post-handler) session id, mint a fresh one and
            // ship it as Set-Cookie on this response.
            let session_id_after = match &session_handle {
                Some(handle) => Some(handle.0.read().await.id),
                None => None,
            };
            let mut token_to_set = replacement_token(
                &config,
                &issuer,
                provisional_mint,
                cookie_token.as_deref(),
                session_id_after,
            );
            // Nobody read the token and the session id is the one the request
            // began with (a rotation stores its session regardless): leave
            // the guest unstored and the response without cookies.
            if fresh_session
                && !config.mint_on_every_request
                && !read.load(Ordering::Relaxed)
                && session_id_after == session_id
            {
                token_to_set = None;
            }

            if token_to_set.is_some()
                && let Some(handle) = &session_handle
            {
                // A token bound to the id needs the session stored and its
                // cookie set, or the next request cannot present it.
                handle.mark_needs_persist().await;
            }
            if let Some(new_token) = token_to_set {
                let cookie = build_cookie(&config, &new_token);
                if let Ok(hv) = HeaderValue::from_str(&cookie) {
                    response.headers_mut().append(header::SET_COOKIE, hv);
                    crate::session::layer::mark_cookie_response(response.headers_mut());
                }
            }

            Ok(response)
        })
    }
}

/// The response for a request the CSRF check refuses.
fn forbidden() -> Response<Body> {
    (StatusCode::FORBIDDEN, "CSRF validation failed").into_response()
}

mod guards;
use guards::check_cookie_rules;
// Shared with the session layer, which applies the same Origin rule to a
// WebSocket upgrade.
pub(crate) use guards::{
    is_websocket_upgrade, normalize_origin, origin_is_own_host, origin_matches_allowed,
};
mod issued;
use issued::{EntryToken, build_cookie, entry_token, replacement_token};
mod presented;
#[cfg(test)]
use presented::extract_presented_token;
use presented::{Refused, extract_cookie_token, is_state_changing, validate_state_changing};
mod token;
use token::{mint_token, validate_pair, validate_token};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod rotation_tests;

#[cfg(test)]
mod upgrade_tests;
