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
//! With an allow-list configured, a WebSocket upgrade (a `GET` with
//! `Upgrade: websocket`, which the token check never sees) must present an
//! allowed `Origin` too, and is refused with `403` otherwise.
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
use subtle::ConstantTimeEq;
use tower::{Layer, Service};
use zeroize::Zeroizing;

use crate::session::id::SessionId;
use crate::session::layer::SessionHandle;

/// Default cookie name for the CSRF token.
pub const DEFAULT_CSRF_COOKIE: &str = "axess.csrf";

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
    cookie_name: Arc<str>,
    header_name: Arc<str>,
    form_field_name: Arc<str>,
    form_body_limit: usize,
    secure: bool,
    same_site: tower_cookies::cookie::SameSite,
    path: Arc<str>,
    /// If populated, state-changing requests must present an `Origin`
    /// (or `Referer`-derived origin) matching one of these exact strings
    /// in addition to passing the token check.
    allowed_origins: Arc<[Arc<str>]>,
    /// Issue a token (and so store a session) on every request that arrives
    /// without one, whether or not a handler uses it.
    mint_on_every_request: bool,
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
    pub fn new(signing_key: [u8; 32]) -> Self {
        Self {
            signing_key: Arc::new(Zeroizing::new(signing_key)),
            rng: Arc::new(axess_rng::SystemRng),
            cookie_name: DEFAULT_CSRF_COOKIE.into(),
            header_name: DEFAULT_CSRF_HEADER.into(),
            form_field_name: DEFAULT_CSRF_FORM_FIELD.into(),
            form_body_limit: DEFAULT_CSRF_FORM_BODY_LIMIT,
            secure: true,
            same_site: tower_cookies::cookie::SameSite::Lax,
            path: "/".into(),
            allowed_origins: Arc::from(Vec::new()),
            mint_on_every_request: false,
        }
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

    /// Draw token nonces from `rng` (default: `SystemRng`), so a seeded RNG
    /// makes the issued tokens reproducible.
    pub fn rng(mut self, rng: impl SecureRng) -> Self {
        self.rng = Arc::new(rng);
        self
    }

    /// Override the cookie name.
    pub fn cookie_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.cookie_name = name.into();
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
    /// only in local development over HTTP.
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

    /// Set the cookie `SameSite` attribute. Default `Lax`.
    pub fn same_site(mut self, same_site: tower_cookies::cookie::SameSite) -> Self {
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
}

impl CsrfLayer {
    /// Construct a layer that issues and validates CSRF tokens with `config`.
    ///
    /// # Panics
    ///
    /// Panics when the cookie name carries a `__Host-` or `__Secure-` prefix
    /// the configuration cannot honour (no `Secure`, or for `__Host-` a path
    /// other than `/`): browsers drop such a cookie silently.
    pub fn new(config: CsrfConfig) -> Self {
        check_cookie_rules(&config.cookie_name, config.secure, &config.path);
        Self { config }
    }
}

impl<S> Layer<S> for CsrfLayer {
    type Service = CsrfService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Tower service produced by [`CsrfLayer`].
#[derive(Clone)]
pub struct CsrfService<S> {
    inner: S,
    config: CsrfConfig,
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
        let mut inner = self.inner.clone();
        std::mem::swap(&mut inner, &mut self.inner);

        Box::pin(async move {
            let cookie_token = extract_cookie_token(&req, &config.cookie_name);

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
            // an allow-list configured it gets the same Origin gate.
            if !config.allowed_origins.is_empty()
                && is_websocket_upgrade(&req)
                && !origin_matches_allowed(&req, &config.allowed_origins)
            {
                tracing::warn!(
                    path = %req.uri().path(),
                    "csrf: WebSocket upgrade refused, Origin not in the allow-list"
                );
                return Ok(forbidden());
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
                    Err(Refused) => return Ok(forbidden()),
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

/// A state-changing request the CSRF check refuses.
struct Refused;

/// The response for a request the CSRF check refuses.
fn forbidden() -> Response<Body> {
    (StatusCode::FORBIDDEN, "CSRF validation failed").into_response()
}

/// Decide whether a state-changing request carries a valid CSRF token.
///
/// Fails closed: with no session id there is nothing to bind the token to,
/// so the request is refused. The Origin/Referer check runs before any body
/// is buffered. On success the request is returned with its body intact (a
/// form-encoded body may have been read to find the token); on failure the
/// request is refused with [`Refused`].
async fn validate_state_changing(
    mut req: Request<Body>,
    config: &CsrfConfig,
    session_id: Option<SessionId>,
    cookie_token: Option<&str>,
) -> Result<Request<Body>, Refused> {
    let method = req.method().clone();
    // Fail closed: without a session id we cannot verify the
    // binding, so a mis-ordered layer stack (CsrfLayer outside the
    // session layer) is rejected rather than silently validating
    // an unbound token.
    let Some(session_id) = session_id else {
        tracing::warn!(
            method = %method,
            path = %req.uri().path(),
            "csrf: no session id on state-changing request \
             (CsrfLayer must be layered inside the session layer)"
        );
        return Err(Refused);
    };

    // Origin/Referer defence in depth, if configured. Runs
    // BEFORE the body-buffering path so a mismatched Origin
    // never triggers form-body extraction.
    if !config.allowed_origins.is_empty() && !origin_matches_allowed(&req, &config.allowed_origins)
    {
        tracing::warn!(
            method = %method,
            path = %req.uri().path(),
            "csrf: Origin/Referer validation failed"
        );
        return Err(Refused);
    }

    // Extract the presented token, possibly by buffering a
    // form-urlencoded body. `req` may be re-created with its
    // body restored.
    let (extracted, req_after) = match extract_presented_token(req, config).await {
        Ok(pair) => pair,
        Err(reason) => {
            tracing::warn!(
                method = %method,
                reason = %reason,
                "csrf: request rejected during token extraction"
            );
            return Err(Refused);
        }
    };
    req = req_after;
    let presented = extracted;
    let cookie_present = cookie_token;
    if !validate_pair(
        cookie_present,
        presented.as_deref(),
        session_id.as_bytes(),
        &config.signing_key,
    ) {
        tracing::warn!(
            method = %method,
            path = %req.uri().path(),
            cookie_present = cookie_present.is_some(),
            header_or_form_present = presented.is_some(),
            "csrf: token validation failed"
        );
        return Err(Refused);
    }
    Ok(req)
}

/// The token handed to the handler before it runs.
struct EntryToken {
    /// A fresh token minted for this response, when the client has no usable one.
    provisional_mint: Option<String>,
    /// The value the handler sees in the [`CsrfToken`] extension.
    extension_token: String,
}

/// Decide which token the handler sees at request entry.
///
/// Handlers
/// that read `CsrfToken` from the request extension (to embed
/// in an HTML form, say) need SOME value; give them either
/// the presented cookie or a fresh mint bound to the current
/// session id. A token can only be minted when a session id
/// is present to bind it to; without one we leave the client
/// tokenless rather than issue an unbound token.
///
/// A presented cookie that does not verify against the session id
/// at entry (left over from before the id changed) is not handed
/// to the handler: embedding it would render a form whose first
/// submit is refused. It is treated as absent here, so the handler
/// sees a fresh token bound to the current id, and the same token
/// goes out as the replacement cookie. Validation of a
/// state-changing request is unchanged and has already run.
fn entry_token(
    config: &CsrfConfig,
    cookie_token: Option<&str>,
    session_id: Option<SessionId>,
) -> EntryToken {
    let usable_cookie = cookie_token.filter(|c| {
        !c.is_empty()
            && session_id
                .as_ref()
                .is_none_or(|sid| validate_token(c, sid.as_bytes(), &config.signing_key))
    });
    let provisional_mint = match (usable_cookie, session_id.as_ref()) {
        (Some(_), _) => None,
        (None, Some(sid_at_entry)) => Some(mint_token(
            sid_at_entry.as_bytes(),
            &config.signing_key,
            &*config.rng,
        )),
        (None, None) => None,
    };
    let extension_token = provisional_mint
        .clone()
        .or_else(|| usable_cookie.map(str::to_owned))
        .or_else(|| cookie_token.map(str::to_owned))
        .unwrap_or_default();
    EntryToken {
        provisional_mint,
        extension_token,
    }
}

/// The token to ship as `Set-Cookie` after the handler ran, if any.
///
/// The post-handler session id decides: if the cookie the client will present
/// next no longer verifies against it (typical after `session.regenerate()`), a
/// token for the new id is issued; otherwise only a token minted at entry is sent.
fn replacement_token(
    config: &CsrfConfig,
    issuer: &CsrfIssuer,
    provisional_mint: Option<String>,
    cookie_token: Option<&str>,
    session_id_after: Option<SessionId>,
) -> Option<String> {
    // The token the client would present next request: either the
    // freshly-provisioned mint (if we issued one) or the cookie
    // they sent this request. Empty string means "no token to
    // present": treat as absent.
    let effective_cookie = provisional_mint
        .as_deref()
        .or(cookie_token)
        .filter(|t| !t.is_empty());
    match (effective_cookie, session_id_after.as_ref()) {
        (Some(existing), Some(sid_after))
            if validate_token(existing, sid_after.as_bytes(), &config.signing_key) =>
        {
            // Cookie still binds to the post-handler session id
            // (usually because the handler didn't rotate). Mint
            // only if we chose to at entry.
            provisional_mint
        }
        (_, Some(sid_after)) => {
            // Either no effective cookie, or the effective cookie
            // no longer binds to the current session id (typical
            // after `session.regenerate()`). Use the issuer's token
            // for the new id: it is the one a handler that rotated
            // may already have embedded in its response body.
            Some(issuer.token_for(*sid_after))
        }
        (_, None) => None,
    }
}

fn is_state_changing(method: &axum::http::Method) -> bool {
    // A deny-list of the SAFE methods (RFC 9110 §9.2.1), not an allow-list
    // of the unsafe ones: PURGE, MKCOL, LOCK, PROPPATCH and any custom method
    // change state and were skipped by the old list.
    !matches!(
        *method,
        axum::http::Method::GET
            | axum::http::Method::HEAD
            | axum::http::Method::OPTIONS
            | axum::http::Method::TRACE
    )
}

fn extract_cookie_token(req: &Request<Body>, cookie_name: &str) -> Option<String> {
    // Delegates to the shared `utils::cookies` helper. The cap is
    // enforced inside the helper; CSRF passes its own `MAX_COOKIE_VALUE_BYTES`
    // constant so the value is auditable next to the rest of the CSRF
    // configuration.
    crate::cookies::extract_named_cookie(req.headers(), cookie_name, MAX_COOKIE_VALUE_BYTES)
}

/// Return the presented CSRF token and the (possibly-rebuilt) request.
///
/// Extraction order:
///
/// 1. Header (`config.header_name`): no body cost. Standard for AJAX.
/// 2. Form field (`config.form_field_name`): only if the request is
///    `application/x-www-form-urlencoded`. Buffers the body up to
///    `config.form_body_limit` bytes, parses for the field, then restores
///    the (in-memory) body into the request so downstream handlers still
///    read the form normally.
///
/// Multipart form data (`multipart/form-data`) is deliberately NOT
/// supported: extracting one field would parse the entire upload,
/// which is the wrong tradeoff for CSRF middleware. JS-driven multipart
/// clients should set the header instead.
///
/// Returns `Err(reason)` when the request declares (or streams) a
/// body larger than `form_body_limit` on the form-field path: the
/// caller fails the request closed rather than let a hostile client
/// exhaust memory.
async fn extract_presented_token(
    req: Request<Body>,
    config: &CsrfConfig,
) -> Result<(Option<String>, Request<Body>), &'static str> {
    // Header path first; if present, the body stays untouched.
    if let Some(value) = req.headers().get(config.header_name.as_ref())
        && let Ok(s) = value.to_str()
        && !s.is_empty()
    {
        return Ok((Some(s.to_string()), req));
    }

    // Form-field path is scoped to state-changing requests carrying an
    // urlencoded body. Anything else: no form field to look at, return
    // `None` with the request untouched.
    let is_urlencoded = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            let base = s.split(';').next().unwrap_or("").trim();
            base.eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
        .unwrap_or(false);
    if !is_urlencoded {
        return Ok((None, req));
    }

    // Reject up front if the client declared a body larger than the cap.
    if let Some(declared) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        && declared > config.form_body_limit
    {
        return Err("form body exceeds csrf buffer cap");
    }

    // Split, buffer, parse, restore. `axum::body::to_bytes` enforces
    // the cap even for chunked bodies with no Content-Length.
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, config.form_body_limit).await {
        Ok(b) => b,
        Err(_) => return Err("form body exceeds csrf buffer cap"),
    };
    let field = form_urlencoded::parse(&bytes)
        .find(|(k, _)| k.as_ref() == config.form_field_name.as_ref())
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty());
    let restored = Request::from_parts(parts, Body::from(bytes));
    Ok((field, restored))
}

fn validate_pair(
    cookie_token: Option<&str>,
    presented: Option<&str>,
    session_id: &[u8],
    signing_key: &[u8; 32],
) -> bool {
    let (Some(c), Some(p)) = (cookie_token, presented) else {
        return false;
    };
    if c.is_empty() || p.is_empty() {
        return false;
    }
    // Cookie and presented must match exactly (double-submit) AND the token
    // must verify against the signing key *and* the current session id (so an
    // attacker who can set cookies cannot inject a self-chosen value, and a
    // token stolen from another session cannot be replayed here).
    bool::from(c.as_bytes().ct_eq(p.as_bytes())) && validate_token(c, session_id, signing_key)
}

fn build_cookie(config: &CsrfConfig, token: &str) -> String {
    use tower_cookies::Cookie;

    let mut cookie = Cookie::new(config.cookie_name.as_ref().to_string(), token.to_string());
    // Intentionally NOT HttpOnly; JavaScript needs to read the token to
    // include it in headers (the double-submit pattern requires this).
    cookie.set_http_only(false);
    cookie.set_secure(config.secure);
    cookie.set_same_site(config.same_site);
    cookie.set_path(config.path.as_ref().to_string());
    cookie.to_string()
}

mod guards;
use guards::{check_cookie_rules, is_websocket_upgrade, normalize_origin, origin_matches_allowed};
mod token;
use token::{mint_token, validate_token};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod rotation_tests;

#[cfg(test)]
mod upgrade_tests;
