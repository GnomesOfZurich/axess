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
//! **Rotation-mid-request footgun.** The token in the request extension
//! is bound to the session id observed at request entry. If the handler
//! both (a) reads `CsrfToken` from the extensions to embed in a body
//! rendered on the same response AND (b) rotates the session
//! (e.g. `handle.rotate_id()` after login), the response `Set-Cookie`
//! ships a *different* token bound to the post-rotation id; the
//! embedded value silently mismatches and the client's next
//! state-changing request 403s. Handlers that rotate MUST redirect
//! (302) rather than render inline, or re-read the token from the
//! post-rotation `SessionHandle` before embedding.

use axess_rng::{SecureRng, SystemRng};
use axum::{
    body::Body,
    http::{HeaderValue, Request, Response, StatusCode, header},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use subtle::ConstantTimeEq;
use tower::{Layer, Service};
use url::Url;

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
    signing_key: Arc<[u8; 32]>,
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
    /// Create a new config with the given HMAC signing key. Reuse the same
    /// key as your session layer so token rotation is handled automatically
    /// when sessions cycle.
    pub fn new(signing_key: [u8; 32]) -> Self {
        Self {
            signing_key: Arc::new(signing_key),
            cookie_name: DEFAULT_CSRF_COOKIE.into(),
            header_name: DEFAULT_CSRF_HEADER.into(),
            form_field_name: DEFAULT_CSRF_FORM_FIELD.into(),
            form_body_limit: DEFAULT_CSRF_FORM_BODY_LIMIT,
            secure: true,
            same_site: tower_cookies::cookie::SameSite::Lax,
            path: "/".into(),
            allowed_origins: Arc::from(Vec::new()),
        }
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

/// The CSRF token to inject into form fields or AJAX headers.
///
/// Available as a request extension after the [`CsrfLayer`] runs. The token
/// is rotated automatically per response when no cookie was presented.
#[derive(Clone, Debug)]
/// The CSRF token for the current request.
///
/// Available as a request extension after [`CsrfLayer`] runs. Inject it
/// into HTML forms as a hidden field or expose it to your SPA via a
/// dedicated endpoint. The token is HMAC-bound to the session and
/// rotated automatically when no cookie was present.
pub struct CsrfToken(pub String);

impl CsrfToken {
    /// Borrow the token as a `&str` for templating into forms or headers.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Tower layer that issues and validates CSRF tokens.
#[derive(Clone)]
pub struct CsrfLayer {
    config: CsrfConfig,
}

impl CsrfLayer {
    /// Construct a layer that issues and validates CSRF tokens with `config`.
    pub fn new(config: CsrfConfig) -> Self {
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
            let method = req.method().clone();

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

            // Validate on state-changing methods. GET/HEAD/OPTIONS pass through
            // because they must be safe (idempotent, no side effects) per
            // RFC 9110 section 9.2.1; and CSRF only matters for unsafe verbs.
            if is_state_changing(&method) {
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
                    return Ok((StatusCode::FORBIDDEN, "CSRF validation failed").into_response());
                };

                // Origin/Referer defence in depth, if configured. Runs
                // BEFORE the body-buffering path so a mismatched Origin
                // never triggers form-body extraction.
                if !config.allowed_origins.is_empty()
                    && !origin_matches_allowed(&req, &config.allowed_origins)
                {
                    tracing::warn!(
                        method = %method,
                        path = %req.uri().path(),
                        "csrf: Origin/Referer validation failed"
                    );
                    return Ok((StatusCode::FORBIDDEN, "CSRF validation failed").into_response());
                }

                // Extract the presented token, possibly by buffering a
                // form-urlencoded body. `req` may be re-created with its
                // body restored.
                let (extracted, req_after) = match extract_presented_token(req, &config).await {
                    Ok(pair) => pair,
                    Err(reason) => {
                        tracing::warn!(
                            method = %method,
                            reason = %reason,
                            "csrf: request rejected during token extraction"
                        );
                        return Ok(
                            (StatusCode::FORBIDDEN, "CSRF validation failed").into_response()
                        );
                    }
                };
                req = req_after;
                let presented = extracted;
                let cookie_present = cookie_token.as_deref();
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
                    return Ok((StatusCode::FORBIDDEN, "CSRF validation failed").into_response());
                }
            }

            // Provisional mint decision before the handler runs. Handlers
            // that read `CsrfToken` from the request extension (to embed
            // in an HTML form, say) need SOME value; give them either
            // the presented cookie or a fresh mint bound to the current
            // session id. A token can only be minted when a session id
            // is present to bind it to; without one we leave the client
            // tokenless rather than issue an unbound token.
            let provisional_mint = match (&cookie_token, session_id.as_ref()) {
                (Some(existing), _) if !existing.is_empty() => None,
                (_, Some(sid_at_entry)) => {
                    Some(mint_token(sid_at_entry.as_bytes(), &config.signing_key))
                }
                (_, None) => None,
            };
            let extension_token = provisional_mint
                .clone()
                .or_else(|| cookie_token.clone())
                .unwrap_or_default();
            req.extensions_mut().insert(CsrfToken(extension_token));

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
            // The token the client would present next request: either the
            // freshly-provisioned mint (if we issued one) or the cookie
            // they sent this request. Empty string means "no token to
            // present": treat as absent.
            let effective_cookie = provisional_mint
                .as_deref()
                .or(cookie_token.as_deref())
                .filter(|t| !t.is_empty());
            let token_to_set = match (effective_cookie, session_id_after.as_ref()) {
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
                    // after `session.regenerate()`). Mint fresh so the
                    // client's next request presents a valid pair.
                    Some(mint_token(sid_after.as_bytes(), &config.signing_key))
                }
                (_, None) => None,
            };

            if let Some(new_token) = token_to_set {
                let cookie = build_cookie(&config, &new_token);
                if let Ok(hv) = HeaderValue::from_str(&cookie) {
                    response.headers_mut().append(header::SET_COOKIE, hv);
                }
            }

            Ok(response)
        })
    }
}

fn is_state_changing(method: &axum::http::Method) -> bool {
    matches!(
        *method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
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

/// Canonicalize an origin string ("scheme://host[:port]") to a form suitable
/// for exact-match comparison against the allow-list.
///
/// Delegates to [`url::Url::origin`] so the comparison honours RFC 6454:
/// scheme + host are compared case-insensitively, `userinfo@` is stripped,
/// and the default port is dropped for `http` / `https`. Tuple origins
/// serialize to `"scheme://host[:port]"`; opaque origins (`"null"`,
/// non-tuple-origin schemes) are rejected.
fn normalize_origin(raw: &str) -> Option<String> {
    let parsed = Url::parse(raw).ok()?;
    match parsed.origin() {
        url::Origin::Tuple(..) => Some(parsed.origin().ascii_serialization()),
        url::Origin::Opaque(_) => None,
    }
}

/// Compare the request's `Origin` (fallback `Referer`-derived) origin
/// against the allowed list. Any missing / malformed / non-matching
/// case fails closed.
fn origin_matches_allowed(req: &Request<Body>, allowed: &[Arc<str>]) -> bool {
    // Origin first: browsers set it on cross-origin state-changing
    // requests. `Origin: null` (opaque origin, cross-origin redirect,
    // sandboxed iframe) is normalized to `None` and treated as failure.
    if let Some(header) = req.headers().get(header::ORIGIN) {
        let Ok(s) = header.to_str() else { return false };
        let Some(origin) = normalize_origin(s) else {
            return false;
        };
        return allowed.iter().any(|a| a.as_ref() == origin);
    }

    // Fall back to Referer: some browsers omit Origin on same-origin
    // POSTs. Extract the origin component and match. If Referer is
    // absent AND Origin was absent, fail closed (attacker can strip
    // both).
    let Some(referer) = req.headers().get(header::REFERER) else {
        return false;
    };
    let Ok(referer_str) = referer.to_str() else {
        return false;
    };
    let Some(origin) = normalize_origin(referer_str) else {
        return false;
    };
    allowed.iter().any(|a| a.as_ref() == origin)
}

fn mint_token(session_id: &[u8], signing_key: &[u8; 32]) -> String {
    let mut nonce = [0u8; TOKEN_NONCE_BYTES];
    SystemRng.fill_bytes(&mut nonce);
    let tag = compute_tag(&nonce, session_id, signing_key);
    let mut combined = Vec::with_capacity(TOKEN_NONCE_BYTES + tag.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&tag);
    URL_SAFE_NO_PAD.encode(&combined)
}

fn compute_tag(nonce: &[u8], session_id: &[u8], signing_key: &[u8; 32]) -> [u8; 32] {
    // MAC over `nonce || session_id`. Binding the session id into the tag is
    // what makes a token minted under one session fail validation under
    // another: the nonce is echoed in the token but the id is not, so an
    // attacker cannot recompute the tag for a different session without the
    // key. The nonce has a fixed length (`TOKEN_NONCE_BYTES`), so the
    // concatenation is unambiguous and needs no separator.
    let mut mac = crate::hmac::new_signer(signing_key);
    mac.update(nonce);
    mac.update(session_id);
    mac.finalize().into_bytes().into()
}

fn validate_token(token: &str, session_id: &[u8], signing_key: &[u8; 32]) -> bool {
    let bytes = match URL_SAFE_NO_PAD.decode(token) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if bytes.len() != TOKEN_NONCE_BYTES + 32 {
        return false;
    }
    let (nonce, tag) = bytes.split_at(TOKEN_NONCE_BYTES);
    let expected = compute_tag(nonce, session_id, signing_key);
    expected.ct_eq(tag).into()
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

#[cfg(test)]
mod tests;
