//! CSRF (Cross-Site Request Forgery) protection middleware.
//!
//! Implements the **signed double-submit cookie** pattern: the server issues
//! a token bound to the session id via HMAC and the client must echo it back
//! on every state-changing request (POST/PUT/PATCH/DELETE) either as the
//! `X-CSRF-Token` header (AJAX) or the `_csrf` form field (HTML forms). The
//! cookie itself is sent automatically by the browser, but cannot be read or
//! forged by cross-origin code thanks to the same-origin policy.
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

use crate::session::layer::SessionHandle;

/// Default cookie name for the CSRF token.
pub const DEFAULT_CSRF_COOKIE: &str = "axess.csrf";

/// Default header name for the CSRF token on AJAX requests.
pub const DEFAULT_CSRF_HEADER: &str = "x-csrf-token";

/// Number of random bytes in the token nonce. 32 bytes = 256 bits.
const TOKEN_NONCE_BYTES: usize = 32;

use crate::cookies::MAX_COOKIE_VALUE_BYTES;

/// Configuration for [`CsrfLayer`].
#[derive(Clone)]
pub struct CsrfConfig {
    signing_key: Arc<[u8; 32]>,
    cookie_name: Arc<str>,
    header_name: Arc<str>,
    secure: bool,
    same_site: tower_cookies::cookie::SameSite,
    path: Arc<str>,
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
            secure: true,
            same_site: tower_cookies::cookie::SameSite::Lax,
            path: "/".into(),
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
                Some(handle) => Some(handle.0.read().await.id.to_string()),
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
                let Some(session_id) = session_id.as_deref() else {
                    tracing::warn!(
                        method = %method,
                        path = %req.uri().path(),
                        "csrf: no session id on state-changing request \
                         (CsrfLayer must be layered inside the session layer)"
                    );
                    return Ok((StatusCode::FORBIDDEN, "CSRF validation failed").into_response());
                };
                let presented = extract_token_from_request(&req, &config);
                let cookie_present = cookie_token.as_deref();
                if !validate_pair(
                    cookie_present,
                    presented.as_deref(),
                    session_id,
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
            let provisional_mint = match (&cookie_token, session_id.as_deref()) {
                (Some(existing), _) if !existing.is_empty() => None,
                (_, Some(sid_at_entry)) => Some(mint_token(sid_at_entry, &config.signing_key)),
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
            // the cookie the client currently holds — even if it was
            // valid at request entry — no longer validates against the
            // new id. Left alone the client would 403 on every state-
            // changing request until the browser cookie expires. Deciding
            // the mint post-handler closes that gap: if the cookie the
            // client will present next no longer verifies against the
            // effective (post-handler) session id, mint a fresh one and
            // ship it as Set-Cookie on this response.
            let session_id_after = match &session_handle {
                Some(handle) => Some(handle.0.read().await.id.to_string()),
                None => None,
            };
            // The token the client would present next request: either the
            // freshly-provisioned mint (if we issued one) or the cookie
            // they sent this request. Empty string means "no token to
            // present" — treat as absent.
            let effective_cookie = provisional_mint
                .as_deref()
                .or(cookie_token.as_deref())
                .filter(|t| !t.is_empty());
            let token_to_set = match (effective_cookie, session_id_after.as_deref()) {
                (Some(existing), Some(sid_after))
                    if validate_token(existing, sid_after, &config.signing_key) =>
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
                    Some(mint_token(sid_after, &config.signing_key))
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

fn extract_token_from_request(req: &Request<Body>, config: &CsrfConfig) -> Option<String> {
    // Form-field extraction would require buffering the body, which would
    // make the middleware unfriendly to streaming uploads. Applications
    // that need form-field CSRF should set the token in the
    // `X-CSRF-Token` header instead (e.g., via a hidden input read by
    // JavaScript). This matches the OWASP CSRF cheat sheet's recommended
    // approach for SPAs.
    let value = req.headers().get(config.header_name.as_ref())?;
    let s = value.to_str().ok()?;
    if s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

fn mint_token(session_id: &str, signing_key: &[u8; 32]) -> String {
    let mut nonce = [0u8; TOKEN_NONCE_BYTES];
    SystemRng.fill_bytes(&mut nonce);
    let tag = compute_tag(&nonce, session_id, signing_key);
    let mut combined = Vec::with_capacity(TOKEN_NONCE_BYTES + tag.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&tag);
    URL_SAFE_NO_PAD.encode(&combined)
}

fn compute_tag(nonce: &[u8], session_id: &str, signing_key: &[u8; 32]) -> Vec<u8> {
    // MAC over `nonce || session_id`. Binding the session id into the tag is
    // what makes a token minted under one session fail validation under
    // another: the nonce is echoed in the token but the id is not, so an
    // attacker cannot recompute the tag for a different session without the
    // key. The nonce has a fixed length (`TOKEN_NONCE_BYTES`), so the
    // concatenation is unambiguous and needs no separator.
    let mut mac = crate::hmac::new_signer(signing_key);
    mac.update(nonce);
    mac.update(session_id.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn validate_token(token: &str, session_id: &str, signing_key: &[u8; 32]) -> bool {
    let bytes = match URL_SAFE_NO_PAD.decode(token) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if bytes.len() != TOKEN_NONCE_BYTES + 32 {
        return false;
    }
    let (nonce, tag) = bytes.split_at(TOKEN_NONCE_BYTES);
    let expected = compute_tag(nonce, session_id, signing_key);
    expected.as_slice().ct_eq(tag).into()
}

fn validate_pair(
    cookie_token: Option<&str>,
    presented: Option<&str>,
    session_id: &str,
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
mod tests {
    use super::*;

    /// A stand-in session id for the crypto-level tests. Real ids are
    /// `SessionId` strings; the binding only cares that the same string is
    /// threaded through mint and validate.
    const SID: &str = "session-a";

    /// Build a `SessionHandle` carrying a deterministic session id derived
    /// from `seed`, matching the extension the session layer injects. Two
    /// calls with the same seed yield the same id (so a token minted under
    /// one can be replayed under a handle built from the same seed); distinct
    /// seeds yield distinct ids (so the cross-session tests can prove
    /// isolation).
    fn session_handle(seed: u64) -> SessionHandle {
        use crate::session::data::SessionData;
        use crate::session::id::SessionId;
        use crate::session::layer::SessionInner;
        use crate::testing::mock_random::MockRng;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let rng = MockRng::new(seed);
        let inner = SessionInner {
            id: SessionId::new(&rng),
            data: SessionData::default(),
            modified: false,
            regenerate: false,
            pre_cycle_id: None,
            pending_fingerprint: None,
            max_custom_bytes: 64 * 1024,
        };
        SessionHandle(Arc::new(RwLock::new(inner)))
    }

    #[test]
    fn token_round_trip_validates() {
        let key = [7u8; 32];
        let token = mint_token(SID, &key);
        assert!(validate_token(&token, SID, &key));
    }

    #[test]
    fn token_with_wrong_key_rejected() {
        let key = [7u8; 32];
        let other_key = [9u8; 32];
        let token = mint_token(SID, &key);
        assert!(!validate_token(&token, SID, &other_key));
    }

    #[test]
    fn truncated_token_rejected() {
        let key = [7u8; 32];
        let token = mint_token(SID, &key);
        let truncated = &token[..token.len() - 4];
        assert!(!validate_token(truncated, SID, &key));
    }

    #[test]
    fn empty_token_rejected() {
        let key = [7u8; 32];
        assert!(!validate_token("", SID, &key));
    }

    /// A token minted under session "A" validates under "A" but is rejected
    /// under a different session id "B" (same key, same nonce echoed in the
    /// token) — the documented cross-session isolation property. Pins the
    /// `mac.update(session_id.as_bytes())` line: dropping it would make the
    /// tag independent of the session id and this test would then accept the
    /// token under "B".
    #[test]
    fn token_bound_to_session_rejects_other_session() {
        let key = [7u8; 32];
        let token = mint_token("session-A", &key);
        // Same session: accepted.
        assert!(
            validate_token(&token, "session-A", &key),
            "token must validate under the session it was minted for"
        );
        // Different session: rejected even though key and token bytes are
        // identical.
        assert!(
            !validate_token(&token, "session-B", &key),
            "token minted under session A must NOT validate under session B"
        );
        // Same property through the double-submit path.
        assert!(
            validate_pair(Some(&token), Some(&token), "session-A", &key),
            "cookie==header token must validate under its own session"
        );
        assert!(
            !validate_pair(Some(&token), Some(&token), "session-B", &key),
            "cookie==header token must NOT validate under a different session"
        );
    }

    #[test]
    fn validate_pair_requires_both_match_and_signature() {
        let key = [7u8; 32];
        let valid = mint_token(SID, &key);
        // Both match and valid signature.
        assert!(validate_pair(Some(&valid), Some(&valid), SID, &key));
        // Mismatch.
        let other = mint_token(SID, &key);
        assert!(!validate_pair(Some(&valid), Some(&other), SID, &key));
        // Missing cookie.
        assert!(!validate_pair(None, Some(&valid), SID, &key));
        // Missing header.
        assert!(!validate_pair(Some(&valid), None, SID, &key));
        // Same value but invalid signature (cookie set by attacker).
        let forged =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(!validate_pair(Some(forged), Some(forged), SID, &key));
    }

    #[test]
    fn is_state_changing_only_unsafe_verbs() {
        assert!(!is_state_changing(&axum::http::Method::GET));
        assert!(!is_state_changing(&axum::http::Method::HEAD));
        assert!(!is_state_changing(&axum::http::Method::OPTIONS));
        assert!(is_state_changing(&axum::http::Method::POST));
        assert!(is_state_changing(&axum::http::Method::PUT));
        assert!(is_state_changing(&axum::http::Method::PATCH));
        assert!(is_state_changing(&axum::http::Method::DELETE));
    }

    #[test]
    fn validate_pair_rejects_empty_strings() {
        let key = [7u8; 32];
        assert!(!validate_pair(Some(""), Some(""), SID, &key));
        let valid = mint_token(SID, &key);
        assert!(!validate_pair(Some(""), Some(&valid), SID, &key));
        assert!(!validate_pair(Some(&valid), Some(""), SID, &key));
    }

    #[test]
    fn validate_token_rejects_non_base64() {
        let key = [7u8; 32];
        assert!(!validate_token("not-valid-base64!!!", SID, &key));
    }

    #[test]
    fn validate_token_rejects_wrong_length_payload() {
        let key = [7u8; 32];
        // Valid base64 but wrong length (too short to contain nonce + tag).
        let short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"too_short");
        assert!(!validate_token(&short, SID, &key));
    }

    #[test]
    fn extract_cookie_token_parses_correctly() {
        use axum::http::Request;

        let req = Request::builder()
            .header("cookie", "other=abc; axess.csrf=my_token; third=xyz")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_cookie_token(&req, "axess.csrf"),
            Some("my_token".to_string())
        );
    }

    #[test]
    fn extract_cookie_token_missing_returns_none() {
        use axum::http::Request;

        let req = Request::builder()
            .header("cookie", "other=abc")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_cookie_token(&req, "axess.csrf"), None);
    }

    #[test]
    fn extract_cookie_token_no_cookie_header_returns_none() {
        use axum::http::Request;

        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(extract_cookie_token(&req, "axess.csrf"), None);
    }

    #[test]
    fn extract_cookie_token_rejects_oversize_value() {
        use axum::http::Request;

        let oversize = "x".repeat(MAX_COOKIE_VALUE_BYTES + 1);
        let header = format!("axess.csrf={oversize}");
        let req = Request::builder()
            .header("cookie", header)
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_cookie_token(&req, "axess.csrf"), None);
    }

    #[test]
    fn extract_cookie_token_accepts_value_at_cap() {
        use axum::http::Request;

        let at_cap = "x".repeat(MAX_COOKIE_VALUE_BYTES);
        let header = format!("axess.csrf={at_cap}");
        let req = Request::builder()
            .header("cookie", header)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_cookie_token(&req, "axess.csrf").map(|v| v.len()),
            Some(MAX_COOKIE_VALUE_BYTES)
        );
    }

    // ── Mutation-coverage tests ──────────────────────────────────────

    /// `CsrfToken::as_str` returns the inner string verbatim;
    /// pins both `-> ""` and `-> "xyzzy"` body replacements.
    #[test]
    fn csrf_token_as_str_returns_inner_value() {
        let t = CsrfToken("abc.defg.hij".to_string());
        assert_eq!(t.as_str(), "abc.defg.hij");
        let empty = CsrfToken(String::new());
        assert_eq!(empty.as_str(), "");
    }

    /// `extract_token_from_request` reads the configured header
    /// and returns its value as `Option<String>`. Pins three body
    /// replacements: `-> None` (would break header-based double-submit
    /// for every request), `Some(String::new())` (would compare the
    /// presented token as empty, defeating ct_eq match), and
    /// `Some("xyzzy")` (would brick header extraction to a constant).
    #[test]
    fn extract_token_from_request_returns_header_value() {
        use axum::http::Request;

        let key = [9u8; 32];
        let config = CsrfConfig::new(key);

        // Header present with a real value.
        let req = Request::builder()
            .header(config.header_name.as_ref(), "presented-csrf-value")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_token_from_request(&req, &config),
            Some("presented-csrf-value".to_string()),
            "must return the exact header value, not None / empty / 'xyzzy'"
        );

        // Header absent → None.
        let req = Request::builder().body(Body::empty()).unwrap();
        assert!(
            extract_token_from_request(&req, &config).is_none(),
            "missing header must return None, not Some(...)"
        );

        // Empty header value → None (the function explicitly normalises
        // empty → None so callers don't have to recheck).
        let req = Request::builder()
            .header(config.header_name.as_ref(), "")
            .body(Body::empty())
            .unwrap();
        assert!(
            extract_token_from_request(&req, &config).is_none(),
            "empty header must return None"
        );
    }

    /// Drives `CsrfService` end-to-end via the full tower
    /// stack so the call-path mutations get observed:
    /// - **GET without cookie** must mint a fresh cookie via
    ///   `Set-Cookie` (pins `match guard !existing.is_empty()` against
    ///   `false`; the guard mutant would never mint, so no cookie
    ///   would appear).
    /// - **GET with a non-empty cookie** must NOT mint a new cookie
    ///   (pins the same guard against `true` and `delete !`, both of
    ///   which would force a fresh mint on every request and
    ///   silently break token persistence).
    /// - **POST with valid cookie+header pair** must reach the inner
    ///   service (pins `delete !` on the `if !validate_pair(...)`
    ///   guard at line 201; the mutant would 403 every successful
    ///   request).
    /// - **POST with no token** must return 403 (additional pin on
    ///   the validate-and-reject path).
    #[tokio::test]
    async fn csrf_service_end_to_end_drives_call_path() {
        use axum::http::{Method, Request};
        use std::convert::Infallible;
        use tower::{Layer, ServiceExt, service_fn};

        // `service_fn` provides an always-ready `poll_ready` for free, so
        // the mock only needs to handle `call`. The trace use of `req`
        // keeps the closure param meaningful.
        let echo_body = service_fn(|req: Request<Body>| {
            tracing::trace!(method = %req.method(), uri = %req.uri(), "EchoBody call");
            async move {
                Ok::<_, Infallible>(Response::builder().status(200).body(Body::empty()).unwrap())
            }
        });

        let key = [13u8; 32];
        let config = CsrfConfig::new(key);
        let service = CsrfLayer::new(config.clone()).layer(echo_body);

        // A single session handle threaded through every request below so the
        // token minted in step 1 stays bound to the same session id it is
        // replayed under in step 3.
        let handle = session_handle(1);

        // 1. GET without cookie → response carries Set-Cookie minting a
        //    fresh token.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/safe")
            .extension(handle.clone())
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200, "safe verb must pass through");
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("GET without cookie must mint a fresh CSRF cookie")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            set_cookie.starts_with(&format!("{}=", config.cookie_name)),
            "minted cookie must be named {}",
            config.cookie_name
        );

        // Extract the minted token from the Set-Cookie header for reuse below.
        let token = set_cookie
            .split('=')
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(!token.is_empty(), "minted cookie value must not be empty");

        // 2. GET with a non-empty cookie → no new Set-Cookie is appended.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/safe")
            .header("cookie", format!("{}={}", config.cookie_name, token))
            .extension(handle.clone())
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert!(
            resp.headers().get(header::SET_COOKIE).is_none(),
            "existing non-empty cookie must NOT trigger a fresh mint \
            ; pins `match guard !existing.is_empty() -> false` and `delete !`"
        );

        // 2b. GET with an EMPTY cookie value → fresh mint must happen.
        // Pins `match guard !existing.is_empty() -> true` (mutant would
        // suppress the mint even for empty cookies, leaving the client
        // with a permanent empty bucket and no token to double-submit).
        let req = Request::builder()
            .method(Method::GET)
            .uri("/safe")
            .header("cookie", format!("{}=", config.cookie_name))
            .extension(handle.clone())
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let minted = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect(
                "empty cookie value must trigger a fresh mint \
                 (otherwise the client never gets a token)",
            )
            .to_str()
            .unwrap();
        assert!(
            minted.starts_with(&format!("{}=", config.cookie_name)),
            "minted cookie must be named {}",
            config.cookie_name
        );
        let minted_value = minted.split('=').nth(1).unwrap().split(';').next().unwrap();
        assert!(
            !minted_value.is_empty(),
            "minted cookie value must not itself be empty"
        );

        // 3. POST with valid cookie+header pair → must reach inner.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/state-changing")
            .header("cookie", format!("{}={}", config.cookie_name, token))
            .header(config.header_name.as_ref(), &token)
            .extension(handle.clone())
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            200,
            "POST with valid cookie+header must reach inner service \
            ; pins `delete !` on the `if !validate_pair(...)` guard at line 201"
        );

        // 4. POST without any token (but with a session handle) → 403.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/state-changing")
            .extension(handle.clone())
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "state-changing request without tokens must be rejected as 403"
        );
    }

    /// End-to-end proof of the session-binding property through the full
    /// middleware stack: a token minted while carrying session A's handle is
    /// accepted on a POST that carries session A's handle, but rejected on an
    /// otherwise-identical POST that carries session B's handle. This is the
    /// behaviour the module docs promise — cross-session replay fails.
    #[tokio::test]
    async fn csrf_service_rejects_token_replayed_under_different_session() {
        use axum::http::{Method, Request};
        use std::convert::Infallible;
        use tower::{Layer, ServiceExt, service_fn};

        let echo_body = service_fn(|_req: Request<Body>| async move {
            Ok::<_, Infallible>(Response::builder().status(200).body(Body::empty()).unwrap())
        });

        let key = [21u8; 32];
        let config = CsrfConfig::new(key);
        let service = CsrfLayer::new(config.clone()).layer(echo_body);

        let handle_a = session_handle(1);
        let handle_b = session_handle(2);

        // Mint a token under session A via a safe GET.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/safe")
            .extension(handle_a.clone())
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("GET under session A must mint a token")
            .to_str()
            .unwrap()
            .to_string();
        let token = set_cookie
            .split('=')
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(!token.is_empty());

        // Replay the A-minted token on a POST carrying session B → 403.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/state-changing")
            .header("cookie", format!("{}={}", config.cookie_name, token))
            .header(config.header_name.as_ref(), &token)
            .extension(handle_b.clone())
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a token minted under session A must be rejected under session B"
        );

        // The same token on a POST carrying session A → 200.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/state-changing")
            .header("cookie", format!("{}={}", config.cookie_name, token))
            .header(config.header_name.as_ref(), &token)
            .extension(handle_a.clone())
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            200,
            "the A-minted token must still be accepted under session A"
        );
    }

    /// Fail-closed: a state-changing request with an otherwise-valid
    /// cookie+header pair but NO session handle (as happens when `CsrfLayer`
    /// is mis-ordered outside the session layer) is rejected rather than
    /// validated against an unbound token. Pins the `let Some(session_id) =
    /// ... else { return 403 }` guard.
    #[tokio::test]
    async fn csrf_service_fails_closed_without_session_handle() {
        use axum::http::{Method, Request};
        use std::convert::Infallible;
        use tower::{Layer, ServiceExt, service_fn};

        let echo_body = service_fn(|_req: Request<Body>| async move {
            Ok::<_, Infallible>(Response::builder().status(200).body(Body::empty()).unwrap())
        });

        let key = [23u8; 32];
        let config = CsrfConfig::new(key);
        let service = CsrfLayer::new(config.clone()).layer(echo_body);

        // A token that is internally valid for *some* session.
        let token = mint_token("some-session", &key);

        // POST with matching cookie+header but no session handle in the
        // extensions → fail closed with 403.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/state-changing")
            .header("cookie", format!("{}={}", config.cookie_name, token))
            .header(config.header_name.as_ref(), &token)
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "no session handle on a state-changing request must fail closed (403)"
        );
    }

    /// Post-handler re-mint: a safe GET that carries a cookie no longer
    /// bound to the current session id (as happens after any handler
    /// upstream of a `session.regenerate()`, or when the handler itself
    /// regenerates) receives a fresh `Set-Cookie` in the response bound
    /// to the current session id. Without this, the client would be stuck
    /// with a permanently-stale cookie and every subsequent state-
    /// changing request would 403 until the browser cookie expired.
    #[tokio::test]
    async fn csrf_service_remints_stale_cookie_on_safe_verb() {
        use axum::http::{Method, Request};
        use std::convert::Infallible;
        use tower::{Layer, ServiceExt, service_fn};

        let echo_body = service_fn(|_req: Request<Body>| async move {
            Ok::<_, Infallible>(Response::builder().status(200).body(Body::empty()).unwrap())
        });

        let key = [29u8; 32];
        let config = CsrfConfig::new(key);
        let service = CsrfLayer::new(config.clone()).layer(echo_body);

        // A handle for session A carries a cookie that was minted under
        // a different session. This mirrors what happens after a
        // regenerate: the cookie is stale relative to the session id
        // that the request now carries.
        let handle_a = session_handle(1);
        let stale_token = mint_token("some-other-session", &key);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/safe")
            .header("cookie", format!("{}={}", config.cookie_name, stale_token))
            .extension(handle_a.clone())
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200, "safe verb must pass through");

        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("stale cookie on safe verb must trigger a fresh mint")
            .to_str()
            .unwrap()
            .to_string();
        let refreshed = set_cookie
            .split('=')
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(!refreshed.is_empty(), "refreshed cookie must not be empty");
        assert_ne!(
            refreshed, stale_token,
            "refreshed cookie must differ from the stale one"
        );

        // The refreshed cookie must validate against session A (the id
        // on the handle at request time), not the stale binding.
        let sid_a = handle_a.0.read().await.id.to_string();
        assert!(
            validate_token(&refreshed, &sid_a, &key),
            "refreshed cookie must be HMAC-bound to the current session id"
        );
    }

    /// Post-handler re-mint after mid-request rotation: a safe GET whose
    /// inner service calls `regenerate()` on the session handle (as a
    /// factor-chain-completion path would) receives a fresh `Set-Cookie`
    /// bound to the post-rotation id. This is the case that makes the
    /// login flow survive `AuthnService::verify_factor` cycling the id
    /// without leaving the client tokenless.
    #[tokio::test]
    async fn csrf_service_remints_when_handler_rotates_session() {
        use axum::http::{Method, Request};
        use std::convert::Infallible;
        use tower::{Layer, ServiceExt, service_fn};

        // Inner service that rotates the session id via the handle in
        // the request extensions before responding — mirrors what
        // `complete_factor_step` does today after Guest→Authenticated.
        let rotating_body = service_fn(|req: Request<Body>| async move {
            if let Some(handle) = req.extensions().get::<SessionHandle>() {
                let mut guard = handle.0.write().await;
                guard.rotate_id();
                guard.modified = true;
            }
            Ok::<_, Infallible>(Response::builder().status(200).body(Body::empty()).unwrap())
        });

        let key = [31u8; 32];
        let config = CsrfConfig::new(key);
        let service = CsrfLayer::new(config.clone()).layer(rotating_body);

        let handle = session_handle(1);
        let sid_before = handle.0.read().await.id.to_string();
        let token_before = mint_token(&sid_before, &key);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/rotate")
            .header("cookie", format!("{}={}", config.cookie_name, token_before))
            .extension(handle.clone())
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let sid_after = handle.0.read().await.id.to_string();
        assert_ne!(
            sid_before, sid_after,
            "test precondition: inner service rotated the session id"
        );

        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("session rotation mid-request must trigger a fresh Set-Cookie")
            .to_str()
            .unwrap()
            .to_string();
        let refreshed = set_cookie
            .split('=')
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert_ne!(
            refreshed, token_before,
            "refreshed cookie must differ from the pre-rotation token"
        );
        assert!(
            validate_token(&refreshed, &sid_after, &key),
            "refreshed cookie must bind to the post-rotation session id"
        );
    }

    /// End-to-end through the REAL `SessionLayer` (not a mock handle): a CSRF
    /// token minted for a fresh guest on a safe GET must validate on that
    /// guest's next state-changing POST — the shape of the login flow. The
    /// token is HMAC-bound to the session id the request ran under, so the
    /// response cookie MUST carry that same id.
    ///
    /// Regression guard for the 0.3.3 fix: pre-fix, `finalize_session` minted a
    /// *second*, different id for a fresh guest's response cookie (it took the
    /// id-cycle branch on `existing_id.is_none()`), so the token was bound to
    /// one id while `axess.sid` carried another and this POST returned `403`.
    /// The mock-handle tests above stub the session id and so cannot see this
    /// cross-layer interaction; stacking the real `SessionLayer` here is what
    /// exposes it. Runs under `cargo test --lib`.
    #[tokio::test]
    async fn csrf_token_for_fresh_guest_survives_session_finalize() {
        use crate::session::layer::SessionLayer;
        use crate::session::store::MemorySessionStore;
        use axum::Router;
        use axum::http::Method;
        use axum::routing::{get, post};
        use tower::ServiceExt;

        let session_layer =
            SessionLayer::new(MemorySessionStore::new(), [42u8; 32]).with_secure(false);
        let csrf_layer = CsrfLayer::new(CsrfConfig::new([7u8; 32]).secure(false));
        let app = Router::new()
            .route("/safe", get(|| async { "ok" }))
            .route("/change", post(|| async { "changed" }))
            .layer(csrf_layer) // inner: sees the SessionHandle
            .layer(session_layer); // outer: injects the handle first

        // 1. Safe GET, no cookies → mints axess.sid + the CSRF cookie, both
        //    bound to the same fresh-guest session id.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/safe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie = |name: &str| {
            resp.headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|hv| hv.to_str().ok())
                .find_map(|c| {
                    let (k, v) = c.split(';').next()?.split_once('=')?;
                    (k.trim() == name).then(|| v.trim().to_string())
                })
        };
        let sid = cookie("axess.sid").expect("GET must set the session cookie");
        let csrf = cookie(DEFAULT_CSRF_COOKIE).expect("GET must mint the CSRF cookie");

        // 2. The fresh guest's first state-changing request — the login POST
        //    shape: double-submit cookie + header, carrying the same session id.
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/change")
                    .header(
                        "cookie",
                        format!("axess.sid={sid}; {DEFAULT_CSRF_COOKIE}={csrf}"),
                    )
                    .header(DEFAULT_CSRF_HEADER, &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a CSRF token minted for a fresh guest must validate on its next \
             state-changing request; a 403 here means finalize handed the \
             response cookie a different session id than the token was bound to"
        );
    }
}
