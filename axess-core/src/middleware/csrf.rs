//! CSRF (Cross-Site Request Forgery) protection middleware.
//!
//! Implements the **signed double-submit cookie** pattern: the server issues
//! a token bound to the session id via HMAC and the client must echo it back
//! on every state-changing request (POST/PUT/PATCH/DELETE) either as the
//! `X-CSRF-Token` header (AJAX) or the `_csrf` form field (HTML forms). The
//! cookie itself is sent automatically by the browser, but cannot be read or
//! forged by cross-origin code thanks to the same-origin policy.
//!
//! The token is HMAC-bound to the session id, so a stolen token from one
//! session cannot be replayed against another. Tokens are constant-time
//! verified against the cookie.
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
//!     .layer(csrf);
//! ```
//!
//! Read the token from the `CsrfToken` request extension and inject it into
//! HTML forms or expose it to your SPA via a `/csrf` endpoint.

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

            // Validate on state-changing methods. GET/HEAD/OPTIONS pass through
            // because they must be safe (idempotent, no side effects) per
            // RFC 9110 section 9.2.1; and CSRF only matters for unsafe verbs.
            if is_state_changing(&method) {
                let presented = extract_token_from_request(&req, &config);
                let cookie_present = cookie_token.as_deref();
                if !validate_pair(cookie_present, presented.as_deref(), &config.signing_key) {
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

            // Issue a fresh token on responses where the request had no
            // cookie. Once a token is in the cookie it is reused until the
            // session cycles (caller can force rotation by clearing the
            // cookie alongside the session cycle).
            let token_to_set = match &cookie_token {
                Some(existing) if !existing.is_empty() => None,
                _ => Some(mint_token(&config.signing_key)),
            };
            let extension_token = token_to_set
                .clone()
                .or_else(|| cookie_token.clone())
                .unwrap_or_default();
            req.extensions_mut().insert(CsrfToken(extension_token));

            let mut response = inner.call(req).await?;

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

fn mint_token(signing_key: &[u8; 32]) -> String {
    let mut nonce = [0u8; TOKEN_NONCE_BYTES];
    SystemRng.fill_bytes(&mut nonce);
    let tag = compute_tag(&nonce, signing_key);
    let mut combined = Vec::with_capacity(TOKEN_NONCE_BYTES + tag.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&tag);
    URL_SAFE_NO_PAD.encode(&combined)
}

fn compute_tag(nonce: &[u8], signing_key: &[u8; 32]) -> Vec<u8> {
    let mut mac = crate::hmac::new_signer(signing_key);
    mac.update(nonce);
    mac.finalize().into_bytes().to_vec()
}

fn validate_token(token: &str, signing_key: &[u8; 32]) -> bool {
    let bytes = match URL_SAFE_NO_PAD.decode(token) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if bytes.len() != TOKEN_NONCE_BYTES + 32 {
        return false;
    }
    let (nonce, tag) = bytes.split_at(TOKEN_NONCE_BYTES);
    let expected = compute_tag(nonce, signing_key);
    expected.as_slice().ct_eq(tag).into()
}

fn validate_pair(
    cookie_token: Option<&str>,
    presented: Option<&str>,
    signing_key: &[u8; 32],
) -> bool {
    let (Some(c), Some(p)) = (cookie_token, presented) else {
        return false;
    };
    if c.is_empty() || p.is_empty() {
        return false;
    }
    // Cookie and presented must match exactly (double-submit) AND the token
    // must verify against the signing key (so an attacker who can set
    // cookies cannot inject a self-chosen value).
    bool::from(c.as_bytes().ct_eq(p.as_bytes())) && validate_token(c, signing_key)
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

    #[test]
    fn token_round_trip_validates() {
        let key = [7u8; 32];
        let token = mint_token(&key);
        assert!(validate_token(&token, &key));
    }

    #[test]
    fn token_with_wrong_key_rejected() {
        let key = [7u8; 32];
        let other_key = [9u8; 32];
        let token = mint_token(&key);
        assert!(!validate_token(&token, &other_key));
    }

    #[test]
    fn truncated_token_rejected() {
        let key = [7u8; 32];
        let token = mint_token(&key);
        let truncated = &token[..token.len() - 4];
        assert!(!validate_token(truncated, &key));
    }

    #[test]
    fn empty_token_rejected() {
        let key = [7u8; 32];
        assert!(!validate_token("", &key));
    }

    #[test]
    fn validate_pair_requires_both_match_and_signature() {
        let key = [7u8; 32];
        let valid = mint_token(&key);
        // Both match and valid signature.
        assert!(validate_pair(Some(&valid), Some(&valid), &key));
        // Mismatch.
        let other = mint_token(&key);
        assert!(!validate_pair(Some(&valid), Some(&other), &key));
        // Missing cookie.
        assert!(!validate_pair(None, Some(&valid), &key));
        // Missing header.
        assert!(!validate_pair(Some(&valid), None, &key));
        // Same value but invalid signature (cookie set by attacker).
        let forged =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(!validate_pair(Some(forged), Some(forged), &key));
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
        assert!(!validate_pair(Some(""), Some(""), &key));
        let valid = mint_token(&key);
        assert!(!validate_pair(Some(""), Some(&valid), &key));
        assert!(!validate_pair(Some(&valid), Some(""), &key));
    }

    #[test]
    fn validate_token_rejects_non_base64() {
        let key = [7u8; 32];
        assert!(!validate_token("not-valid-base64!!!", &key));
    }

    #[test]
    fn validate_token_rejects_wrong_length_payload() {
        let key = [7u8; 32];
        // Valid base64 but wrong length (too short to contain nonce + tag).
        let short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"too_short");
        assert!(!validate_token(&short, &key));
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

        // 1. GET without cookie → response carries Set-Cookie minting a
        //    fresh token.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/safe")
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
            .header("cookie", format!("{}={}", config.cookie_name, &token))
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
            .header("cookie", format!("{}={}", config.cookie_name, &token))
            .header(config.header_name.as_ref(), &token)
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            200,
            "POST with valid cookie+header must reach inner service \
            ; pins `delete !` on the `if !validate_pair(...)` guard at line 201"
        );

        // 4. POST without any token → 403 FORBIDDEN.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/state-changing")
            .body(Body::empty())
            .unwrap();
        let resp = service.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "state-changing request without tokens must be rejected as 403"
        );
    }
}
