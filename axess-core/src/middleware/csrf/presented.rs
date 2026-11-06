//! What a request presents: whether it is state-changing, the cookie and header/form
//! token it carries, and the check of that token against its session.

use super::*;

/// A state-changing request the CSRF check refuses.
pub(super) struct Refused(pub(super) crate::metrics::CsrfRefusal);

/// Decide whether a state-changing request carries a valid CSRF token.
///
/// Fails closed: with no session id there is nothing to bind the token to,
/// so the request is refused. The Origin/Referer check runs before any body
/// is buffered. On success the request is returned with its body intact (a
/// form-encoded body may have been read to find the token); on failure the
/// request is refused with [`Refused`].
pub(super) async fn validate_state_changing(
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
        return Err(Refused(crate::metrics::CsrfRefusal::NoSession));
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
        return Err(Refused(crate::metrics::CsrfRefusal::OriginMismatch));
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
            return Err(Refused(crate::metrics::CsrfRefusal::TokenUnreadable));
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
        return Err(Refused(crate::metrics::CsrfRefusal::TokenInvalid));
    }
    Ok(req)
}

pub(super) fn is_state_changing(method: &axum::http::Method) -> bool {
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

pub(super) fn extract_cookie_token(req: &Request<Body>, cookie_name: &str) -> Option<String> {
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
pub(super) async fn extract_presented_token(
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
    let field = url::form_urlencoded::parse(&bytes)
        .find(|(k, _)| k.as_ref() == config.form_field_name.as_ref())
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty());
    let restored = Request::from_parts(parts, Body::from(bytes));
    Ok((field, restored))
}
