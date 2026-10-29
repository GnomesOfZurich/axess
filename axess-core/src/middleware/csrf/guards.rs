//! Request and configuration guards of the CSRF layer: origin matching, the
//! WebSocket upgrade test and the cookie-name prefix rules.

use axum::{body::Body, extract::Request, http::header};
use std::sync::Arc;
use url::Url;

/// Canonicalize an origin string ("scheme://host[:port]") to a form suitable
/// for exact-match comparison against the allow-list.
///
/// Delegates to [`url::Url::origin`] so the comparison honours RFC 6454:
/// scheme + host are compared case-insensitively, `userinfo@` is stripped,
/// and the default port is dropped for `http` / `https`. Tuple origins
/// serialize to `"scheme://host[:port]"`; opaque origins (`"null"`,
/// non-tuple-origin schemes) are rejected.
pub(super) fn normalize_origin(raw: &str) -> Option<String> {
    let parsed = Url::parse(raw).ok()?;
    match parsed.origin() {
        url::Origin::Tuple(..) => Some(parsed.origin().ascii_serialization()),
        url::Origin::Opaque(_) => None,
    }
}

/// Compare the request's `Origin` (fallback `Referer`-derived) origin
/// against the allowed list. Any missing / malformed / non-matching
/// case fails closed.
pub(super) fn origin_matches_allowed(req: &Request<Body>, allowed: &[Arc<str>]) -> bool {
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

/// Whether `req` asks to upgrade to a WebSocket: `Upgrade: websocket` with
/// `Connection` listing `upgrade`, both compared case-insensitively.
pub(super) fn is_websocket_upgrade(req: &Request<Body>) -> bool {
    let headers = req.headers();
    let names = |name: header::HeaderName, token: &str| {
        headers.get_all(name).iter().any(|value| {
            value
                .to_str()
                .is_ok_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
        })
    };
    names(header::UPGRADE, "websocket") && names(header::CONNECTION, "upgrade")
}

/// Refuse a cookie name whose prefix the configuration cannot honour. A
/// browser drops a `__Host-` or `__Secure-` cookie set without `Secure`
/// (and a `__Host-` one with a path other than `/`), so the CSRF cookie
/// would never arrive and every state-changing request would fail.
///
/// # Panics
///
/// On such a combination, as `SessionConfigBuilder::build` does for the
/// session cookie.
pub(super) fn check_cookie_rules(name: &str, secure: bool, path: &str) {
    if name.starts_with("__Host-") {
        assert!(
            secure,
            "CsrfConfig: cookie name `{name}` requires `secure = true`"
        );
        assert!(
            path == "/",
            "CsrfConfig: cookie name `{name}` requires `path = \"/\"`"
        );
    } else if name.starts_with("__Secure-") {
        assert!(
            secure,
            "CsrfConfig: cookie name `{name}` requires `secure = true`"
        );
    }
}
