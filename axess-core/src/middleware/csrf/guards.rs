//! Request and configuration guards of the CSRF layer: origin matching, the
//! WebSocket upgrade test and the cookie-name prefix rules.

use axum::{body::Body, extract::Request, http::header};
use cookie::SameSite;
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
pub(crate) fn normalize_origin(raw: &str) -> Option<String> {
    let parsed = Url::parse(raw).ok()?;
    match parsed.origin() {
        url::Origin::Tuple(..) => Some(parsed.origin().ascii_serialization()),
        url::Origin::Opaque(_) => None,
    }
}

/// Compare the request's `Origin` (fallback `Referer`-derived) origin
/// against the allowed list. Any missing / malformed / non-matching
/// case fails closed.
pub(crate) fn origin_matches_allowed(req: &Request<Body>, allowed: &[Arc<str>]) -> bool {
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

/// Whether the request's `Origin`, when it has one, is the request's own
/// host under an expected scheme: `https` alone when the deployment's
/// cookies are `Secure`, `http` or `https` otherwise. The host is the `Host`
/// header, or the request target's authority (HTTP/2 carries it there).
///
/// A request with no `Origin` passes: a browser sends one on every
/// WebSocket upgrade, so its absence means a non-browser client, which has
/// no ambient cookies a cross-site page could borrow. A malformed `Origin`,
/// an opaque one (`null`), or a request with no host fails closed.
pub(crate) fn origin_is_own_host(req: &Request<Body>, secure: bool) -> bool {
    let Some(header) = req.headers().get(header::ORIGIN) else {
        return true;
    };
    let Some(origin) = header.to_str().ok().and_then(normalize_origin) else {
        return false;
    };
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()));
    let Some(host) = host else {
        return false;
    };
    let schemes: &[&str] = if secure {
        &["https"]
    } else {
        &["http", "https"]
    };
    schemes
        .iter()
        .filter_map(|scheme| normalize_origin(&format!("{scheme}://{host}")))
        .any(|own| own == origin)
}

/// Whether `req` asks to upgrade to a WebSocket: `Upgrade: websocket` with
/// `Connection` listing `upgrade`, both compared case-insensitively.
pub(crate) fn is_websocket_upgrade(req: &Request<Body>) -> bool {
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

/// Refuse cookie attributes no browser stores. A browser drops a `__Host-`
/// or `__Secure-` cookie set without `Secure` (and a `__Host-` one with a
/// path other than `/`), and a `SameSite=None` cookie without `Secure`, so
/// the CSRF cookie would never arrive and every state-changing request
/// would fail.
///
/// # Panics
///
/// On such a combination, as `SessionConfigBuilder::build` does for the
/// session cookie.
pub(super) fn check_cookie_rules(name: &str, secure: bool, path: &str, same_site: SameSite) {
    assert!(
        crate::session::config::is_valid_cookie_path(path),
        "CsrfConfig: path must start with '/' and contain no ';' or control characters"
    );
    assert!(
        same_site != SameSite::None || secure,
        "CsrfConfig: `SameSite=None` requires `secure = true` (browsers reject the cookie otherwise)"
    );
    use crate::session::config::has_prefix_ignoring_case;
    if has_prefix_ignoring_case(name, "__Host-") {
        assert!(
            secure,
            "CsrfConfig: cookie name `{name}` requires `secure = true`"
        );
        assert!(
            path == "/",
            "CsrfConfig: cookie name `{name}` requires `path = \"/\"`"
        );
    } else if has_prefix_ignoring_case(name, "__Secure-") {
        assert!(
            secure,
            "CsrfConfig: cookie name `{name}` requires `secure = true`"
        );
    }
}
