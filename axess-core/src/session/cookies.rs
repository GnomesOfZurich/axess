//! Cookie-header parsing helpers.
//!
//! Single zero-alloc cookie scan shared by [`crate::session::layer`]
//! and [`crate::middleware::csrf`]. The `max_value_bytes` parameter is
//! mandatory so neither call site can forget the DoS cap: a malicious
//! client cannot ship arbitrary-length cookie values into the middleware
//! hot path.
//!
//! # Why borrow-and-iterate instead of `Cookie::split_parse`
//!
//! `tower_cookies::Cookie::split_parse` takes ownership of the input
//! string and re-allocates each parsed pair. On a hot middleware that
//! runs on every authenticated request, that was the dominant per-request
//! allocation in flame graphs. The borrow-based scan here keeps
//! everything on the request's existing buffer until the matching pair
//! is found, then allocates exactly once for the returned `String`.

use axum::http::HeaderMap;
use axum::http::header;

/// Default per-cookie-value DoS cap, in bytes.
///
/// 4 KiB leaves abundant headroom for application-supplied cookie
/// schemes (the legitimate axess session cookie is ~65 bytes;
/// `tower_cookies` recommends staying well under the 4 KiB RFC 6265
/// soft limit) while bounding the worst-case scan + clone a malicious
/// client can force on any middleware hot path that runs
/// [`extract_named_cookie`].
///
/// Provided so call sites don't have to invent their own constant; the
/// session layer and CSRF middleware both pass this. Adopters with a
/// stricter or looser policy can pass their own `usize` instead.
pub const MAX_COOKIE_VALUE_BYTES: usize = 4096;

/// Extract the value of a single cookie by name from a request's
/// `Cookie:` headers.
///
/// Every `Cookie:` header field is read (HTTP/2 clients may split cookies
/// across several fields), and every `name=value` pair in each. Returns
/// `Some(value.to_string())` when the name occurs with one distinct value
/// whose trimmed length is at most `max_value_bytes`. Returns `None` if:
///
/// - No `Cookie:` header is present, or none is valid UTF-8 (defensive:
///   production HTTP libs reject this earlier, but the parser must not
///   panic).
/// - No pair matches `name`.
/// - Every matching value is longer than `max_value_bytes`; a `tracing::warn!`
///   with the cookie name and observed length is emitted for each. An over-cap
///   duplicate next to an in-cap one is skipped, not fatal.
/// - The name occurs with **different** values. A browser sends several
///   cookies of one name when a sibling subdomain or a more specific path
///   has set one ("cookie tossing"), in an order the page cannot control, so
///   taking the first would let an attacker's value shadow the real one.
///   Refusing to choose treats the request as having no cookie. Repeats of
///   the same value are harmless and are accepted.
///
/// `max_value_bytes` is **mandatory**: there is no "no-cap" sentinel.
/// Pass a sensible constant per use site (the session layer and CSRF
/// middleware both pass 4096, which leaves headroom for application-
/// chosen cookie schemes while bounding the worst-case scan + clone).
pub fn extract_named_cookie(
    headers: &HeaderMap,
    name: &str,
    max_value_bytes: usize,
) -> Option<String> {
    let mut found: Option<&str> = None;
    for field in headers.get_all(header::COOKIE) {
        let Ok(raw) = field.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let pair = pair.trim();
            let mut split = pair.splitn(2, '=');
            // Skip malformed pairs (no `=`) by `continue`-ing rather than `?`.
            // `?` would propagate `None` and abort the whole scan, letting an
            // attacker who can inject a single cookie via prior XSS (or via a
            // downstream service that emits an unkeyed `Set-Cookie`) prepend
            // `garbage; ` to suppress every legitimate cookie that follows;
            // forcing the session layer to see "no cookie" on every request.
            let Some(pair_name) = split.next().map(str::trim) else {
                continue;
            };
            let Some(value) = split.next().map(str::trim) else {
                continue;
            };
            if pair_name != name {
                continue;
            }
            if value.len() > max_value_bytes {
                tracing::warn!(
                    cookie_name = name,
                    value_bytes = value.len(),
                    cap_bytes = max_value_bytes,
                    "cookie value exceeds DoS cap, rejecting"
                );
                continue;
            }
            match found {
                None => found = Some(value),
                Some(first) if first == value => {}
                Some(_) => {
                    tracing::warn!(
                        cookie_name = name,
                        "cookie name appears with different values; treating the cookie as absent"
                    );
                    return None;
                }
            }
        }
    }
    found.map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_cookie(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        h
    }

    #[test]
    fn returns_none_when_header_absent() {
        let h = HeaderMap::new();
        assert_eq!(extract_named_cookie(&h, "axess.sid", 4096), None);
    }

    #[test]
    fn extracts_single_named_cookie() {
        let h = headers_with_cookie("axess.sid=abc123");
        assert_eq!(
            extract_named_cookie(&h, "axess.sid", 4096),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn extracts_named_cookie_among_many() {
        let h = headers_with_cookie("foo=1; axess.sid=abc123; bar=hello");
        assert_eq!(
            extract_named_cookie(&h, "axess.sid", 4096),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn whitespace_around_pairs_is_tolerated() {
        let h = headers_with_cookie("  foo=1;  axess.sid =   abc123 ; bar=hello  ");
        assert_eq!(
            extract_named_cookie(&h, "axess.sid", 4096),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn returns_none_for_unmatched_name() {
        let h = headers_with_cookie("foo=1; bar=2");
        assert_eq!(extract_named_cookie(&h, "axess.sid", 4096), None);
    }

    #[test]
    fn rejects_value_exceeding_cap() {
        // 5-byte value with a 4-byte cap; must reject with None.
        let h = headers_with_cookie("axess.sid=12345");
        assert_eq!(extract_named_cookie(&h, "axess.sid", 4), None);
    }

    #[test]
    fn cap_at_exact_boundary_accepts() {
        // 4-byte value with a 4-byte cap; must accept.
        let h = headers_with_cookie("axess.sid=1234");
        assert_eq!(
            extract_named_cookie(&h, "axess.sid", 4),
            Some("1234".to_string())
        );
    }

    #[test]
    fn malformed_pair_without_equals_skipped() {
        // A leading pair without `=` MUST NOT short-circuit the scan;
        // an attacker who can inject one well-formed cookie via prior
        // XSS or a downstream service could otherwise prepend
        // `garbage; ` to deny every legitimate cookie that follows.
        // The valid `axess.sid=abc` after the malformed entry must
        // still be found.
        let h = headers_with_cookie("noequals; axess.sid=abc");
        assert_eq!(
            extract_named_cookie(&h, "axess.sid", 4096),
            Some("abc".to_string())
        );
    }

    #[test]
    fn malformed_pair_trailing_still_finds_earlier_match() {
        // Symmetric: a trailing malformed pair must not invalidate the
        // earlier valid match either.
        let h = headers_with_cookie("axess.sid=abc; noequals");
        assert_eq!(
            extract_named_cookie(&h, "axess.sid", 4096),
            Some("abc".to_string())
        );
    }

    #[test]
    fn empty_value_is_returned_as_empty_string() {
        // `axess.sid=` → empty value is a legitimate cookie shape.
        let h = headers_with_cookie("axess.sid=");
        assert_eq!(
            extract_named_cookie(&h, "axess.sid", 4096),
            Some(String::new())
        );
    }

    #[test]
    fn reads_a_cookie_from_a_later_header_field() {
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, HeaderValue::from_static("foo=1"));
        h.append(header::COOKIE, HeaderValue::from_static("axess.sid=abc"));
        assert_eq!(
            extract_named_cookie(&h, "axess.sid", 4096),
            Some("abc".to_string())
        );
    }

    #[test]
    fn over_cap_duplicate_is_skipped_not_fatal() {
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            HeaderValue::from_static("axess.sid=toolong"),
        );
        h.append(header::COOKIE, HeaderValue::from_static("axess.sid=ok"));
        assert_eq!(
            extract_named_cookie(&h, "axess.sid", 4),
            Some("ok".to_string())
        );
    }

    #[test]
    fn same_name_with_different_values_is_treated_as_absent() {
        let h = headers_with_cookie("axess.sid=attacker; axess.sid=real");
        assert_eq!(extract_named_cookie(&h, "axess.sid", 4096), None);
        let mut split = HeaderMap::new();
        split.append(header::COOKIE, HeaderValue::from_static("axess.sid=a"));
        split.append(header::COOKIE, HeaderValue::from_static("axess.sid=b"));
        assert_eq!(extract_named_cookie(&split, "axess.sid", 4096), None);
    }

    #[test]
    fn same_name_with_the_same_value_is_accepted() {
        let h = headers_with_cookie("axess.sid=abc; x=1; axess.sid=abc");
        assert_eq!(
            extract_named_cookie(&h, "axess.sid", 4096),
            Some("abc".to_string())
        );
    }
}
