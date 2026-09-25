//! Unit tests for the CSRF middleware.
//!
//! Extracted from `csrf.rs` per the 200-LoC inline-test rule in
//! AGENTS.md: the production file carried 1003 lines of tests around
//! 698 lines of logic.

use super::*;

/// A stand-in session id for the crypto-level tests. Real ids are
/// `SessionId::as_bytes()` slices; the binding only cares that the same
/// bytes are threaded through mint and validate.
const SID: &[u8] = b"session-a";

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
/// token): the documented cross-session isolation property. Pins the
/// `mac.update(session_id.as_bytes())` line: dropping it would make the
/// tag independent of the session id and this test would then accept the
/// token under "B".
#[test]
fn token_bound_to_session_rejects_other_session() {
    let key = [7u8; 32];
    let token = mint_token(b"session-A".as_slice(), &key);
    // Same session: accepted.
    assert!(
        validate_token(&token, b"session-A".as_slice(), &key),
        "token must validate under the session it was minted for"
    );
    // Different session: rejected even though key and token bytes are
    // identical.
    assert!(
        !validate_token(&token, b"session-B".as_slice(), &key),
        "token minted under session A must NOT validate under session B"
    );
    // Same property through the double-submit path.
    assert!(
        validate_pair(Some(&token), Some(&token), b"session-A".as_slice(), &key),
        "cookie==header token must validate under its own session"
    );
    assert!(
        !validate_pair(Some(&token), Some(&token), b"session-B".as_slice(), &key),
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

/// `extract_presented_token` reads the configured header first and
/// returns its value as `Option<String>`. Pins three body
/// replacements: `-> None` (would break header-based double-submit
/// for every request), `Some(String::new())` (would compare the
/// presented token as empty, defeating ct_eq match), and
/// `Some("xyzzy")` (would brick header extraction to a constant).
#[tokio::test]
async fn extract_presented_token_returns_header_value() {
    use axum::http::Request;

    let key = [9u8; 32];
    let config = CsrfConfig::new(key);

    // Header present with a real value.
    let req = Request::builder()
        .header(config.header_name.as_ref(), "presented-csrf-value")
        .body(Body::empty())
        .unwrap();
    let (extracted, _req) = extract_presented_token(req, &config).await.unwrap();
    assert_eq!(
        extracted,
        Some("presented-csrf-value".to_string()),
        "must return the exact header value, not None / empty / 'xyzzy'"
    );

    // Header absent → None (and no urlencoded body to fall back to).
    let req = Request::builder().body(Body::empty()).unwrap();
    let (extracted, _req) = extract_presented_token(req, &config).await.unwrap();
    assert!(
        extracted.is_none(),
        "missing header must return None, not Some(...)"
    );

    // Empty header value → falls through to form-field path (empty
    // header is treated as absent). No form body, so overall None.
    let req = Request::builder()
        .header(config.header_name.as_ref(), "")
        .body(Body::empty())
        .unwrap();
    let (extracted, _req) = extract_presented_token(req, &config).await.unwrap();
    assert!(extracted.is_none(), "empty header must return None");
}

/// Form-field fallback: when the header is absent and the request
/// carries an `application/x-www-form-urlencoded` body containing
/// `_csrf=<token>`, the extractor returns the token AND restores
/// the body so the handler can still parse the form.
#[tokio::test]
async fn extract_presented_token_reads_form_field_and_restores_body() {
    use axum::http::Request;
    use http_body_util::BodyExt;

    let config = CsrfConfig::new([9u8; 32]);
    let body_str = "username=alice&_csrf=form-token-value&password=x";
    let req = Request::builder()
        .method(axum::http::Method::POST)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(Body::from(body_str))
        .unwrap();
    let (extracted, restored) = extract_presented_token(req, &config).await.unwrap();
    assert_eq!(
        extracted,
        Some("form-token-value".to_string()),
        "must extract the _csrf field from the urlencoded body"
    );
    let bytes = restored.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        body_str.as_bytes(),
        "body must be restored verbatim so handlers can still parse the form"
    );
}

/// Multipart bodies deliberately do NOT trigger form-field
/// extraction: no body is buffered and no field is returned.
#[tokio::test]
async fn extract_presented_token_skips_multipart_body() {
    use axum::http::Request;

    let config = CsrfConfig::new([9u8; 32]);
    let req = Request::builder()
        .method(axum::http::Method::POST)
        .header(
            axum::http::header::CONTENT_TYPE,
            "multipart/form-data; boundary=xxx",
        )
        .body(Body::from(b"unused".as_slice()))
        .unwrap();
    let (extracted, _req) = extract_presented_token(req, &config).await.unwrap();
    assert!(
        extracted.is_none(),
        "multipart Content-Type must skip form-field extraction"
    );
}

/// Bodies larger than `form_body_limit` fail closed. Ensures a
/// hostile client can't force axess to buffer a gigabyte of form
/// data hunting for `_csrf`.
#[tokio::test]
async fn extract_presented_token_rejects_oversized_body() {
    use axum::http::Request;

    let config = CsrfConfig::new([9u8; 32]).form_body_limit(64);
    // Declared Content-Length above the cap.
    let big_body = "a=".to_string() + &"x".repeat(500);
    let req = Request::builder()
        .method(axum::http::Method::POST)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(axum::http::header::CONTENT_LENGTH, big_body.len())
        .body(Body::from(big_body))
        .unwrap();
    let err = extract_presented_token(req, &config).await.unwrap_err();
    assert!(
        err.contains("cap"),
        "oversized body must return a cap-related error, got {err:?}"
    );
}

/// Origin allow-list matches the request's `Origin` header exactly.
#[test]
fn origin_matches_allowed_exact_origin() {
    use axum::http::Request;

    let allowed: Vec<Arc<str>> = vec!["https://app.example.com".into()];
    let req = Request::builder()
        .header(axum::http::header::ORIGIN, "https://app.example.com")
        .body(Body::empty())
        .unwrap();
    assert!(origin_matches_allowed(&req, &allowed));

    // Wrong scheme.
    let req = Request::builder()
        .header(axum::http::header::ORIGIN, "http://app.example.com")
        .body(Body::empty())
        .unwrap();
    assert!(!origin_matches_allowed(&req, &allowed));

    // Wrong host.
    let req = Request::builder()
        .header(axum::http::header::ORIGIN, "https://evil.example.com")
        .body(Body::empty())
        .unwrap();
    assert!(!origin_matches_allowed(&req, &allowed));
}

/// `Origin: null` (cross-origin redirect, opaque origin, sandboxed
/// iframe) is treated as failure: never as a match.
#[test]
fn origin_matches_allowed_rejects_null_origin() {
    use axum::http::Request;

    let allowed: Vec<Arc<str>> = vec!["https://app.example.com".into()];
    let req = Request::builder()
        .header(axum::http::header::ORIGIN, "null")
        .body(Body::empty())
        .unwrap();
    assert!(
        !origin_matches_allowed(&req, &allowed),
        "'Origin: null' must be treated as failure"
    );
}

/// Referer fallback when Origin is absent: derive origin from URL,
/// match against allow-list.
#[test]
fn origin_matches_allowed_falls_back_to_referer() {
    use axum::http::Request;

    let allowed: Vec<Arc<str>> = vec!["https://app.example.com".into()];
    let req = Request::builder()
        .header(
            axum::http::header::REFERER,
            "https://app.example.com/login?next=/dashboard",
        )
        .body(Body::empty())
        .unwrap();
    assert!(
        origin_matches_allowed(&req, &allowed),
        "Referer with matching origin component must match when Origin is absent"
    );

    // Referer from a disallowed origin.
    let req = Request::builder()
        .header(axum::http::header::REFERER, "https://evil.example.com/pwn")
        .body(Body::empty())
        .unwrap();
    assert!(!origin_matches_allowed(&req, &allowed));
}

/// Both Origin and Referer absent must fail closed, attackers can
/// strip both, and the token check alone would otherwise carry the
/// day.
#[test]
fn origin_matches_allowed_fails_when_both_headers_absent() {
    use axum::http::Request;

    let allowed: Vec<Arc<str>> = vec!["https://app.example.com".into()];
    let req = Request::builder().body(Body::empty()).unwrap();
    assert!(!origin_matches_allowed(&req, &allowed));
}

/// Origin comparison is case-insensitive on scheme and host per RFC
/// 6454 §4. A pre-normalization bug would let a raw-string comparison
/// treat `HTTPS://APP.example.com` as distinct from the allow-list
/// entry and admit it under other bypass paths.
#[test]
fn origin_matches_allowed_is_case_insensitive() {
    use axum::http::Request;

    let allowed: Vec<Arc<str>> = vec!["https://app.example.com".into()];
    let req = Request::builder()
        .header(axum::http::header::ORIGIN, "HTTPS://APP.EXAMPLE.COM")
        .body(Body::empty())
        .unwrap();
    assert!(
        origin_matches_allowed(&req, &allowed),
        "scheme+host comparison must be case-insensitive"
    );
}

/// `userinfo@` in a Referer must not survive origin extraction:
/// otherwise `https://attacker@app.example.com/…` would mismatch the
/// allow-list even though the browser treats it as same-origin.
#[test]
fn origin_matches_allowed_strips_userinfo_from_referer() {
    use axum::http::Request;

    let allowed: Vec<Arc<str>> = vec!["https://app.example.com".into()];
    let req = Request::builder()
        .header(
            axum::http::header::REFERER,
            "https://attacker@app.example.com/",
        )
        .body(Body::empty())
        .unwrap();
    assert!(
        origin_matches_allowed(&req, &allowed),
        "userinfo must be stripped before origin comparison"
    );
}

/// Adopters passing the default port explicitly must still match a
/// browser-sent `Origin` (which never carries default ports).
/// The warn guard fires only for a *partial* failure. All-kept is the
/// normal case and all-rejected is the assert's job, so neither warns.
#[test]
fn dropped_origin_warning_fires_only_on_partial_failure() {
    assert!(!should_warn_dropped_origins(2, 0), "all kept must not warn");
    assert!(
        !should_warn_dropped_origins(0, 2),
        "all rejected is the assert's case"
    );
    assert!(
        !should_warn_dropped_origins(0, 0),
        "nothing supplied must not warn"
    );
    assert!(
        should_warn_dropped_origins(1, 1),
        "partial failure must warn"
    );
}

/// A list mixing a good origin with a malformed one keeps the good one
/// and drops the other. The drop is fail-closed --- traffic from the
/// malformed entry is rejected --- so it must not silently pass as though
/// the adopter's whole list had been honoured.
#[test]
fn require_origin_keeps_valid_entries_and_drops_malformed_ones() {
    let config = CsrfConfig::new([0u8; 32])
        .require_origin(["https://app.example.com", "htps://typo.example.com"]);
    assert_eq!(
        config.allowed_origins.as_ref(),
        &[Arc::<str>::from("https://app.example.com")],
        "the malformed entry must be dropped, the valid one kept"
    );
}

#[test]
fn require_origin_normalizes_default_port() {
    let config = CsrfConfig::new([0u8; 32]).require_origin(["https://app.example.com:443"]);
    assert_eq!(
        config.allowed_origins.as_ref(),
        &[Arc::<str>::from("https://app.example.com")]
    );
}

/// Passing origins where every entry fails to canonicalize must
/// panic: silently emptying `allowed_origins` would turn the
/// runtime `!allowed_origins.is_empty() && ...` gate into a no-op,
/// leaving the adopter thinking Origin validation was on when it
/// was actually off. This mirrors `SessionConfigBuilder::build`'s
/// fail-fast discipline for `__Host-` misconfig.
#[test]
#[should_panic(expected = "all 2 supplied origin(s) failed to canonicalize")]
fn require_origin_panics_when_all_inputs_are_malformed() {
    let _ = CsrfConfig::new([0u8; 32]).require_origin(["not-a-url", "javascript:alert(1)"]);
}

/// The empty iterator is legitimate ("no Origin gate configured")
/// and must NOT panic: that's the default state.
#[test]
fn require_origin_with_no_inputs_stays_disabled() {
    let empty: [&str; 0] = [];
    let config = CsrfConfig::new([0u8; 32]).require_origin(empty);
    assert!(config.allowed_origins.is_empty());
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
        async move { Ok::<_, Infallible>(Response::builder().status(200).body(Body::empty()).unwrap()) }
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
/// behaviour the module docs promise: cross-session replay fails.
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
    let token = mint_token(b"some-session", &key);

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
    let stale_token = mint_token(b"some-other-session", &key);

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
    let sid_a = handle_a.0.read().await.id;
    assert!(
        validate_token(&refreshed, sid_a.as_bytes(), &key),
        "refreshed cookie must be HMAC-bound to the current session id"
    );
}

/// Post-handler re-mint after mid-request rotation: a safe GET whose
/// inner service calls `regenerate()` on the session handle (as a
/// factor-chain-completion path would) receives a fresh `Set-Cookie`
/// bound to the post-rotation id. This is the case that makes the
/// login flow survive `RequestAuthnService::verify_factor` cycling the id
/// without leaving the client tokenless.
#[tokio::test]
async fn csrf_service_remints_when_handler_rotates_session() {
    use axum::http::{Method, Request};
    use std::convert::Infallible;
    use tower::{Layer, ServiceExt, service_fn};

    // Inner service that rotates the session id via the handle in
    // the request extensions before responding: mirrors what
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
    let sid_before = handle.0.read().await.id;
    let token_before = mint_token(sid_before.as_bytes(), &key);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/rotate")
        .header("cookie", format!("{}={}", config.cookie_name, token_before))
        .extension(handle.clone())
        .body(Body::empty())
        .unwrap();
    let resp = service.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let sid_after = handle.0.read().await.id;
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
        validate_token(&refreshed, sid_after.as_bytes(), &key),
        "refreshed cookie must bind to the post-rotation session id"
    );
}

/// End-to-end through the REAL `SessionLayer` (not a mock handle): a CSRF
/// token minted for a fresh guest on a safe GET must validate on that
/// guest's next state-changing POST: the shape of the login flow. The
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

    let session_layer = SessionLayer::new(MemorySessionStore::new(), [42u8; 32]).with_secure(false);
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

    // 2. The fresh guest's first state-changing request: the login POST
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
