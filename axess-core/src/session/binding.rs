//! Session binding: ties a session to client-specific signals to detect hijacking.
//!
//! Session binding prevents session hijacking by computing an HMAC-SHA256
//! fingerprint of client-specific request properties (e.g. the `User-Agent`
//! header) and storing it in the session. On every subsequent request the
//! fingerprint is recomputed and compared using constant-time equality. A
//! mismatch indicates the session cookie may have been stolen and replayed
//! from a different client, so the session is reset to `Guest`.
//!
//! # When bindings are created
//!
//! The [`SessionLayer`](super::layer::SessionLayer) pre-computes a
//! `pending_fingerprint` from the incoming request on every request. This
//! pending value is stored in
//! `SessionInner::pending_fingerprint`
//! and applied (written into [`SessionData::fingerprint`](super::data::SessionData::fingerprint))
//! at the earliest auth-state transition that moves the session out of `Guest`:
//!
//! - **`set_identifying`**: when the user submits their username.
//! - **`begin_authenticating`**: when a multi-factor flow starts.
//! - **`set_authenticated` / `advance_factor`**: when authentication completes.
//!
//! Binding as early as possible (during `Identifying`) ensures that even
//! pre-MFA sessions cannot be replayed from a different device. Once the
//! fingerprint is set it is never overwritten; it persists for the lifetime
//! of the session.
//!
//! # Usage
//!
//! ```text
//! let layer = SessionLayer::new(store, key)
//!     .with_binding(UserAgentBinding);
//! ```
//!
//! Implement [`SessionBinding`] for custom binding strategies (e.g. combining
//! User-Agent with IP subnet or TLS channel binding).

use axum::{body::Body, http::Request};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;

/// Extracts a binding value from a request for session-to-client binding.
///
/// The returned string is stored as an HMAC-SHA256 digest in the session.
/// On subsequent requests, the HMAC is recomputed and compared to detect
/// session hijacking (cookie theft from a different client).
///
/// Return `None` if the binding signal is absent (e.g. no User-Agent header),
/// in which case binding is skipped for that request.
///
/// # Scope: where binding is checked
///
/// The fingerprint is recomputed and compared **once per HTTP request**
/// at [`SessionLayer`](super::layer::SessionLayer) entry. It is not
/// re-checked at any other point in the request lifecycle. The
/// implications:
///
/// - **Persistent connections (WebSocket, Server-Sent Events) are
///   bound only at upgrade.** Once the WS handshake completes, the
///   layer no longer sees the underlying frames: an attacker who
///   manages to splice into the existing socket can drive it
///   indefinitely without the binding firing. If you need to
///   re-validate, do so in your own message handler at
///   policy-relevant intervals.
/// - **gRPC streaming** has the same caveat: only the initial HTTP/2
///   stream-open request runs through this middleware.
/// - **Long-poll request bodies** that pause for minutes do not
///   re-check binding mid-flight, but each new HTTP request does, so
///   a long-poll loop fired from a hijacked client will fail at the
///   next round trip.
/// - **Background jobs the application enqueues "as the user"** are
///   not bound by this trait at all; the application owns that
///   threat model. If you spawn a long-running task on behalf of a
///   user, do not assume the user is still legitimately connected
///   when it finishes.
pub trait SessionBinding: Send + Sync + 'static {
    /// Extract the raw binding material from the request.
    ///
    /// The library will HMAC-SHA256 the returned bytes (keyed with the session
    /// signing key) before storing/comparing, so implementations can return raw
    /// header values without pre-hashing.
    fn extract(&self, req: &Request<Body>) -> Option<Vec<u8>>;
}

/// Compute the HMAC-SHA256 fingerprint used for storage and comparison.
///
/// Keyed with the session signing key so that an attacker who reads the session
/// data from the store cannot recompute a valid fingerprint without the key.
pub(crate) fn compute_fingerprint(
    binding: &dyn SessionBinding,
    req: &Request<Body>,
    signing_key: &[u8; 32],
) -> Option<String> {
    let material = binding.extract(req)?;
    let mut mac = crate::hmac::new_signer(signing_key);
    mac.update(&material);
    let result = mac.finalize();
    Some(URL_SAFE_NO_PAD.encode(result.into_bytes()))
}

/// Binds the session to the `User-Agent` header.
///
/// **Threat model, read this before relying on it.** UA binding catches
/// only the dumbest hijacking modes: the attacker steals the cookie via
/// log scraping, browser-extension exfiltration, or a prior breach where
/// the UA wasn't captured, and replays it from a different client. It
/// does **not** stop:
///
/// - **XSS / cookie-jacking attacks where the attacker is in the
///   victim's browser.** The User-Agent is plaintext on every request and
///   trivially copyable; an attacker who exfiltrates the cookie via a
///   malicious script or browser extension also has full access to
///   `navigator.userAgent`.
/// - **Network-level interception** where the attacker observes the
///   victim's traffic (TLS-stripping proxies, compromised CA, captured
///   PCAPs). The UA travels in clear with the cookie.
/// - **Phishing** that proxies the victim's browser to your origin:
///   the proxy forwards the real UA verbatim.
///
/// What it *is* useful for: defense in depth against database/log dumps
/// where the attacker has cookies but no captured UA, and as a cheap
/// signal for hijack telemetry. Combine with at least one of: client-IP
/// `/24` binding (acceptable when users don't roam between networks
/// often), TLS channel binding (RFC 8471), or a hardware-bound key
/// (FIDO2). Document the limits to your security reviewers; assuming
/// UA binding stops cookie theft is a common misreading.
#[derive(Debug, Clone, Default)]
pub struct UserAgentBinding;

impl SessionBinding for UserAgentBinding {
    fn extract(&self, req: &Request<Body>) -> Option<Vec<u8>> {
        req.headers()
            .get(axum::http::header::USER_AGENT)
            .map(|v| v.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    use axum::http::HeaderValue;

    fn req_with_ua(ua: &str) -> Request<Body> {
        let mut r = Request::new(Body::empty());
        r.headers_mut().insert(
            axum::http::header::USER_AGENT,
            HeaderValue::from_str(ua).unwrap(),
        );
        r
    }

    /// `UserAgentBinding::extract` returns the User-Agent
    /// header bytes when present and `None` when absent. Pins the
    /// four `extract -> None / Some(vec![])/Some(vec![0])/Some(vec![1])`
    /// body replacements.
    #[test]
    fn user_agent_binding_extract_returns_header_bytes_or_none() {
        let binding = UserAgentBinding;

        // Present UA → Some(exact bytes).
        let req = req_with_ua("Mozilla/5.0 (test)");
        let extracted = binding.extract(&req).expect("UA present must yield Some");
        assert_eq!(
            extracted,
            b"Mozilla/5.0 (test)".to_vec(),
            "extract must return UA bytes verbatim; kills Some(vec![]) / Some(vec![0]) / Some(vec![1]) replacements"
        );

        // Absent UA → None.
        let req = Request::new(Body::empty());
        assert!(
            binding.extract(&req).is_none(),
            "missing UA must yield None; kills Some(...) body replacements when no header present"
        );
    }

    /// `compute_fingerprint` returns `Some(non-empty base64)`
    /// when the binding extracts material, and the digest depends on
    /// both the material and the signing key (HMAC contract). Pins
    /// the body mutations: `None` (would break binding everywhere),
    /// `Some(String::new())` (would compare empty to empty → all
    /// requests look bound), and `Some("xyzzy")` (would brick binding
    /// to a constant value).
    #[test]
    fn compute_fingerprint_is_deterministic_and_keyed() {
        let binding = UserAgentBinding;
        let req_a = req_with_ua("Mozilla/5.0 (browser-A)");
        let req_b = req_with_ua("curl/8.0");
        let key1: [u8; 32] = [1u8; 32];
        let key2: [u8; 32] = [2u8; 32];

        // Some + non-empty.
        let fp = compute_fingerprint(&binding, &req_a, &key1)
            .expect("with material, fingerprint must be Some");
        assert!(
            !fp.is_empty(),
            "fingerprint must not be empty (kills String::new())"
        );
        assert_ne!(fp, "xyzzy", "fingerprint must not be the constant 'xyzzy'");

        // Determinism: same input → same output.
        let fp_again = compute_fingerprint(&binding, &req_a, &key1).unwrap();
        assert_eq!(fp, fp_again, "fingerprint must be deterministic");

        // Material-sensitive: different UA → different fingerprint.
        let fp_b = compute_fingerprint(&binding, &req_b, &key1).unwrap();
        assert_ne!(
            fp, fp_b,
            "different binding material must yield different fingerprint"
        );

        // Key-sensitive: different signing key → different fingerprint
        // (this is the HMAC keying property; kills any const-return mutant
        // that would ignore the key).
        let fp_k2 = compute_fingerprint(&binding, &req_a, &key2).unwrap();
        assert_ne!(
            fp, fp_k2,
            "different signing key must yield different fingerprint"
        );

        // No material → None (the helper threads the binding's `extract`
        // result through `?`; if extract returns None, the helper must too).
        let req_no_ua = Request::new(Body::empty());
        assert!(
            compute_fingerprint(&binding, &req_no_ua, &key1).is_none(),
            "no binding material must yield None; kills Some(...) body replacements"
        );
    }
}
