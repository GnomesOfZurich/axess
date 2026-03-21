//! Session binding — ties a session to client-specific signals to detect hijacking.
//!
//! When a user authenticates, the library computes a hash of client-specific
//! request properties (e.g. `User-Agent` header) and stores it in the session.
//! On subsequent requests the hash is recomputed and compared. A mismatch
//! indicates the session cookie may have been stolen and used from a different
//! client, so the session is invalidated.
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
use sha2::{Digest, Sha256};

/// Extracts a binding value from a request for session-to-client binding.
///
/// The returned string is stored as a hex-encoded SHA-256 hash in the session.
/// On subsequent requests, the hash is recomputed and compared to detect
/// session hijacking (cookie theft from a different client).
///
/// Return `None` if the binding signal is absent (e.g. no User-Agent header),
/// in which case binding is skipped for that request.
pub trait SessionBinding: Send + Sync + 'static {
    /// Extract the raw binding material from the request.
    ///
    /// The library will SHA-256 hash the returned bytes before storing/comparing,
    /// so implementations can return raw header values without pre-hashing.
    fn extract(&self, req: &Request<Body>) -> Option<Vec<u8>>;
}

/// Compute the hex-encoded SHA-256 hash used for storage and comparison.
pub(crate) fn compute_fingerprint(
    binding: &dyn SessionBinding,
    req: &Request<Body>,
) -> Option<String> {
    let material = binding.extract(req)?;
    let hash = Sha256::digest(&material);
    Some(URL_SAFE_NO_PAD.encode(hash))
}

/// Binds the session to the `User-Agent` header.
///
/// This is the simplest binding strategy. It detects session cookies being
/// replayed from a different browser or HTTP client. It does not protect
/// against an attacker who copies the User-Agent along with the cookie,
/// but it raises the bar significantly against opportunistic theft
/// (e.g. XSS exfiltration where the attacker's browser differs).
#[derive(Debug, Clone, Default)]
pub struct UserAgentBinding;

impl SessionBinding for UserAgentBinding {
    fn extract(&self, req: &Request<Body>) -> Option<Vec<u8>> {
        req.headers()
            .get(axum::http::header::USER_AGENT)
            .map(|v| v.as_bytes().to_vec())
    }
}
