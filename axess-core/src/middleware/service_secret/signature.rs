//! Signed requests: the caller proves it holds the secret without sending
//! it.

use super::{ServiceSecret, ServiceSecrets};
use crate::session::hmac::new_signer;
use axess_clock::{Clock, SystemClock};
use axum::{
    body::Body,
    extract::{OriginalUri, Request},
    http::{
        HeaderMap, Method, StatusCode,
        header::{CONTENT_LENGTH, HeaderName, HeaderValue},
    },
};
use hmac::Mac;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The header a signed request carries: `x-axess-signature`.
///
/// Its value is `t=<unix seconds>,v1=<signature>`, where the signature is
/// the lowercase hex of
///
/// ```text
/// HMAC-SHA256(key, "v1\n" + t + "\n" + METHOD + "\n" + path?query + "\n" + body)
/// key = HMAC-SHA256(secret, "axess-service-signature-v1")
/// ```
///
/// `secret` is the configured secret with surrounding whitespace trimmed,
/// `METHOD` is upper-case as sent, and `path?query` is the request target
/// as the client sent it (the path, plus `?` and the query when there is
/// one). [`ServiceSigner`] does all of this; the recipe is here for a
/// caller that is not written in Rust. Unknown `key=value` pairs in the
/// header are ignored, so a later scheme can be sent beside `v1`.
pub const SIGNATURE_HEADER: HeaderName = HeaderName::from_static("x-axess-signature");

const KEY_LABEL: &[u8] = b"axess-service-signature-v1";

pub(super) fn derive_key(secret: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = new_signer(secret);
    mac.update(KEY_LABEL);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn sign_bytes(
    key: &[u8; 32],
    unix_seconds: i64,
    method: &Method,
    target: &str,
    body: &[u8],
) -> [u8; 32] {
    let mut mac = new_signer(key);
    mac.update(format!("v1\n{unix_seconds}\n{method}\n{target}\n").as_bytes());
    mac.update(body);
    mac.finalize().into_bytes().into()
}

/// Signs requests on the calling side. Made by [`ServiceSecret::signer`].
#[derive(Clone)]
pub struct ServiceSigner {
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ServiceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSigner").finish_non_exhaustive()
    }
}

impl ServiceSigner {
    pub(super) fn from_key(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key }
    }

    /// The [`SIGNATURE_HEADER`] value for a request sent at
    /// `unix_seconds`, with this method, request target (`/path` or
    /// `/path?query`) and body. Send the body exactly as signed.
    pub fn sign(
        &self,
        unix_seconds: i64,
        method: &Method,
        path_and_query: &str,
        body: &[u8],
    ) -> HeaderValue {
        let tag = sign_bytes(&self.key, unix_seconds, method, path_and_query, body);
        let mut value = format!("t={unix_seconds},v1=");
        for byte in tag {
            value.push_str(&format!("{byte:02x}"));
        }
        HeaderValue::from_str(&value).expect("digits, letters, `=` and `,` are valid header bytes")
    }
}

/// How a [`ServiceSecretLayer::signed`](super::ServiceSecretLayer::signed)
/// route checks signatures.
#[derive(Clone)]
pub struct SignedRequests {
    tolerance: Duration,
    max_body_bytes: usize,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SignedRequests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedRequests")
            .field("tolerance", &self.tolerance)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

impl Default for SignedRequests {
    /// Five minutes either side of the server's clock, bodies up to 1 MiB,
    /// the system clock.
    fn default() -> Self {
        Self {
            tolerance: Duration::from_secs(300),
            max_body_bytes: 1024 * 1024,
            clock: Arc::new(SystemClock),
        }
    }
}

impl SignedRequests {
    /// How far a signature's timestamp may be from the server's clock, in
    /// either direction. Also how long a seen signature is remembered to
    /// refuse a replay.
    #[must_use]
    pub fn tolerance(mut self, tolerance: Duration) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// The largest body read to verify a signature; a longer one is
    /// answered `413 Payload Too Large` without being read further.
    #[must_use]
    pub fn max_body_bytes(mut self, limit: usize) -> Self {
        self.max_body_bytes = limit;
        self
    }

    /// The clock timestamps are checked against.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

/// Checks signatures and remembers the ones it has accepted.
///
/// The memory is per process: behind a load balancer with several
/// instances, a replay that reaches a different instance within the
/// tolerance is not caught. Only verified signatures are remembered, so a
/// caller without the secret cannot grow it.
pub(super) struct Verifier {
    config: SignedRequests,
    seen: Mutex<HashMap<[u8; 32], i64>>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    pub(super) fn new(config: SignedRequests) -> Self {
        Self {
            config,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// The request with its body restored and its [`ServiceCaller`](super::ServiceCaller)
    /// attached, or the status to refuse it with.
    pub(super) async fn verify(
        &self,
        secrets: &ServiceSecrets,
        req: Request<Body>,
    ) -> Result<Request<Body>, StatusCode> {
        let (stamp, tag) = parse_header(req.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
        let now = self.config.clock.now().timestamp();
        let tolerance = i64::try_from(self.config.tolerance.as_secs()).unwrap_or(i64::MAX);
        if now.abs_diff(stamp) > tolerance.unsigned_abs() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if declared_length(req.headers()).is_some_and(|len| len > self.config.max_body_bytes) {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let target = req
            .extensions()
            .get::<OriginalUri>()
            .map_or(req.uri(), |original| &original.0)
            .path_and_query()
            .map_or_else(|| "/".to_owned(), |pq| pq.as_str().to_owned());
        let (mut parts, body) = req.into_parts();
        // The limit is the only failure a client that is still listening
        // can cause; a broken stream has no one to read the answer.
        let body = axum::body::to_bytes(body, self.config.max_body_bytes)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

        let caller = secrets
            .first_match(|secret: &ServiceSecret| {
                sign_bytes(&secret.signing_key, stamp, &parts.method, &target, &body).ct_eq(&tag)
            })
            .ok_or(StatusCode::UNAUTHORIZED)?;

        {
            let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
            seen.retain(|_, at| now.abs_diff(*at) <= tolerance.unsigned_abs());
            if seen.insert(tag, stamp).is_some() {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }

        parts.extensions.insert(caller);
        Ok(Request::from_parts(parts, Body::from(body)))
    }
}

fn declared_length(headers: &HeaderMap) -> Option<usize> {
    headers.get(CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

/// `t=<seconds>,v1=<64 hex>`, in either order, other pairs ignored.
fn parse_header(headers: &HeaderMap) -> Option<(i64, [u8; 32])> {
    let value = headers.get(SIGNATURE_HEADER)?.to_str().ok()?;
    let mut stamp = None;
    let mut tag = None;
    for pair in value.split(',') {
        match pair.trim().split_once('=')? {
            ("t", digits) => stamp = Some(digits.parse::<i64>().ok()?),
            ("v1", hex) => tag = Some(decode_hex(hex)?),
            _ => {}
        }
    }
    Some((stamp?, tag?))
}

fn decode_hex(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let (pairs, _) = hex.as_chunks::<2>();
    for (byte, [high, low]) in out.iter_mut().zip(pairs) {
        let high = char::from(*high).to_digit(16)?;
        let low = char::from(*low).to_digit(16)?;
        *byte = u8::try_from(high * 16 + low).ok()?;
    }
    Some(out)
}
