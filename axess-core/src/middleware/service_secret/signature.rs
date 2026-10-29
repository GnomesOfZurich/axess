//! Signed requests: the caller proves it holds the secret without sending
//! it.

use super::rejection::{Rejection, peer_of};
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
use chrono::{DateTime, Utc};
use hmac::Mac;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

/// The header a signed request carries: `x-axess-signature`.
///
/// Its value is `t=<unix seconds>,v2=<signature>`, where the signature is
/// the lowercase hex of
///
/// ```text
/// HMAC-SHA256(key, "v2\n" + t + "\n" + METHOD + "\n" + path?query + "\n" + audience + "\n" + body)
/// key = HMAC-SHA256(secret, "axess-service-signature-v1")
/// ```
///
/// `secret` is the configured secret with surrounding whitespace trimmed,
/// `METHOD` is upper-case as sent, `path?query` is the request target as the
/// client sent it (the path, plus `?` and the query when there is one), and
/// `audience` is the recipient's name as configured with
/// [`SignedRequests::audience`] (not the `Host` header, which a proxy may
/// rewrite). [`ServiceSigner::sign_for`] does all of this; the recipe is here
/// for a caller that is not written in Rust. Unknown `key=value` pairs in the
/// header are ignored, so a later scheme can be sent beside `v2`.
///
/// # `v1`: the unaddressed form, read only inside a window
///
/// An older caller signs `t=<unix seconds>,v1=<signature>` over
/// `"v1\n" + t + "\n" + METHOD + "\n" + path?query + "\n" + body`, with the
/// same key. It does not say who the request is for, so a recipient that
/// shares the secret with another service can replay what it received to
/// that other service. A route therefore refuses `v1` unless it was told,
/// with [`SignedRequests::accept_unaddressed_until`], to read it until an
/// instant; nothing reads it afterwards. Even with `v2`, give each recipient
/// its own secret: that is the stronger separation.
pub const SIGNATURE_HEADER: HeaderName = HeaderName::from_static("x-axess-signature");

const KEY_LABEL: &[u8] = b"axess-service-signature-v1";

pub(super) fn derive_key(secret: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = new_signer(secret);
    mac.update(KEY_LABEL);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// The `v2` tag: [`sign_bytes`]'s message with the recipient inserted
/// before the body.
pub(super) fn sign_bytes_v2(
    key: &[u8; 32],
    unix_seconds: i64,
    method: &Method,
    target: &str,
    audience: &str,
    body: &[u8],
) -> [u8; 32] {
    let mut mac = new_signer(key);
    mac.update(format!("v2\n{unix_seconds}\n{method}\n{target}\n{audience}\n").as_bytes());
    mac.update(body);
    mac.finalize().into_bytes().into()
}

pub(super) fn sign_bytes(
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

    /// The [`SIGNATURE_HEADER`] value for a request sent at `unix_seconds`
    /// to the recipient `audience` (the name the receiving route configured
    /// with [`SignedRequests::audience`]), with this method, request target
    /// (`/path` or `/path?query`) and body. Send the body exactly as signed.
    /// The header carries `v2=`, which only a route configured with that same
    /// audience accepts.
    pub fn sign_for(
        &self,
        audience: &str,
        unix_seconds: i64,
        method: &Method,
        path_and_query: &str,
        body: &[u8],
    ) -> HeaderValue {
        let tag = sign_bytes_v2(
            &self.key,
            unix_seconds,
            method,
            path_and_query,
            audience,
            body,
        );
        let mut value = format!("t={unix_seconds},v2=");
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
    max_remembered: usize,
    audience: Option<String>,
    unaddressed_until: Option<DateTime<Utc>>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SignedRequests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedRequests")
            .field("tolerance", &self.tolerance)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_remembered", &self.max_remembered)
            .field("audience", &self.audience)
            .field("unaddressed_until", &self.unaddressed_until)
            .finish_non_exhaustive()
    }
}

impl Default for SignedRequests {
    /// Five minutes either side of the server's clock, bodies up to 1 MiB,
    /// 100,000 remembered signatures, the system clock. It names no
    /// audience, so [`ServiceSecretLayer::signed`](super::ServiceSecretLayer::signed)
    /// refuses it until [`audience`](Self::audience) is set.
    fn default() -> Self {
        Self {
            tolerance: Duration::from_secs(300),
            max_body_bytes: 1024 * 1024,
            max_remembered: 100_000,
            audience: None,
            unaddressed_until: None,
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

    /// The most accepted signatures remembered at once (minimum 1).
    ///
    /// A signature is remembered for the [`tolerance`](Self::tolerance), and
    /// a live one is never forgotten to make room. When this many are live,
    /// a request that would add one more is answered `503 Service
    /// Unavailable` instead of being accepted unchecked for replay: refusing
    /// is the safe direction, and only holders of a secret can reach it.
    #[must_use]
    pub fn max_remembered(mut self, limit: usize) -> Self {
        self.max_remembered = limit.max(1);
        self
    }

    /// Name this route as the recipient of its signed requests. The route
    /// accepts `v2` signatures made for exactly this name
    /// ([`ServiceSigner::sign_for`]), so a request signed for another service
    /// that shares the secret cannot be replayed here. Required:
    /// [`ServiceSecretLayer::signed`](super::ServiceSecretLayer::signed)
    /// refuses a configuration with neither an audience nor an unaddressed
    /// window.
    #[must_use]
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Also accept the unaddressed `v1` signature until `instant`, checked
    /// against the configured [`clock`](Self::clock), for callers that have
    /// not moved to [`ServiceSigner::sign_for`] yet. A `v1` signature names no
    /// recipient, so it can be replayed against any other service that shares
    /// the secret; this is a migration window, not a setting to leave on. From
    /// `instant` on, `v1` is refused.
    #[must_use]
    pub fn accept_unaddressed_until(mut self, instant: DateTime<Utc>) -> Self {
        self.unaddressed_until = Some(instant);
        self
    }

    /// Whether the configuration names an audience or an unaddressed window,
    /// which is what a route needs to be built.
    pub(super) fn is_addressed(&self) -> bool {
        self.audience.is_some() || self.unaddressed_until.is_some()
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
///
/// Expired entries are swept at most once per `max(tolerance / 8, 1 s)` of
/// the configured clock, by whichever request wins the claim on the sweep
/// stamp; the rest only insert. An entry that has outlived the tolerance but
/// not yet been swept cannot be mistaken for a live one: a request carrying
/// its signature is older than the tolerance and is refused on its timestamp
/// first. At [`max_remembered`](SignedRequests::max_remembered) live entries
/// a sweep is attempted at most once per second, and if the cache is still
/// full the request is refused with `503`.
pub(super) struct Verifier {
    config: SignedRequests,
    seen: Mutex<HashMap<[u8; 32], i64>>,
    /// Unix seconds of the last sweep, claimed with `compare_exchange`.
    last_sweep: AtomicU64,
    /// Unix seconds of the last warning emitted, claimed with
    /// `compare_exchange`.
    last_warn: AtomicU64,
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
            last_sweep: AtomicU64::new(0),
            last_warn: AtomicU64::new(0),
        }
    }

    /// Whether this caller won the right to sweep: at least `interval`
    /// seconds have passed since the stamp, or the clock now reads earlier
    /// than the stamp (it stepped back; waiting for it to catch up would stop
    /// the sweeping and fill the cache), and the stamp was moved by us.
    fn claim_sweep(&self, now: i64, interval: u64) -> bool {
        let now = u64::try_from(now).unwrap_or(0);
        let last = self.last_sweep.load(Ordering::Acquire);
        (now < last || now - last >= interval)
            && self
                .last_sweep
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    /// Signatures currently remembered, expired-but-unswept ones included.
    #[cfg(test)]
    pub(super) fn remembered(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// The request with its body restored and its [`ServiceCaller`](super::ServiceCaller)
    /// attached, or the status to refuse it with. Every refusal is logged on
    /// the `axess::service_secret` target with its reason (see
    /// [`Rejection`]).
    pub(super) async fn verify(
        &self,
        secrets: &ServiceSecrets,
        req: Request<Body>,
    ) -> Result<Request<Body>, StatusCode> {
        let peer = peer_of(&req);
        match self.check(secrets, req).await {
            Ok(req) => Ok(req),
            Err(rejection) => {
                let now = self.config.clock.now().timestamp();
                let warn_due = rejection.warns() && self.claim_warn(now);
                rejection.log(peer, warn_due);
                Err(rejection.status())
            }
        }
    }

    /// Whether this caller won the right to emit a warning: at most one per
    /// second, so a flood of replays does not become a flood of log lines.
    fn claim_warn(&self, now: i64) -> bool {
        let now = u64::try_from(now).unwrap_or(0);
        let last = self.last_warn.load(Ordering::Acquire);
        (last == 0 || now > last)
            && self
                .last_warn
                .compare_exchange(last, now.max(1), Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    async fn check(
        &self,
        secrets: &ServiceSecrets,
        req: Request<Body>,
    ) -> Result<Request<Body>, Rejection> {
        let (stamp, tags) = parse_header(req.headers()).ok_or(Rejection::Malformed)?;
        // The schemes in force are the route's, never the sender's: `v2` when
        // the route names an audience, `v1` only while its window is open. A
        // header without a tag the route reads is malformed for this route.
        let instant = self.config.clock.now();
        let now = instant.timestamp();
        let v1_open = self
            .config
            .unaddressed_until
            .is_some_and(|until| instant < until);
        let tag = match (&self.config.audience, tags.v2, tags.v1) {
            (Some(_), Some(v2), _) => Scheme::V2(v2),
            (_, _, Some(v1)) if v1_open => Scheme::V1(v1),
            _ => return Err(Rejection::Malformed),
        };
        let tolerance = i64::try_from(self.config.tolerance.as_secs()).unwrap_or(i64::MAX);
        if now.abs_diff(stamp) > tolerance.unsigned_abs() {
            return Err(Rejection::StaleStamp);
        }
        if declared_length(req.headers()).is_some_and(|len| len > self.config.max_body_bytes) {
            return Err(Rejection::TooLarge);
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
            .map_err(|_| Rejection::TooLarge)?;

        let caller = secrets
            .first_match(|secret: &ServiceSecret| {
                match (&tag, &self.config.audience) {
                    (Scheme::V2(presented), Some(audience)) => sign_bytes_v2(
                        &secret.signing_key,
                        stamp,
                        &parts.method,
                        &target,
                        audience,
                        &body,
                    )
                    .ct_eq(presented),
                    (Scheme::V1(presented), _) => {
                        sign_bytes(&secret.signing_key, stamp, &parts.method, &target, &body)
                            .ct_eq(presented)
                    }
                    // `v2` is only chosen above when the route has an audience.
                    (Scheme::V2(_), None) => Choice::from(0),
                }
            })
            .ok_or(Rejection::BadSignature)?;

        let window = tolerance.unsigned_abs();
        let sweep_due = self.claim_sweep(now, (window / 8).max(1));
        {
            let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
            if sweep_due {
                seen.retain(|_, at| now.abs_diff(*at) <= window);
            }
            let tag = tag.bytes();
            if seen.contains_key(&tag) {
                return Err(Rejection::Replay(caller));
            }
            if seen.len() >= self.config.max_remembered {
                if self.claim_sweep(now, 1) {
                    seen.retain(|_, at| now.abs_diff(*at) <= window);
                }
                if seen.len() >= self.config.max_remembered {
                    return Err(Rejection::CacheFull);
                }
            }
            seen.insert(tag, stamp);
        }

        parts.extensions.insert(caller);
        Ok(Request::from_parts(parts, Body::from(body)))
    }
}

fn declared_length(headers: &HeaderMap) -> Option<usize> {
    headers.get(CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

/// The signature a request is judged by, with the scheme it was made under.
enum Scheme {
    V1([u8; 32]),
    V2([u8; 32]),
}

impl Scheme {
    fn bytes(&self) -> [u8; 32] {
        match self {
            Self::V1(tag) | Self::V2(tag) => *tag,
        }
    }
}

/// The tags a header carried, by scheme.
struct Tags {
    v1: Option<[u8; 32]>,
    v2: Option<[u8; 32]>,
}

/// `t=<seconds>,v1=<64 hex>` or `t=<seconds>,v2=<64 hex>`, in either order,
/// other pairs ignored.
fn parse_header(headers: &HeaderMap) -> Option<(i64, Tags)> {
    let value = headers.get(SIGNATURE_HEADER)?.to_str().ok()?;
    let mut stamp = None;
    let mut tags = Tags { v1: None, v2: None };
    for pair in value.split(',') {
        match pair.trim().split_once('=')? {
            ("t", digits) => stamp = Some(digits.parse::<i64>().ok()?),
            ("v1", hex) => tags.v1 = Some(decode_hex(hex)?),
            ("v2", hex) => tags.v2 = Some(decode_hex(hex)?),
            _ => {}
        }
    }
    Some((stamp?, tags))
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
