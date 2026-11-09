//! Signed requests: the caller proves it holds the secret without sending
//! it.

use super::rejection::{Rejection, peer_of};
use super::{ServiceCaller, ServiceSecret, ServiceSecrets};
use crate::session::hmac::new_signer;
use axess_clock::{Clock, SystemClock};
use axum::{
    body::Body,
    extract::{OriginalUri, Request},
    http::{
        HeaderMap, Method, StatusCode,
        header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue},
    },
};
use chrono::{DateTime, Utc};
use hmac::Mac;
use sha2::{Digest as _, Sha256};
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
/// Its value is `t=<unix seconds>,v3=<signature>` (and `v2=<signature>`
/// beside it, for a recipient that has not moved to `v3` yet), where the
/// `v3` signature is the lowercase hex of
///
/// ```text
/// HMAC-SHA256(key, "v3\n" + t + "\n" + METHOD + "\n" + path?query + "\n" + audience
///                  + "\n" + hex(SHA-256(content-type)) + "\n" + hex(SHA-256(content-encoding))
///                  + "\n" + body)
/// key = HMAC-SHA256(secret, "axess-service-signature-v1")
/// ```
///
/// `secret` is the configured secret with surrounding whitespace trimmed,
/// `METHOD` is upper-case as sent, `path?query` is the request target as the
/// client sent it (the path, plus `?` and the query when there is one), and
/// `audience` is the recipient's name as configured with
/// [`SignedRequests::audience`] (not the `Host` header, which a proxy may
/// rewrite). `content-type` and `content-encoding` are the values of those
/// headers as sent (several header lines of one name joined with `", "`), and
/// a header that is absent hashes as the empty string: `hex(SHA-256(""))` is
/// `e3b0c442...b855`. [`ServiceSigner::sign_for`] does all of this; the recipe
/// is here for a caller that is not written in Rust. Unknown `key=value`
/// pairs in the header are ignored, so a later scheme can be sent beside
/// `v3`.
///
/// A route reads the highest scheme it enables: `v3` whenever the header
/// carries it. It reads `v2` (the same message without the two header hashes,
/// tagged `"v2\n"`) only until the instant given to
/// [`SignedRequests::accept_v2_until`], and only when the header has no `v3`.
///
/// # What the signature covers and does not cover
///
/// `v3` covers `Content-Type` and `Content-Encoding`, so a request cannot be
/// re-typed (JSON to a form, say) or re-encoded on its way without breaking
/// the signature. No other header is signed, `Authorization` included, and
/// neither is any header under `v2`. A handler must not trust an unsigned
/// header of a signed request for anything that matters: take identity from
/// the signature's caller, not from a header. Run the call over TLS, which is
/// what keeps a third party from altering it at all.
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

/// The `v3` tag: the `v2` message with the hashes of `Content-Type` and
/// `Content-Encoding` before the body.
pub(super) fn sign_bytes_v3(
    key: &[u8; 32],
    unix_seconds: i64,
    method: &Method,
    target: &str,
    audience: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> [u8; 32] {
    let mut mac = new_signer(key);
    mac.update(
        format!(
            "v3\n{unix_seconds}\n{method}\n{target}\n{audience}\n{}\n{}\n",
            header_digest(headers, &CONTENT_TYPE),
            header_digest(headers, &CONTENT_ENCODING),
        )
        .as_bytes(),
    );
    mac.update(body);
    mac.finalize().into_bytes().into()
}

/// Lowercase hex SHA-256 of a header's value as sent: all of its lines
/// joined with `", "`, and the empty string when it is absent.
fn header_digest(headers: &HeaderMap, name: &HeaderName) -> String {
    let mut hasher = Sha256::new();
    for (i, value) in headers.get_all(name).iter().enumerate() {
        if i > 0 {
            hasher.update(b", ");
        }
        hasher.update(value.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
    /// (`/path` or `/path?query`), headers and body. Send the body exactly as
    /// signed, and the `Content-Type` and `Content-Encoding` in `headers`
    /// exactly as signed: they are part of the signature (only those two are
    /// read; pass the request's header map, or an empty one when it sends
    /// neither). The value carries `v3=` and, beside it, `v2=`, which a route
    /// still inside its [`accept_v2_until`](SignedRequests::accept_v2_until)
    /// window reads from a caller that predates `v3`.
    pub fn sign_for(
        &self,
        audience: &str,
        unix_seconds: i64,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> HeaderValue {
        let hex = |tag: [u8; 32]| {
            tag.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let v2 = sign_bytes_v2(
            &self.key,
            unix_seconds,
            method,
            path_and_query,
            audience,
            body,
        );
        let v3 = sign_bytes_v3(
            &self.key,
            unix_seconds,
            method,
            path_and_query,
            audience,
            headers,
            body,
        );
        let value = format!("t={unix_seconds},v2={},v3={}", hex(v2), hex(v3));
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
    v2_until: Option<DateTime<Utc>>,
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
            .field("v2_until", &self.v2_until)
            .finish_non_exhaustive()
    }
}

impl Default for SignedRequests {
    /// Five minutes either side of the server's clock, bodies up to 256 KiB,
    /// 100,000 remembered signatures, the system clock, `v3` only. It names no
    /// audience, so [`ServiceSecretLayer::signed`](super::ServiceSecretLayer::signed)
    /// refuses it until [`audience`](Self::audience) is set.
    fn default() -> Self {
        Self {
            tolerance: Duration::from_secs(300),
            max_body_bytes: 256 * 1024,
            max_remembered: 100_000,
            audience: None,
            unaddressed_until: None,
            v2_until: None,
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

    /// The largest body read to verify a signature (default: 256 KiB); a
    /// longer one is answered `413 Payload Too Large` without being read
    /// further.
    ///
    /// The body is buffered in memory before any secret is checked, because
    /// the handler is given it only once a signature has been accepted. A
    /// header with a current timestamp needs no secret, so each concurrent
    /// request on the route can hold up to this many bytes whether or not it
    /// is signed. Set it to the largest body the route takes, and cap the
    /// concurrency on every signed route (a `tower`
    /// [`ConcurrencyLimitLayer`](https://docs.rs/tower/latest/tower/limit/struct.ConcurrencyLimitLayer.html)
    /// outside this layer): with N concurrent requests the route can hold N
    /// times this many bytes.
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
    /// accepts `v3` signatures made for exactly this name
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

    /// Also accept the `v2` signature until `instant`, checked against the
    /// configured [`clock`](Self::clock), for callers that have not moved to
    /// a [`ServiceSigner::sign_for`] that emits `v3` yet. `v2` signs no
    /// header, so a `Content-Type` or `Content-Encoding` can be changed on its
    /// way without breaking it; and a header that carries only `v2` is read
    /// as `v2` during the window, so an attacker who strips the `v3` tag
    /// of a request in flight gets the `v2` guarantees. This is a migration
    /// window, not a setting to leave on. A header that carries `v3` is
    /// always judged by it. From `instant` on, `v2` is refused.
    #[must_use]
    pub fn accept_v2_until(mut self, instant: DateTime<Utc>) -> Self {
        self.v2_until = Some(instant);
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
/// caller without the secret cannot grow it. What is remembered is the
/// request (its caller, stamp, method, target and body), not the tag it
/// arrived with, so a request accepted under one scheme is a replay when it
/// comes again under another (`v3` stripped to `v2`, `v1` upgraded to `v2`);
/// two requests that differ only in a signed header are one request.
///
/// Expired entries are swept at most once per `max(tolerance / 8, 1 s)` of
/// the configured clock, by whichever request wins the claim on the sweep
/// stamp; the rest only insert. An entry that has outlived the tolerance but
/// not yet been swept cannot be mistaken for a live one: a request carrying
/// its signature is older than the tolerance and is refused on its timestamp
/// first. At [`max_remembered`](SignedRequests::max_remembered) live entries
/// a sweep is attempted at most once per second, and if the cache is still
/// full the request is refused with `503`.
///
/// The clock can step. A sweep never forgets a signature stamped ahead of the
/// clock: it is set aside, outside the count, until the clock has passed it
/// by the tolerance. A signature forgotten for age raises a high-water mark,
/// and a stamp at or below the mark is refused, so a signature swept while
/// the clock read late is not accepted again when the clock comes back.
///
/// The mark has a cost after a backward step larger than the window: a caller
/// that stamps with the server's clock is below a mark that a sweep raised
/// before the step, and is refused as stale until the clock has passed it
/// (fail closed by design; the forgotten signatures cannot be told from a
/// replay of them). The set-aside entries (`ahead`) are those that were live
/// at a sweep: at most `max_remembered` per backward step, and each leaves
/// the set when a sweep finds it older than the tolerance or moves back into
/// `live` when a sweep finds the clock within the tolerance of it.
pub(super) struct Verifier {
    config: SignedRequests,
    seen: Mutex<Remembered>,
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
            seen: Mutex::new(Remembered::default()),
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

    /// Signatures counted against the cache, expired-but-unswept ones
    /// included and those set aside ahead of the clock not.
    #[cfg(test)]
    pub(super) fn remembered(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .live
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
    /// A clock that reads earlier than the stamp (it stepped back) re-arms
    /// the throttle, as [`claim_sweep`](Self::claim_sweep) does: waiting for
    /// it to catch up would silence every warning until then.
    pub(super) fn claim_warn(&self, now: i64) -> bool {
        let now = u64::try_from(now).unwrap_or(0);
        let last = self.last_warn.load(Ordering::Acquire);
        (last == 0 || now != last)
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
        // The schemes in force are the route's, never the sender's: the
        // highest one the route enables that the header carries. `v3` when
        // the route names an audience, `v2` only while its window is open
        // and only when there is no `v3`, `v1` only while its window is
        // open. A header without a tag the route reads is malformed for this
        // route.
        let instant = self.config.clock.now();
        let now = instant.timestamp();
        let open = |until: Option<DateTime<Utc>>| until.is_some_and(|until| instant < until);
        let (v1_open, v2_open) = (
            open(self.config.unaddressed_until),
            open(self.config.v2_until),
        );
        let addressed = self.config.audience.is_some();
        let tag = if let (true, Some(v3)) = (addressed, tags.v3) {
            Scheme::V3(v3)
        } else if let (true, true, Some(v2)) = (addressed, v2_open, tags.v2) {
            Scheme::V2(v2)
        } else if let (true, Some(v1)) = (v1_open, tags.v1) {
            Scheme::V1(v1)
        } else {
            return Err(Rejection::Malformed);
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
                    (Scheme::V3(presented), Some(audience)) => sign_bytes_v3(
                        &secret.signing_key,
                        stamp,
                        &parts.method,
                        &target,
                        audience,
                        &parts.headers,
                        &body,
                    )
                    .ct_eq(presented),
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
                    // `v2` and `v3` are only chosen above when the route has
                    // an audience.
                    (Scheme::V2(_) | Scheme::V3(_), None) => Choice::from(0),
                }
            })
            .ok_or(Rejection::BadSignature)?;

        let window = tolerance.unsigned_abs();
        let sweep_due = self.claim_sweep(now, (window / 8).max(1));
        {
            let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
            if sweep_due {
                seen.sweep(now, window);
            }
            if seen.forgotten_through.is_some_and(|mark| stamp <= mark) {
                return Err(Rejection::StaleStamp);
            }
            // The request is remembered, not the tag it arrived with: a
            // header that carries several schemes, or the same request
            // re-sent under another scheme, is one request.
            let tag = replay_key(&caller, stamp, &parts.method, &target, &body);
            if seen.live.contains_key(&tag) || seen.ahead.contains_key(&tag) {
                return Err(Rejection::Replay(caller));
            }
            if seen.live.len() >= self.config.max_remembered {
                if self.claim_sweep(now, 1) {
                    seen.sweep(now, window);
                }
                if seen.live.len() >= self.config.max_remembered {
                    return Err(Rejection::CacheFull);
                }
            }
            seen.live.insert(tag, stamp);
        }

        parts.extensions.insert(caller);
        Ok(Request::from_parts(parts, Body::from(body)))
    }
}

/// The accepted signatures, by the stamp each was signed with.
#[derive(Default)]
struct Remembered {
    /// Counted against `max_remembered`.
    live: HashMap<[u8; 32], i64>,
    /// Stamped further ahead of the clock than the tolerance when a sweep
    /// ran: the clock stepped back after they were accepted. Not counted
    /// while the clock is behind them, so the step does not fill the cache;
    /// still refused as replays, and counted again once a sweep finds the
    /// clock within the tolerance of them.
    ahead: HashMap<[u8; 32], i64>,
    /// The newest stamp ever forgotten for age.
    forgotten_through: Option<i64>,
}

impl Remembered {
    /// Forget what is older than `window` behind `now`, raising the mark, set
    /// aside what is further than `window` ahead of it, and count again what
    /// was set aside and is now within the window.
    fn sweep(&mut self, now: i64, window: u64) {
        let mut mark = self.forgotten_through;
        let mut aged = |at: i64| {
            let old = at < now && now.abs_diff(at) > window;
            if old {
                mark = Some(mark.map_or(at, |m| m.max(at)));
            }
            old
        };
        let mut back = Vec::new();
        self.ahead.retain(|tag, at| {
            if aged(*at) {
                false
            } else if *at > now && at.abs_diff(now) > window {
                true
            } else {
                back.push((*tag, *at));
                false
            }
        });
        self.live.extend(back);
        let mut set_aside = Vec::new();
        self.live.retain(|tag, at| {
            if aged(*at) {
                false
            } else if *at > now && at.abs_diff(now) > window {
                set_aside.push((*tag, *at));
                false
            } else {
                true
            }
        });
        self.ahead.extend(set_aside);
        self.forgotten_through = mark;
    }
}

fn declared_length(headers: &HeaderMap) -> Option<usize> {
    headers.get(CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

/// The signature a request is judged by, with the scheme it was made under.
enum Scheme {
    V1([u8; 32]),
    V2([u8; 32]),
    V3([u8; 32]),
}

/// What the replay cache remembers about an accepted request: a digest of the
/// caller, the stamp, the method, the target and the body, none of which
/// depends on the scheme that carried the signature. Each field is length
/// prefixed, so no two requests share a digest by shifting a boundary.
fn replay_key(
    caller: &ServiceCaller,
    stamp: i64,
    method: &Method,
    target: &str,
    body: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"axess-service-replay-v1");
    for field in [
        caller.name().as_bytes(),
        &stamp.to_be_bytes(),
        method.as_str().as_bytes(),
        target.as_bytes(),
        body,
    ] {
        digest.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(field);
    }
    digest.finalize().into()
}

/// The tags a header carried, by scheme.
struct Tags {
    v1: Option<[u8; 32]>,
    v2: Option<[u8; 32]>,
    v3: Option<[u8; 32]>,
}

/// `t=<seconds>` and one or more of `v1=<64 hex>`, `v2=<64 hex>`,
/// `v3=<64 hex>`, in any order, other pairs ignored.
fn parse_header(headers: &HeaderMap) -> Option<(i64, Tags)> {
    let value = headers.get(SIGNATURE_HEADER)?.to_str().ok()?;
    let mut stamp = None;
    let mut tags = Tags {
        v1: None,
        v2: None,
        v3: None,
    };
    for pair in value.split(',') {
        match pair.trim().split_once('=')? {
            ("t", digits) => stamp = Some(digits.parse::<i64>().ok()?),
            ("v1", hex) => tags.v1 = Some(decode_hex(hex)?),
            ("v2", hex) => tags.v2 = Some(decode_hex(hex)?),
            ("v3", hex) => tags.v3 = Some(decode_hex(hex)?),
            _ => {}
        }
    }
    Some((stamp?, tags))
}

fn decode_hex(hex: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    axess_rng::hex::decode_to_slice(hex, &mut out).ok()?;
    Some(out)
}
