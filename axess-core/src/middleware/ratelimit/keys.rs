//! Bucket-key derivation for the rate limiter.
//!
//! A key is whatever the configured [`KeyExtractor`] reads from the request,
//! bounded so that neither its length nor the number of keys one identity can
//! create is under the caller's control: an over-long key is cut and suffixed
//! with a digest of the whole, a header value only selects one of
//! [`HEADER_SLOTS`] sub-buckets of its user, and an IPv6 client is keyed by
//! its /64 prefix.

use super::{KeyExtractor, RateLimitLoginIdentifier, RateLimitTenantId, RateLimitUserId};
use axum::{body::Body, http::Request};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Header sub-buckets one authenticated user can hold. A header value picks
/// its slot by digest, so a user sending any number of distinct values holds
/// at most this many buckets and cannot fill the shared table.
pub(super) const HEADER_SLOTS: u64 = 16;

/// Sentinel bucket key for unauthenticated requests when the extractor is
/// scoped to an authenticated identity (`UserId` / `TenantId`). All such
/// requests share a single bucket so the per-identity rate limit cannot be
/// trivially evaded by sending unauthenticated traffic; they are
/// rate-limited collectively under this key.
pub(super) const ANONYMOUS_BUCKET: &str = "__anonymous__";

/// Bucket for requests whose origin could not be established: no peer
/// address, or no `ClientIp` because the layer is not installed. Everything
/// unattributable shares it, which limits harder rather than less.
///
/// The failure mode is worth stating plainly, because it is total. On a
/// route where nothing resolves an address, every caller shares this one
/// bucket, so a single client can exhaust the limit for everybody. That is
/// the correct trade against the alternative, which is keying on something
/// the caller chooses and so enforcing nothing at all, but it is a denial
/// of service reachable from a misconfiguration rather than from a bug.
/// Install the layer, and alert on a non-zero count of audit rows carrying
/// `ip_source = 'unknown'`, which is the same misconfiguration seen from
/// the other side.
pub(super) const UNKNOWN_BUCKET: &str = "unknown";

/// Longest bucket key (bytes). A key over this is cut and suffixed with a
/// digest of the whole key (see [`bound_key`]), so a megabyte-sized
/// identifier cannot inflate per-bucket allocation and two long identifiers
/// that share a prefix still get different buckets. Real values (addresses,
/// UUIDs, identifiers) are far smaller than this.
pub(super) const MAX_KEY_LEN: usize = 256;

/// Bytes of the original key kept in front of the digest suffix.
const KEPT_PREFIX_LEN: usize = MAX_KEY_LEN - 65;

/// Bound `key` to [`MAX_KEY_LEN`] bytes.
///
/// A key within the limit is returned unchanged. A longer one is cut at a
/// UTF-8 boundary to `KEPT_PREFIX_LEN` bytes and suffixed with `:` and the
/// lowercase hex SHA-256 of the full key, so keys that differ only after the
/// cut stay different.
pub(super) fn bound_key(key: String) -> String {
    if key.len() <= MAX_KEY_LEN {
        return key;
    }
    let mut cut = KEPT_PREFIX_LEN;
    while !key.is_char_boundary(cut) {
        cut -= 1;
    }
    let digest = Sha256::digest(key.as_bytes());
    let mut out = String::with_capacity(MAX_KEY_LEN);
    out.push_str(&key[..cut]);
    out.push(':');
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The sub-bucket slot a header value selects: the first eight bytes of its
/// SHA-256, modulo [`HEADER_SLOTS`].
fn header_slot(value: &str) -> u64 {
    let digest = Sha256::digest(value.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first) % HEADER_SLOTS
}

/// The bucket name for a client address: the address itself for IPv4, the
/// /64 prefix for IPv6.
///
/// A single IPv6 subscriber is routinely handed a whole /64, so keying on the
/// full address would give one client 2^64 buckets. An IPv4-mapped IPv6
/// address is keyed as the IPv4 address it carries.
pub(super) fn ip_bucket(addr: IpAddr) -> String {
    match addr.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 64);
            format!("{}/64", std::net::Ipv6Addr::from(masked))
        }
    }
}

pub(super) fn extract_key(req: &Request<Body>, extractor: &KeyExtractor) -> String {
    let raw = match extractor {
        KeyExtractor::ClientIp => extract_resolved_client_ip(req),
        KeyExtractor::PeerIp => extract_peer_ip(req),
        KeyExtractor::UserId => req
            .extensions()
            .get::<RateLimitUserId>()
            .map(|u| u.0.to_string())
            .unwrap_or_else(|| ANONYMOUS_BUCKET.to_owned()),
        KeyExtractor::TenantId => req
            .extensions()
            .get::<RateLimitTenantId>()
            .map(|t| t.0.to_string())
            .unwrap_or_else(|| ANONYMOUS_BUCKET.to_owned()),
        KeyExtractor::LoginIdentifier => req
            .extensions()
            .get::<RateLimitLoginIdentifier>()
            .map(|i| i.as_str().to_owned())
            .unwrap_or_else(|| ANONYMOUS_BUCKET.to_owned()),
        // A header value is the caller's own claim, so it only subdivides a
        // bucket the caller cannot choose: an authenticated identity. Without
        // one, every value would be a fresh bucket for the asking. The
        // identity and the `h:` prefix keep one user's header values out of
        // another user's buckets and out of the address buckets.
        KeyExtractor::Header(name) => {
            match (
                req.extensions().get::<RateLimitUserId>(),
                header_str(req, name),
            ) {
                (Some(user), Some(v)) => format!("h:{}:{}", user.0, header_slot(&v)),
                _ => format!("ip:{}", extract_peer_ip(req)),
            }
        }
    };
    bound_key(raw)
}

/// Read the address `client_ip::layer` resolved for this request.
///
/// No header is consulted here. A missing `ClientIp` means the layer is
/// not installed, and the answer is the shared bucket rather than a guess:
/// a guess would be the caller's own claim, which is what this replaced.
fn extract_resolved_client_ip(req: &Request<Body>) -> String {
    match req.extensions().get::<crate::client_ip::ClientIp>() {
        Some(ip) => match ip.get() {
            Some(addr) => ip_bucket(addr),
            None => UNKNOWN_BUCKET.to_owned(),
        },
        None => {
            use std::sync::Once;
            static WARN: Once = Once::new();
            WARN.call_once(|| {
                tracing::warn!(
                    "ClientIp rate limiting: no ClientIp in request extensions; \
                     all requests share one bucket. Wrap the router in \
                     axess_core::client_ip::layer."
                );
            });
            UNKNOWN_BUCKET.to_owned()
        }
    }
}

/// Extract client IP from the TCP peer address stored in request extensions.
///
/// Looks for axum's `ConnectInfo<SocketAddr>` (populated when the server
/// is mounted via `Router::into_make_service_with_connect_info::<SocketAddr>()`),
/// then falls back to a bare `SocketAddr` (which some integrations insert
/// directly, e.g. test harnesses that wire the extension by hand).
///
/// Falls back to a shared bucket (`"unknown"`) if no peer address is
/// available. This is fail-closed: all unknown-origin requests share one
/// bucket, meaning stricter (not weaker) rate limiting.
pub(super) fn extract_peer_ip(req: &Request<Body>) -> String {
    let ext = req.extensions();
    let addr = ext
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0)
        .or_else(|| ext.get::<std::net::SocketAddr>().copied());
    addr.map(|addr| ip_bucket(addr.ip())).unwrap_or_else(|| {
        use std::sync::Once;
        static WARN: Once = Once::new();
        WARN.call_once(|| {
            tracing::warn!(
                "PeerIp rate limiting: no SocketAddr in request extensions; \
                     all requests will share a single bucket. Use \
                     Router::into_make_service_with_connect_info::<SocketAddr>() \
                     or, behind a proxy, client_ip::layer with \
                     KeyExtractor::ClientIp."
            );
        });
        UNKNOWN_BUCKET.to_owned()
    })
}

fn header_str(req: &Request<Body>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
}

/// A short, stable stand-in for `key` that is safe to log: the first eight
/// bytes of its SHA-256, in hex. The key itself can be a login identifier or
/// a user id, which a debug log should not carry; the fingerprint still lets
/// two log lines for one bucket be matched.
pub(super) fn fingerprint(key: &str) -> String {
    Sha256::digest(key.as_bytes())
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
